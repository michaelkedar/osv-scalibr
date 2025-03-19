// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package osvmatcher an implementation of a VulnerabilityMatcher using the osv.dev API.
package osvmatcher

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/guidedremediation/internal/vulns"
	"github.com/google/osv-scalibr/internal/osvdev"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/sync/errgroup"
)

// This is basically copied from osv-scanner:
// https://github.com/google/osv-scanner/blob/main/internal/clients/clientimpl/osvmatcher/cachedosvmatcher.go
// with the minimal functionality required to get this functioning in osv-scalibr.

const (
	maxConcurrentRequests = 1000
)

// OSVMatcher implements the VulnerabilityMatcher interface with a osv.dev client.
// It sends out requests for every vulnerability of each package, which get cached.
// Checking if a specific version matches an OSV record is done locally.
// This should be used when we know the same packages are going to be repeatedly
// queried multiple times, as in guided remediation.
// This does not support commit-based queries.
type OSVMatcher struct {
	Client osvdev.OSVClient
	// InitialQueryTimeout allows you to set a timeout specifically for the initial paging query
	// If timeout runs out, whatever pages that has been successfully queried within the timeout will
	// still return fully hydrated.
	InitialQueryTimeout time.Duration

	vulnCache sync.Map // map[osvdev.Package][]osvschema.Vulnerability
}

func (matcher *OSVMatcher) MatchVulnerabilities(ctx context.Context, invs []*extractor.Inventory) ([][]*osvschema.Vulnerability, error) {
	// populate vulnCache with missing packages
	if err := matcher.doQueries(ctx, invs); err != nil {
		return nil, err
	}

	results := make([][]*osvschema.Vulnerability, len(invs))

	for i, inv := range invs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		pkg := osvdev.Package{
			Name:      inv.Name,
			Ecosystem: inv.Ecosystem(),
		}
		pkgVulns, ok := matcher.vulnCache.Load(pkg)
		if !ok {
			continue
		}
		// results[i] = localmatcher.VulnerabilitiesAffectingPackage(vulns.([]osvschema.Vulnerability), pkgInfo)
		for _, v := range pkgVulns.([]osvschema.Vulnerability) {
			if vulns.IsAffected(&v, inv) {
				results[i] = append(results[i], &v)
			}
		}
	}

	return results, nil
}

func (matcher *OSVMatcher) doQueries(ctx context.Context, invs []*extractor.Inventory) error {
	var batchResp *osvdev.BatchedResponse
	deadlineExceeded := false

	var queries []*osvdev.Query
	{
		// determine which packages aren't already cached
		// convert Inventory to Query for each pkgs element
		toQuery := make(map[*osvdev.Query]struct{})
		for _, inv := range invs {
			if inv.Name == "" || inv.Ecosystem() == "" {
				continue
			}
			pkg := osvdev.Package{
				Name:      inv.Name,
				Ecosystem: inv.Ecosystem(),
			}
			if _, ok := matcher.vulnCache.Load(pkg); !ok {
				toQuery[&osvdev.Query{Package: pkg}] = struct{}{}
			}
		}
		queries = slices.AppendSeq(make([]*osvdev.Query, 0, len(toQuery)), maps.Keys(toQuery))
	}

	if len(queries) == 0 {
		return nil
	}

	var err error

	// If there is a timeout for the initial query, set an additional context deadline here.
	if matcher.InitialQueryTimeout > 0 {
		batchQueryCtx, cancelFunc := context.WithDeadline(ctx, time.Now().Add(matcher.InitialQueryTimeout))
		batchResp, err = queryForBatchWithPaging(batchQueryCtx, &matcher.Client, queries)
		cancelFunc()
	} else {
		batchResp, err = queryForBatchWithPaging(ctx, &matcher.Client, queries)
	}

	if err != nil {
		// Deadline being exceeded is likely caused by a long paging time
		// if that's the case, we can should return what we already got, and
		// then let the caller know it is not all the results.
		if errors.Is(err, context.DeadlineExceeded) {
			deadlineExceeded = true
		} else {
			return err
		}
	}

	vulnerabilities := make([][]osvschema.Vulnerability, len(batchResp.Results))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentRequests)

	for batchIdx, resp := range batchResp.Results {
		vulnerabilities[batchIdx] = make([]osvschema.Vulnerability, len(resp.Vulns))
		for resultIdx, vuln := range resp.Vulns {
			g.Go(func() error {
				// exit early if another hydration request has already failed
				// results are thrown away later, so avoid needless work
				if ctx.Err() != nil {
					return nil //nolint:nilerr // this value doesn't matter to errgroup.Wait()
				}
				vuln, err := matcher.Client.GetVulnByID(ctx, vuln.ID)
				if err != nil {
					return err
				}
				vulnerabilities[batchIdx][resultIdx] = *vuln

				return nil
			})
		}
	}

	if err := g.Wait(); err != nil {
		return err
	}

	if deadlineExceeded {
		return context.DeadlineExceeded
	}

	for i, vulns := range vulnerabilities {
		matcher.vulnCache.Store(queries[i].Package, vulns)
	}

	return nil
}

func queryForBatchWithPaging(ctx context.Context, c *osvdev.OSVClient, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	batchResp, err := c.QueryBatch(ctx, queries)

	if err != nil {
		return nil, err
	}
	// --- Paging logic ---
	var errToReturn error
	nextPageQueries := []*osvdev.Query{}
	nextPageIndexMap := []int{}
	for i, res := range batchResp.Results {
		if res.NextPageToken == "" {
			continue
		}

		query := *queries[i]
		query.PageToken = res.NextPageToken
		nextPageQueries = append(nextPageQueries, &query)
		nextPageIndexMap = append(nextPageIndexMap, i)
	}

	if len(nextPageQueries) > 0 {
		// If context is cancelled or deadline exceeded, return now
		if ctx.Err() != nil {
			return batchResp, &DuringPagingError{
				PageDepth: 1,
				Inner:     ctx.Err(),
			}
		}

		nextPageResp, err := c.QueryBatch(ctx, nextPageQueries)
		if err != nil {
			var dpr *DuringPagingError
			if ok := errors.As(err, &dpr); ok {
				dpr.PageDepth += 1
				errToReturn = dpr
			} else {
				errToReturn = &DuringPagingError{
					PageDepth: 1,
					Inner:     err,
				}
			}
		}

		// Whether there is an error or not, if there is any data,
		// we want to save and return what we got.
		if nextPageResp != nil {
			for i, res := range nextPageResp.Results {
				batchResp.Results[nextPageIndexMap[i]].Vulns = append(batchResp.Results[nextPageIndexMap[i]].Vulns, res.Vulns...)
				// Set next page token so caller knows whether this is all of the results
				// even if it is being cancelled.
				batchResp.Results[nextPageIndexMap[i]].NextPageToken = res.NextPageToken
			}
		}
	}

	return batchResp, errToReturn
}
