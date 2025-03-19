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

// Package fixrunner provides the main function for running a guided remediation with the SCALIBR binary.
package fixrunner

import (
	"time"

	"github.com/google/osv-scalibr/binary/fixrunner/cli"
	"github.com/google/osv-scalibr/clients/resolution"
	"github.com/google/osv-scalibr/guidedremediation"
	"github.com/google/osv-scalibr/guidedremediation/matcher/osvmatcher"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
	"github.com/google/osv-scalibr/internal/osvdev"
	"github.com/google/osv-scalibr/log"
)

// RunFix executes the remediation with the given CLI flags
// and returns the exit code passed to os.Exit() in the main binary.
func RunFix(flags *cli.Flags) int {
	// TODO(#454): This needs to make a wrapping registry client that lazy initializes
	// native clients depending on ecosystem.
	resolveClient, err := resolution.NewMavenRegistryClient(flags.MavenRegistry)
	if err != nil {
		log.Errorf("failed instantiating dependency resolution client: %v", err)
		return 1
	}

	matcherClient := &osvmatcher.OSVMatcher{
		Client:              *osvdev.DefaultClient(),
		InitialQueryTimeout: 5 * time.Minute,
	}

	fixOpts := options.FixVulnsOptions{
		Manifest:          flags.Manifest,
		Lockfile:          flags.Lockfile,
		Strategy:          strategy.Strategy(flags.Strategy),
		MaxUpgrades:       flags.MaxUpgrades,
		NoIntroduce:       flags.NoIntroduce,
		ResolveClient:     resolveClient,
		MatcherClient:     matcherClient,
		DefaultRepository: flags.MavenRegistry,
		RemediationOptions: options.RemediationOptions{
			IgnoreVulns:   flags.IgnoreVulns,
			ExplicitVulns: flags.OnlyVulns,
			DevDeps:       !flags.IgnoreDevDeps,
			MinSeverity:   flags.MinSeverity,
			MaxDepth:      flags.MaxDepth,
			UpgradeConfig: upgrade.NewConfigFromStrings(flags.UpgradeConfig),
			ResolutionOptions: options.ResolutionOptions{
				MavenManagement: flags.MavenIncludeManagementOnly,
			},
		},
	}

	result, err := guidedremediation.FixVulns(fixOpts)
	if err != nil {
		log.Errorf("failed running guided remediation: %v", err)
		return 1
	}
	// TODO: what to do with result?
	_ = result
	return 0
}
