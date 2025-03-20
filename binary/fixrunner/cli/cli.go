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

// Package cli defines the structures to store the CLI flags used by the fix subcommand.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/binary/cli"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
)

// Flags contains a field for all the cli flags that can be set.
type Flags struct {
	Manifest                   string
	Lockfile                   string
	Strategy                   string
	MaxUpgrades                int
	NoIntroduce                bool
	IgnoreVulns                []string
	OnlyVulns                  []string
	IgnoreDevDeps              bool
	MinSeverity                float64
	MaxDepth                   int
	UpgradeConfig              []string
	MavenIncludeManagementOnly bool
	MavenRegistry              string
}

// ParseFlags parses the command line flags from args.
func ParseFlags(args []string) (*Flags, error) {
	fs := flag.NewFlagSet("scalibr fix", flag.ExitOnError)
	manifest := fs.String("manifest", "", "Path to manifest file on disk")
	lockfile := fs.String("lockfile", "", "Path to lockfile on disk")
	strategy := fs.String("strategy", "", "Remediation strategy to use")
	maxUpgrades := fs.Int("max-upgrades", 0, "Maximum number of patches to apply")
	noIntroduce := fs.Bool("no-introduce", false, "If set, do not introduce new vulnerabilities")
	var ignoreVulns cli.StringListFlag
	fs.Var(&ignoreVulns, "ignore-vulns", "Comma-separated list of vulnerability IDs to ignore")
	var onlyVulns cli.StringListFlag
	fs.Var(&onlyVulns, "vulns", "Comma-separated list of vulnerabilities to only consider")
	ignoreDevDeps := fs.Bool("ignore-dev", false, "If set, ignore vulnerabilities in dev/test dependencies")
	minSeverity := fs.Float64("min-severity", 0.0, "Minimum vulnerability CVSS score to consider")
	maxDepth := fs.Int("max-depth", -1, "Maximum depth of dependencies to consider")
	var upgradeConfig cli.StringListFlag
	fs.Var(&upgradeConfig, "upgrade-config", "The level each package is allowed to be upgraded, in the format [package-name:]level. If package-name is omitted, level is applied to all packages. level must be one of (major, minor, patch, none)")
	mavenManagement := fs.Bool("maven-fix-management", false, "(pom.xml) If set, also remediate vulnerabilities in unused dependencyManagement dependencies.")
	mavenRegistry := fs.String("maven-registry", "", "URL of the default Maven registry to fetch metadata")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	flags := &Flags{
		Manifest:                   *manifest,
		Lockfile:                   *lockfile,
		Strategy:                   *strategy,
		MaxUpgrades:                *maxUpgrades,
		NoIntroduce:                *noIntroduce,
		IgnoreVulns:                ignoreVulns.GetSlice(),
		OnlyVulns:                  onlyVulns.GetSlice(),
		IgnoreDevDeps:              *ignoreDevDeps,
		MinSeverity:                *minSeverity,
		MaxDepth:                   *maxDepth,
		UpgradeConfig:              upgradeConfig.GetSlice(),
		MavenIncludeManagementOnly: *mavenManagement,
		MavenRegistry:              *mavenRegistry,
	}

	if err := ValidateFlags(flags); err != nil {
		return nil, err
	}
	return flags, nil
}

var supportedStrategies = []string{
	string(strategy.StrategyOverride),
}

// ValidateFlags validates the passed command line flags.
func ValidateFlags(flags *Flags) error {
	if flags.Manifest == "" && flags.Lockfile == "" {
		return errors.New("requires at least one of --manifest or --lockfile")
	}
	if flags.Strategy != "" && !slices.Contains(supportedStrategies, flags.Strategy) {
		return fmt.Errorf("strategy %q not recognized, supported strategies are %v", flags.Strategy, supportedStrategies)
	}
	if err := validateUpgradeConfig(flags.UpgradeConfig); err != nil {
		return err
	}
	return nil
}

var supportedUpgradeLevels = []string{
	"major", "minor", "patch", "none",
}

func validateUpgradeConfig(configs []string) error {
	seenPkgs := make(map[string]string)
	for _, c := range configs {
		var pkg string
		level := c
		if idx := strings.LastIndex(c, ":"); idx != -1 {
			pkg = c[:idx]
			level = c[idx+1:]
		}

		if !slices.Contains(supportedUpgradeLevels, level) {
			if pkg == "" {
				return fmt.Errorf("upgrade level %q not recognized, supported levels are %v", level, supportedUpgradeLevels)
			}
			return fmt.Errorf("upgrade level %q in %q not recognized, supported levels are %v", level, c, supportedUpgradeLevels)
		}

		if prev, seen := seenPkgs[pkg]; seen {
			if pkg == "" {
				return fmt.Errorf("general upgrade level set more than once as %q and %q", prev, c)
			}
			return fmt.Errorf("upgrade level for package %q set more than once as %q and %q", pkg, prev, c)
		}
		seenPkgs[pkg] = c
	}
	return nil
}
