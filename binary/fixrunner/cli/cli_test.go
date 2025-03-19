package cli_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/binary/fixrunner/cli"
)

func TestValidateFlags(t *testing.T) {
	for _, tc := range []struct {
		desc    string
		flags   *cli.Flags
		wantErr error
	}{
		{
			desc: "Valid config",
			flags: &cli.Flags{
				Manifest:                   "pom.xml",
				Strategy:                   "override",
				MaxUpgrades:                5,
				NoIntroduce:                true,
				IgnoreVulns:                []string{"CVE-1234", "CVE-5678"},
				OnlyVulns:                  []string{"CVE-9876", "CVE-5432"},
				IgnoreDevDeps:              true,
				MinSeverity:                3.5,
				MaxDepth:                   3,
				UpgradeConfig:              []string{"minor", "com.foo:bar:major", "org.bar:baz:none", "net.baz:foo:patch"},
				MavenIncludeManagementOnly: true,
				MavenRegistry:              "https://example.com",
			},
			wantErr: nil,
		},
		{
			desc:    "Either manifest/lockfile flag missing",
			flags:   &cli.Flags{},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Invalid strategy",
			flags: &cli.Flags{
				Manifest: "pom.xml",
				Strategy: "notarealstrategy",
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Invalid plain upgrade config",
			flags: &cli.Flags{
				Manifest:      "pom.xml",
				UpgradeConfig: []string{"something"},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Invalid package upgrade config",
			flags: &cli.Flags{
				Manifest:      "pom.xml",
				UpgradeConfig: []string{"com.foo:bar:something"},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "Empty package upgrade config",
			flags: &cli.Flags{
				Manifest:      "pom.xml",
				UpgradeConfig: []string{"pkg:"},
			},
			wantErr: cmpopts.AnyError,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := cli.ValidateFlags(tc.flags)
			if diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("cli.ValidateFlags(%v) error got diff (-want +got):\n%s", tc.flags, diff)
			}
		})
	}
}
