package rhel

import (
	"context"
	"strings"

	version "github.com/knqyf263/go-rpm-version"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// Matcher implements driver.Matcher.
type Matcher struct {
}

var _ driver.Matcher = (*Matcher)(nil)

// Name implements driver.Matcher.
func (*Matcher) Name() string {
	return "rhel"
}

// Filter implements driver.Matcher.
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Repository != nil && record.Repository.Key == RedHatRepositoryKey
}

// Query implements driver.Matcher.
func (*Matcher) Query() []driver.MatchConstraint {
	return []driver.MatchConstraint{
		driver.PackageModule,
		driver.RepositoryName,
	}
}

// Vulnerable implements driver.Matcher.
func (m *Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	pkgVer, vulnVer := version.NewVersion(record.Package.Version), version.NewVersion(vuln.Package.Version)
	// Assume the vulnerability record we have is for the last known vulnerable
	// version, so greater versions aren't vulnerable.
	cmp := func(i int) bool { return i != version.GREATER }
	// But if it's explicitly marked as a fixed-in version, it's only vulnerable
	// if less than that version.
	if vuln.FixedInVersion != "" {
		vulnVer = version.NewVersion(vuln.FixedInVersion)
		cmp = func(i int) bool { return i == version.LESS }
		// There are two situations where vulnerability might miss FixedInVersion
	} else {
		// OVAL data includes so-called unaffected vulnerabilities.
		// They are there to confirm that given package is not affected by a known CVE.
		if strings.Split(vuln.Name, " ")[0] == "Unaffected" {
			// TODO: This is probably incorrect. I also need to compare arch.
			return false, nil
		}
		// Otherwise we assume that the vulnerability hasn't been fixed.
		vulnVer = version.NewVersion("65535:0")
	}
	// compare version and architecture
	return cmp(pkgVer.Compare(vulnVer)) && vuln.ArchOperation.Cmp(record.Package.Arch, vuln.Package.Arch), nil
}
