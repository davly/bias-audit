package firewall

import (
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

// repoRoot computes the bias-audit repo root from the test file's
// location. internal/firewall/firewall_test.go → two levels up.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// TestExpectedPackages_NonEmpty — sanity.
func TestExpectedPackages_NonEmpty(t *testing.T) {
	if len(ExpectedPackages()) == 0 {
		t.Fatal("ExpectedPackages returned empty list")
	}
}

// TestExpectedBinaries_NonEmpty — sanity.
func TestExpectedBinaries_NonEmpty(t *testing.T) {
	if len(ExpectedBinaries()) == 0 {
		t.Fatal("ExpectedBinaries returned empty list")
	}
}

// TestExpectedPackages_Sorted — alphabetical order.
func TestExpectedPackages_Sorted(t *testing.T) {
	pkgs := ExpectedPackages()
	if !sort.StringsAreSorted(pkgs) {
		t.Fatalf("ExpectedPackages not sorted: %v", pkgs)
	}
}

// TestExpectedPackages_Unique — unique entries.
func TestExpectedPackages_Unique(t *testing.T) {
	seen := map[string]int{}
	for i, p := range ExpectedPackages() {
		if prev, ok := seen[p]; ok {
			t.Errorf("duplicate package %q at indices %d and %d", p, prev, i)
		}
		seen[p] = i
	}
}

// TestExpectedBinaries_Unique — unique entries.
func TestExpectedBinaries_Unique(t *testing.T) {
	seen := map[string]int{}
	for i, b := range ExpectedBinaries() {
		if prev, ok := seen[b]; ok {
			t.Errorf("duplicate binary %q at indices %d and %d", b, prev, i)
		}
		seen[b] = i
	}
}

// TestFirewall_EveryExpectedPackageExistsOnDisk — drift direction 1.
func TestFirewall_EveryExpectedPackageExistsOnDisk(t *testing.T) {
	root := repoRoot(t)
	onDisk, err := ScanInternal(root)
	if err != nil {
		t.Fatalf("ScanInternal: %v", err)
	}
	onDiskSet := map[string]bool{}
	for _, p := range onDisk {
		onDiskSet[p] = true
	}
	for _, expected := range ExpectedPackages() {
		if !onDiskSet[expected] {
			t.Errorf("R145.C drift: expected package %q not found on disk under internal/", expected)
		}
	}
}

// TestFirewall_EveryOnDiskPackageInExpectedList — drift direction 2.
func TestFirewall_EveryOnDiskPackageInExpectedList(t *testing.T) {
	root := repoRoot(t)
	onDisk, err := ScanInternal(root)
	if err != nil {
		t.Fatalf("ScanInternal: %v", err)
	}
	expectedSet := map[string]bool{}
	for _, p := range ExpectedPackages() {
		expectedSet[p] = true
	}
	for _, found := range onDisk {
		if !expectedSet[found] {
			t.Errorf("R145.C drift: package %q on disk but not in ExpectedPackages list", found)
		}
	}
}

// TestFirewall_EveryExpectedBinaryExistsOnDisk — binary drift direction 1.
func TestFirewall_EveryExpectedBinaryExistsOnDisk(t *testing.T) {
	root := repoRoot(t)
	onDisk, err := ScanCmd(root)
	if err != nil {
		t.Fatalf("ScanCmd: %v", err)
	}
	onDiskSet := map[string]bool{}
	for _, b := range onDisk {
		onDiskSet[b] = true
	}
	for _, expected := range ExpectedBinaries() {
		if !onDiskSet[expected] {
			t.Errorf("R145.C drift: expected binary %q not found on disk under cmd/", expected)
		}
	}
}

// TestFirewall_EveryOnDiskBinaryInExpectedList — binary drift direction 2.
func TestFirewall_EveryOnDiskBinaryInExpectedList(t *testing.T) {
	root := repoRoot(t)
	onDisk, err := ScanCmd(root)
	if err != nil {
		t.Fatalf("ScanCmd: %v", err)
	}
	expectedSet := map[string]bool{}
	for _, b := range ExpectedBinaries() {
		expectedSet[b] = true
	}
	for _, found := range onDisk {
		if !expectedSet[found] {
			t.Errorf("R145.C drift: binary %q on disk but not in ExpectedBinaries list", found)
		}
	}
}

// TestFirewall_AllFiveR174CohortPackagesPresent — R174 5-of-5 maturity.
//
// bias-audit ships the 5-of-5 cohort discipline FROM INCEPTION per
// R174 (memoria + conjure precedent). The 5 cohort packages are:
// lore + mirrormark + manifest + honest + firewall.
//
// PLUS bias-audit's domain-specific packages: legal + auditledger.
//
// Total = 7 internal packages. R174 5-of-5 verified by checking all
// five cohort packages exist.
func TestFirewall_AllFiveR174CohortPackagesPresent(t *testing.T) {
	cohortPackages := []string{"firewall", "honest", "lore", "manifest", "mirrormark"}
	pkgs := ExpectedPackages()
	pkgSet := map[string]bool{}
	for _, p := range pkgs {
		pkgSet[p] = true
	}
	for _, cohortPkg := range cohortPackages {
		if !pkgSet[cohortPkg] {
			t.Errorf("R174 5-of-5 violation: cohort package %q missing from ExpectedPackages — bias-audit claims 5-of-5 from inception but doesn't ship the package", cohortPkg)
		}
	}
}

// TestFirewall_DomainPackagesPresent — bias-audit domain-specific extras.
func TestFirewall_DomainPackagesPresent(t *testing.T) {
	domainPackages := []string{"legal", "auditledger"}
	pkgs := ExpectedPackages()
	pkgSet := map[string]bool{}
	for _, p := range pkgs {
		pkgSet[p] = true
	}
	for _, domainPkg := range domainPackages {
		if !pkgSet[domainPkg] {
			t.Errorf("bias-audit domain package %q missing — required for NYC LL144 + R153.A R-REGULATORY-ESCAPE-INVARIANT-WITH-AUDIT-LEDGER saturation", domainPkg)
		}
	}
}
