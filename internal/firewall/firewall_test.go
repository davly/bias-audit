package firewall

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/davly/bias-audit/internal/stele"
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
// PLUS the R145.B stele-anchor package (2026-06-11): stele.
//
// Total = 8 internal packages. R174 5-of-5 verified by checking all
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

// ---- R145.B stele-anchor paired confinement pins (2026-06-11) ----------

// scanProductionGoFiles walks cmd/ + internal/ and returns every
// non-test .go source file, excluding the firewall package itself
// (this file's patterns would otherwise self-trip).
func scanProductionGoFiles(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	sep := string(filepath.Separator)
	var out []string
	for _, r := range []string{filepath.Join(root, "cmd"), filepath.Join(root, "internal")} {
		_ = filepath.Walk(r, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil // continue walk
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if strings.Contains(path, sep+"firewall"+sep) {
				return nil
			}
			out = append(out, path)
			return nil
		})
	}
	return out
}

// fileContains reports whether the given file contains any of the
// given substring patterns, returning the first hit.
func fileContains(t *testing.T, path string, patterns ...string) (bool, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	src := string(data)
	for _, p := range patterns {
		if strings.Contains(src, p) {
			return true, p
		}
	}
	return false, ""
}

// inSteleDir reports whether path lives under internal/stele/ — the
// ONE package permitted to hold an HTTP client after the R145.B
// stele-anchor amendment (2026-06-11).
func inSteleDir(path string) bool {
	sep := string(filepath.Separator)
	return strings.Contains(path, sep+"stele"+sep)
}

// TestR145B_SteleAnchorConfinement is the paired regression pin for
// the two inception invariants NARROWED on the stele-anchor sibling
// branch (SECURITY.md trust boundary 5 shipped "no net/http, no
// os.Getenv" as grep-verified claims at M6; this pin makes the
// narrowed shape executable). It pins the NEW invariant shape so any
// further drift breaks a test:
//
//  1. every production net/http usage lives under internal/stele/
//     (client-only — listener primitives stay banned EVERYWHERE,
//     including internal/stele/);
//  2. the stele client carries the 5-second timeout;
//  3. os.Getenv appears in exactly one production file
//     (cmd/bias-audit/main.go) and only as os.Getenv(stele.EnvURL);
//     os.LookupEnv / os.Environ stay banned everywhere;
//  4. the spine wire-contract constants hold (env var name,
//     substrate, honest oracle-strength label).
func TestR145B_SteleAnchorConfinement(t *testing.T) {
	var netHTTPFiles, getenvFiles []string
	for _, path := range scanProductionGoFiles(t) {
		if hit, _ := fileContains(t, path, `"net/http"`); hit {
			netHTTPFiles = append(netHTTPFiles, path)
		}
		if hit, _ := fileContains(t, path, `os.Getenv(`); hit {
			getenvFiles = append(getenvFiles, path)
		}
		if hit, p := fileContains(t, path,
			`http.ListenAndServe`,
			`net.Listen(`,
			`httptest.NewServer`, // test-double servers belong in _test.go only
		); hit {
			t.Errorf("R145.B pin violation: %s contains %q — HTTP listener primitives are banned everywhere, including internal/stele/", path, p)
		}
		if hit, p := fileContains(t, path, `os.LookupEnv(`, `os.Environ(`); hit {
			t.Errorf("R145.B pin violation: %s contains %q — the sole permitted env read is os.Getenv(stele.EnvURL) in cmd/bias-audit/main.go", path, p)
		}
	}

	// (1) net/http confined to internal/stele/ — and present there
	// (the wire is load-bearing, not decorative).
	if len(netHTTPFiles) == 0 {
		t.Errorf("R145.B pin violation: no production file imports net/http — the stele spine wire is gone; re-pin the firewall if this is deliberate")
	}
	for _, path := range netHTTPFiles {
		if !inSteleDir(path) {
			t.Errorf("R145.B pin violation: %s imports net/http outside internal/stele/", path)
		}
	}

	// (2) the stele client keeps its 5s timeout.
	steleSrc := filepath.Join(repoRoot(t), "internal", "stele", "stele.go")
	if hit, _ := fileContains(t, steleSrc, `Timeout: 5 * time.Second`); !hit {
		t.Errorf("R145.B pin violation: %s missing the 5-second http.Client timeout", steleSrc)
	}

	// (3) exactly one env-read site: os.Getenv(stele.EnvURL) in
	// cmd/bias-audit/main.go.
	wantGetenv := filepath.Join(repoRoot(t), "cmd", "bias-audit", "main.go")
	if len(getenvFiles) != 1 || getenvFiles[0] != wantGetenv {
		t.Errorf("R145.B pin violation: os.Getenv sites = %v, want exactly [%s]", getenvFiles, wantGetenv)
	}
	data, err := os.ReadFile(wantGetenv)
	if err != nil {
		t.Fatalf("read %q: %v", wantGetenv, err)
	}
	src := string(data)
	if strings.Count(src, "os.Getenv(") != 1 || !strings.Contains(src, "os.Getenv(stele.EnvURL)") {
		t.Errorf("R145.B pin violation: %s must contain exactly one os.Getenv call and it must be os.Getenv(stele.EnvURL)", wantGetenv)
	}

	// (4) spine wire-contract constants.
	if stele.EnvURL != "BIASAUDIT_STELE_URL" {
		t.Errorf("R145.B pin violation: stele.EnvURL = %q, want BIASAUDIT_STELE_URL", stele.EnvURL)
	}
	if stele.Substrate != "flagships/bias-audit/audit-ledger" {
		t.Errorf("R145.B pin violation: stele.Substrate = %q, want flagships/bias-audit/audit-ledger", stele.Substrate)
	}
	if stele.OracleStrengthSelfCheck != "Self-Check" {
		t.Errorf("R145.B pin violation: stele.OracleStrengthSelfCheck = %q, want Self-Check (honesty label is load-bearing)", stele.OracleStrengthSelfCheck)
	}
}
