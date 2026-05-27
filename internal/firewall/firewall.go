// Package firewall implements the R145.C FIREWALL-TEST-DISCIPLINE
// pin for bias-audit — structural firewall against internal/ + cmd/
// drift.
//
// Cohort-port from inception per R174 5-of-5 strict — bias-audit
// ships dedicated `internal/firewall/` from day one rather than
// distributed per-package firewall tests.
package firewall

import (
	"os"
	"path/filepath"
	"sort"
)

// ExpectedPackages returns the canonical list of internal/ packages
// bias-audit ships as of M6 (2026-05-27 launch).
//
// 7 packages from inception per R174 5-of-5:
// auditledger / firewall / honest / legal / lore / manifest / mirrormark.
func ExpectedPackages() []string {
	return []string{
		"auditledger",
		"firewall",
		"honest",
		"legal",
		"lore",
		"manifest",
		"mirrormark",
	}
}

func ExpectedBinaries() []string {
	return []string{
		"bias-audit",
	}
}

func ScanInternal(repoRoot string) ([]string, error) {
	return scanGoSubtree(filepath.Join(repoRoot, "internal"))
}

func ScanCmd(repoRoot string) ([]string, error) {
	cmdDir := filepath.Join(repoRoot, "cmd")
	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		mainGo := filepath.Join(cmdDir, e.Name(), "main.go")
		if _, err := os.Stat(mainGo); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func scanGoSubtree(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		subPath := filepath.Join(root, name)
		hasGo, err := dirHasGoFile(subPath)
		if err != nil {
			return nil, err
		}
		if hasGo {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func dirHasGoFile(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) == ".go" {
			return true, nil
		}
	}
	return false, nil
}
