package npmsemver_test

import (
	"testing"

	"github.com/user/pnpm-vuln-fixer/internal/npmsemver"
)

func TestSatisfies(t *testing.T) {
	tests := []struct {
		version string
		rang    string
		want    bool
	}{
		// Caret — major non-zero
		{"1.2.4", "^1.2.3", true},
		{"1.9.9", "^1.2.3", true},
		{"2.0.0", "^1.2.3", false},
		{"1.2.2", "^1.2.3", false},
		// Caret — 0.x (minor locks)
		{"0.2.3", "^0.2.3", true},
		{"0.2.9", "^0.2.3", true},
		{"0.3.0", "^0.2.3", false},
		{"0.2.2", "^0.2.3", false},
		// Caret — 0.0.x (patch locks exactly)
		{"0.0.3", "^0.0.3", true},
		{"0.0.4", "^0.0.3", false},
		// Tilde
		{"1.2.3", "~1.2.3", true},
		{"1.2.9", "~1.2.3", true},
		{"1.3.0", "~1.2.3", false},
		{"1.2.2", "~1.2.3", false},
		// Exact
		{"1.2.3", "1.2.3", true},
		{"1.2.4", "1.2.3", false},
		// Hyphen range
		{"1.2.3", "1.2.3 - 2.3.4", true},
		{"2.3.4", "1.2.3 - 2.3.4", true},
		{"1.2.2", "1.2.3 - 2.3.4", false},
		{"2.3.5", "1.2.3 - 2.3.4", false},
		// OR
		{"1.0.0", "1.0.0 || 2.0.0", true},
		{"2.0.0", "1.0.0 || 2.0.0", true},
		{"1.5.0", "1.0.0 || 2.0.0", false},
		// Wildcard
		{"9.9.9", "*", true},
		{"0.0.1", "*", true},
		// x-range
		{"1.5.3", "1.x", true},
		{"2.0.0", "1.x", false},
		// Comparators
		{"4.17.21", ">=4.17.11", true},
		{"4.17.10", ">=4.17.11", false},
		// Prerelease: range without prerelease does not match prerelease
		{"1.2.4-beta.0", "^1.2.3", false},
		{"1.2.3-rc.1", "~1.2.3", false},
		// Greater-than-or-equal to a fixed version (common vuln fix pattern)
		{"4.17.21", ">=4.17.21", true},
		{"4.17.20", ">=4.17.21", false},
	}
	for _, tt := range tests {
		t.Run(tt.version+"/"+tt.rang, func(t *testing.T) {
			got, err := npmsemver.Satisfies(tt.version, tt.rang)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Satisfies(%q, %q) = %v, want %v", tt.version, tt.rang, got, tt.want)
			}
		})
	}
}

func TestSatisfies_Errors(t *testing.T) {
	_, err := npmsemver.Satisfies("not-a-version", "^1.0.0")
	if err == nil {
		t.Error("expected error for invalid version")
	}
	_, err = npmsemver.Satisfies("1.0.0", "not-a-range!!!")
	if err == nil {
		t.Error("expected error for invalid range")
	}
}

func TestMinVersionAbove(t *testing.T) {
	always := func(string) bool { return true }
	never := func(string) bool { return false }

	tests := []struct {
		name      string
		sorted    []string
		current   string
		predicate func(string) bool
		wantVer   string
		wantFound bool
	}{
		{
			name:      "first above current",
			sorted:    []string{"1.0.0", "1.0.1", "1.1.0", "2.0.0"},
			current:   "1.0.0",
			predicate: always,
			wantVer:   "1.0.1",
			wantFound: true,
		},
		{
			name:      "no version above current",
			sorted:    []string{"0.9.0", "1.0.0"},
			current:   "1.0.0",
			predicate: always,
			wantVer:   "",
			wantFound: false,
		},
		{
			name:      "predicate filters intermediate",
			sorted:    []string{"1.0.1", "1.0.2", "1.1.0"},
			current:   "1.0.0",
			predicate: func(v string) bool { return v == "1.1.0" },
			wantVer:   "1.1.0",
			wantFound: true,
		},
		{
			name:      "predicate never true",
			sorted:    []string{"1.0.1", "1.0.2"},
			current:   "1.0.0",
			predicate: never,
			wantVer:   "",
			wantFound: false,
		},
		{
			name:      "empty list",
			sorted:    []string{},
			current:   "1.0.0",
			predicate: always,
			wantVer:   "",
			wantFound: false,
		},
		{
			name:      "skips invalid versions",
			sorted:    []string{"1.0.1", "not-semver", "1.0.2"},
			current:   "1.0.0",
			predicate: func(v string) bool { return v == "1.0.2" },
			wantVer:   "1.0.2",
			wantFound: true,
		},
		{
			name:      "invalid current returns not-found",
			sorted:    []string{"1.0.1"},
			current:   "bad",
			predicate: always,
			wantVer:   "",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := npmsemver.MinVersionAbove(tt.sorted, tt.current, tt.predicate)
			if found != tt.wantFound || got != tt.wantVer {
				t.Errorf("MinVersionAbove(%v, %q, ...) = (%q, %v), want (%q, %v)",
					tt.sorted, tt.current, got, found, tt.wantVer, tt.wantFound)
			}
		})
	}
}
