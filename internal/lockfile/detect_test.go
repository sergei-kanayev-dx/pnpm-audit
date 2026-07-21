package lockfile_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/user/pnpm-vuln-fixer/internal/lockfile"
)

func writeTempLockfile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pnpm-lock.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp lockfile: %v", err)
	}
	return path
}

func TestDetectVersion(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantVersion string
		wantErr     string
	}{
		{
			name:        "v9.0 supported",
			content:     "lockfileVersion: '9.0'\n",
			wantVersion: "9.0",
		},
		{
			name:    "v6.x unsupported",
			content: "lockfileVersion: '6.0'\n",
			wantErr: "not supported",
		},
		{
			name:    "v5.4 unsupported",
			content: "lockfileVersion: 5.4\n",
			wantErr: "not supported",
		},
		{
			name:    "unknown version unsupported",
			content: "lockfileVersion: '42.0'\n",
			wantErr: "not supported",
		},
		{
			name:    "missing lockfileVersion field",
			content: "importers: {}\n",
			wantErr: "missing lockfileVersion",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempLockfile(t, tc.content)
			got, err := lockfile.DetectVersion(path)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantVersion {
				t.Fatalf("version = %q, want %q", got, tc.wantVersion)
			}
		})
	}
}

func TestDetectVersionMissingFile(t *testing.T) {
	_, err := lockfile.DetectVersion("/nonexistent/path/pnpm-lock.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestDetectVersionRealFixture(t *testing.T) {
	// Verify DetectVersion works against the actual v9-simple.yaml fixture.
	ver, err := lockfile.DetectVersion("../../testdata/lockfiles/v9-simple.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ver != "9.0" {
		t.Fatalf("version = %q, want %q", ver, "9.0")
	}
}

