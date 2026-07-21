package main_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "pnpm-vuln-fixer-e2e-*")
	if err != nil {
		panic("temp dir: " + err.Error())
	}
	defer os.RemoveAll(tmp)

	binaryPath = filepath.Join(tmp, "pnpm-vuln-fixer")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}

	// Build from current working directory (set by go test to the package dir).
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, buildErr := cmd.CombinedOutput(); buildErr != nil {
		panic("build failed: " + string(out))
	}

	os.Exit(m.Run())
}

// abbrevMeta mirrors the registry.AbbrevMeta JSON shape used by the binary.
type abbrevMeta struct {
	Name     string                `json:"name"`
	Versions map[string]*pkgVer    `json:"versions"`
}

type pkgVer struct {
	Dependencies map[string]string `json:"dependencies"`
}

// mockRegistry starts an httptest server that serves the given package map.
// Package names are matched against the URL path (URL-decoding %2F for scoped names).
func mockRegistry(t *testing.T, pkgs map[string]*abbrevMeta) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pkg := strings.TrimPrefix(r.URL.Path, "/")
		pkg = strings.ReplaceAll(pkg, "%2F", "/")
		meta, ok := pkgs[pkg]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(meta); err != nil {
			http.Error(w, err.Error(), 500)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// e2eFixture returns the absolute path to a file inside testdata/e2e/.
// Relies on go test setting CWD to the package directory.
func e2eFixture(name string) string {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Join(cwd, "..", "..", "testdata", "e2e", name)
}

// run executes the binary with the given extra args prepended by --registry and
// --lockfile flags, and returns stdout, stderr, and exit code.
func run(t *testing.T, registryURL, lockfile string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	full := []string{"--registry", registryURL, "--lockfile", lockfile}
	full = append(full, args...)

	cmd := exec.Command(binaryPath, full...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	if err != nil {
		if ex, ok := err.(*exec.ExitError); ok {
			exitCode = ex.ExitCode()
		} else {
			t.Logf("exec error (not ExitError): %v", err)
			exitCode = -1
		}
	}
	return
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

// TestE2E_AllFixable_NoBumpNeeded: parent@1.0.0 already admits the fixed
// version of vuln via its declared range; exit 0 with "already satisfied".
func TestE2E_AllFixable_NoBumpNeeded(t *testing.T) {
	reg := mockRegistry(t, map[string]*abbrevMeta{
		"parent": {Name: "parent", Versions: map[string]*pkgVer{
			"1.0.0": {Dependencies: map[string]string{"vuln": "^3.0.0"}},
		}},
		"vuln": {Name: "vuln", Versions: map[string]*pkgVer{
			"3.0.0": {Dependencies: map[string]string{}},
			"3.5.0": {Dependencies: map[string]string{}},
		}},
	})

	stdout, stderr, code := run(t, reg, e2eFixture("v9-no-bump.yaml"), "vuln@3.0.0", "3.5.0")

	if code != 0 {
		t.Errorf("exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "already satisfied") {
		t.Errorf("expected 'already satisfied' in stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "FIX:") {
		t.Errorf("expected 'FIX:' in stdout:\n%s", stdout)
	}
}

// TestE2E_AllFixable_BumpNeeded: parent@1.0.0 range does not admit the fixed
// version but parent@2.0.0 does; tool bumps parent and exits 0.
func TestE2E_AllFixable_BumpNeeded(t *testing.T) {
	reg := mockRegistry(t, map[string]*abbrevMeta{
		"parent": {Name: "parent", Versions: map[string]*pkgVer{
			"1.0.0": {Dependencies: map[string]string{"vuln": "^2.0.0"}},
			"2.0.0": {Dependencies: map[string]string{"vuln": "^3.0.0"}},
		}},
		"vuln": {Name: "vuln", Versions: map[string]*pkgVer{
			"2.0.0": {Dependencies: map[string]string{}},
			"3.0.0": {Dependencies: map[string]string{}},
		}},
	})

	stdout, stderr, code := run(t, reg, e2eFixture("v9-bump.yaml"), "vuln@2.0.0", "3.0.0")

	if code != 0 {
		t.Errorf("exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "bump parent") {
		t.Errorf("expected 'bump parent' in stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "FIX:") {
		t.Errorf("expected 'FIX:' in stdout:\n%s", stdout)
	}
}

// TestE2E_NoFix: parent has no newer version whose range admits the fixed
// vuln; dead-end → exit 1 with BLOCKED and OVERRIDE sections.
func TestE2E_NoFix(t *testing.T) {
	reg := mockRegistry(t, map[string]*abbrevMeta{
		"parent": {Name: "parent", Versions: map[string]*pkgVer{
			// Only v1.0.0 exists; its range cannot admit 3.0.0.
			"1.0.0": {Dependencies: map[string]string{"vuln": "^2.0.0"}},
		}},
		"vuln": {Name: "vuln", Versions: map[string]*pkgVer{
			"2.0.0": {Dependencies: map[string]string{}},
			"3.0.0": {Dependencies: map[string]string{}},
		}},
	})

	stdout, _, code := run(t, reg, e2eFixture("v9-bump.yaml"), "vuln@2.0.0", "3.0.0")

	if code != 1 {
		t.Errorf("exit %d, want 1\nstdout: %s", code, stdout)
	}
	if !strings.Contains(stdout, "BLOCKED") {
		t.Errorf("expected 'BLOCKED' in stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "OVERRIDE") {
		t.Errorf("expected 'OVERRIDE' in stdout:\n%s", stdout)
	}
}

// TestE2E_PartialFix: two importers; one chain (parent-a) can be bumped,
// the other (parent-b) is a dead-end → AllFixable=false, exit 1, PARTIAL FIX.
func TestE2E_PartialFix(t *testing.T) {
	reg := mockRegistry(t, map[string]*abbrevMeta{
		"parent-a": {Name: "parent-a", Versions: map[string]*pkgVer{
			"1.0.0": {Dependencies: map[string]string{"vuln": "^2.0.0"}},
			"2.0.0": {Dependencies: map[string]string{"vuln": "^3.0.0"}},
		}},
		"parent-b": {Name: "parent-b", Versions: map[string]*pkgVer{
			// Only v1.0.0; no upgrade path.
			"1.0.0": {Dependencies: map[string]string{"vuln": "^2.0.0"}},
		}},
		"vuln": {Name: "vuln", Versions: map[string]*pkgVer{
			"2.0.0": {Dependencies: map[string]string{}},
			"3.0.0": {Dependencies: map[string]string{}},
		}},
	})

	stdout, _, code := run(t, reg, e2eFixture("v9-partial-fix.yaml"), "vuln@2.0.0", "3.0.0")

	if code != 1 {
		t.Errorf("exit %d, want 1 (partial fix)\nstdout: %s", code, stdout)
	}
	if !strings.Contains(stdout, "PARTIAL FIX") {
		t.Errorf("expected 'PARTIAL FIX' in stdout:\n%s", stdout)
	}
}

// TestE2E_ExitCode3_PkgNotInLockfile: asking for a package that has no entry
// in the lockfile at all → exit 3.
func TestE2E_ExitCode3_PkgNotInLockfile(t *testing.T) {
	reg := mockRegistry(t, map[string]*abbrevMeta{})

	_, stderr, code := run(t, reg, e2eFixture("v9-no-bump.yaml"), "nonexistent@1.0.0", "2.0.0")

	if code != 3 {
		t.Errorf("exit %d, want 3\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "not found") {
		t.Errorf("expected 'not found' in stderr:\n%s", stderr)
	}
}

// TestE2E_ExitCode3_WrongVersion: package exists in the lockfile but not at
// the requested version → exit 3.
func TestE2E_ExitCode3_WrongVersion(t *testing.T) {
	reg := mockRegistry(t, map[string]*abbrevMeta{})

	// v9-no-bump.yaml has vuln@3.0.0; request vuln@9.9.9.
	_, stderr, code := run(t, reg, e2eFixture("v9-no-bump.yaml"), "vuln@9.9.9", "10.0.0")

	if code != 3 {
		t.Errorf("exit %d, want 3\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "9.9.9") {
		t.Errorf("expected version '9.9.9' in stderr:\n%s", stderr)
	}
}

// TestE2E_ExitCode2_NoArgs: no CLI arguments → usage error, exit 2.
func TestE2E_ExitCode2_NoArgs(t *testing.T) {
	cmd := exec.Command(binaryPath)
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	err := cmd.Run()

	code := 0
	if err != nil {
		if ex, ok := err.(*exec.ExitError); ok {
			code = ex.ExitCode()
		}
	}
	if code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "Usage") {
		t.Errorf("expected 'Usage' in stderr:\n%s", errBuf.String())
	}
}

// TestE2E_ExitCode2_BadPackageArg: malformed package argument → exit 2.
func TestE2E_ExitCode2_BadPackageArg(t *testing.T) {
	reg := mockRegistry(t, map[string]*abbrevMeta{})
	_, stderr, code := run(t, reg, e2eFixture("v9-no-bump.yaml"), "no-at-sign", "1.0.0")

	if code != 2 {
		t.Errorf("exit %d, want 2\nstderr: %s", code, stderr)
	}
}

// TestE2E_JSONOutput: --json flag produces valid JSON with the expected fields;
// exit 0 for an all-fixable (NoBumpNeeded) scenario.
func TestE2E_JSONOutput(t *testing.T) {
	reg := mockRegistry(t, map[string]*abbrevMeta{
		"parent": {Name: "parent", Versions: map[string]*pkgVer{
			"1.0.0": {Dependencies: map[string]string{"vuln": "^3.0.0"}},
		}},
		"vuln": {Name: "vuln", Versions: map[string]*pkgVer{
			"3.0.0": {Dependencies: map[string]string{}},
			"3.5.0": {Dependencies: map[string]string{}},
		}},
	})

	stdout, stderr, code := run(t, reg, e2eFixture("v9-no-bump.yaml"),
		"--json", "vuln@3.0.0", "3.5.0")

	if code != 0 {
		t.Errorf("exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("expected valid JSON, got: %v\noutput: %s", err, stdout)
	}
	if result["VulnPkg"] != "vuln" {
		t.Errorf("JSON VulnPkg = %v, want 'vuln'", result["VulnPkg"])
	}
	if result["FixedVer"] != "3.5.0" {
		t.Errorf("JSON FixedVer = %v, want '3.5.0'", result["FixedVer"])
	}
	if allFixable, _ := result["AllFixable"].(bool); !allFixable {
		t.Errorf("JSON AllFixable = %v, want true", result["AllFixable"])
	}
}
