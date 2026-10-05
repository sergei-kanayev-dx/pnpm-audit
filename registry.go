package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"

	"github.com/Masterminds/semver/v3"
)

// maxRegistryJobs bounds concurrent `pnpm view` calls. Each one is a registry
// round-trip; eight keeps a large report responsive without hammering the proxy.
const maxRegistryJobs = 8

// runView shells out to `pnpm view`. It is a variable so tests can stub the registry
// without a network or a pnpm binary.
var runView = func(dir string, args ...string) (stdout, stderr []byte, err error) {
	var out, errBuf bytes.Buffer
	cmd := exec.Command("pnpm", append([]string{"view"}, args...)...)
	cmd.Dir = dir
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return bytes.TrimSpace(out.Bytes()), errBuf.Bytes(), err
}

// pkgManifest is the slice of a published manifest this tool reasons about. Fetching the
// whole document costs one registry round-trip per (package, version) and answers every
// question about that version's edges, where asking field by field costs one per edge.
type pkgManifest struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Deprecated           string            `json:"deprecated"`
}

// rangeFor reports the range this version declares for child, and whether it declares
// one at all. The two answers must be told apart: a version that no longer depends on a
// vulnerable package has severed the path, which is a fix.
func (m *pkgManifest) rangeFor(child string) (string, bool) {
	for _, field := range []map[string]string{m.Dependencies, m.OptionalDependencies, m.PeerDependencies} {
		if r, ok := field[child]; ok {
			return r, true
		}
	}
	return "", false
}

// rangeLookup answers "what does parent@version declare for child?" and "which versions
// of this package exist?" by shelling out to `pnpm view`, memoising every answer.
// Usage paths share long prefixes and repeat across advisories, so the cache collapses
// thousands of would-be registry calls into a few dozen.
type rangeLookup struct {
	dir      string
	disabled bool

	mu        sync.Mutex
	manifests map[string]*manifestResult
	versions  map[string]*versionsResult
	errs      map[string]struct{} // distinct registry failures, for a footnote
}

// manifestResult is one in-flight or completed lookup. The done channel makes concurrent
// requests for the same key wait for the first one rather than duplicating the call.
type manifestResult struct {
	done chan struct{}
	m    *pkgManifest
	err  error
}

type versionsResult struct {
	done chan struct{}
	v    []*semver.Version
	err  error
}

func newRangeLookup(dir string, disabled bool) *rangeLookup {
	return &rangeLookup{
		dir:       dir,
		disabled:  disabled,
		manifests: make(map[string]*manifestResult),
		versions:  make(map[string]*versionsResult),
		errs:      make(map[string]struct{}),
	}
}

func specOf(name, version string) string { return name + "@" + version }

// errLookupsDisabled is returned to the fix search when -no-ranges suppressed the
// registry; the search cannot run at all in that mode.
var errLookupsDisabled = errors.New("registry lookups are disabled")

// manifest fetches (once) the published manifest of pkg@version.
func (r *rangeLookup) manifest(pkg, version string) (*pkgManifest, error) {
	if r.disabled {
		return nil, errLookupsDisabled
	}
	if pkg == "" || version == "" {
		return nil, errors.New("incomplete package spec")
	}
	spec := specOf(pkg, version)

	r.mu.Lock()
	res, ok := r.manifests[spec]
	if !ok {
		res = &manifestResult{done: make(chan struct{})}
		r.manifests[spec] = res
	}
	r.mu.Unlock()

	if ok {
		<-res.done
		return res.m, res.err
	}

	res.m, res.err = r.fetchManifest(spec)
	close(res.done)
	if res.err != nil {
		r.noteErr(res.err.Error())
	}
	return res.m, res.err
}

func (r *rangeLookup) fetchManifest(spec string) (*pkgManifest, error) {
	stdout, stderr, runErr := runView(r.dir, spec, "--json")
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			// pnpm missing from PATH, or the directory is gone.
			return nil, fmt.Errorf("%s: %v", spec, runErr)
		}
		return nil, errors.New(viewError(spec, stdout, stderr))
	}
	if len(stdout) == 0 {
		return nil, fmt.Errorf("%s: pnpm view returned no manifest", spec)
	}

	var m pkgManifest
	if err := json.Unmarshal(stdout, &m); err != nil {
		return nil, fmt.Errorf("%s: unexpected `pnpm view` output %s", spec, truncate(string(stdout), 120))
	}
	return &m, nil
}

// publishedVersions returns every published version of pkg, sorted ascending, with
// unparseable tags dropped.
func (r *rangeLookup) publishedVersions(pkg string) ([]*semver.Version, error) {
	if r.disabled {
		return nil, errLookupsDisabled
	}
	if pkg == "" {
		return nil, errors.New("empty package name")
	}

	r.mu.Lock()
	res, ok := r.versions[pkg]
	if !ok {
		res = &versionsResult{done: make(chan struct{})}
		r.versions[pkg] = res
	}
	r.mu.Unlock()

	if ok {
		<-res.done
		return res.v, res.err
	}

	res.v, res.err = r.fetchVersions(pkg)
	close(res.done)
	if res.err != nil {
		r.noteErr(res.err.Error())
	}
	return res.v, res.err
}

func (r *rangeLookup) fetchVersions(pkg string) ([]*semver.Version, error) {
	stdout, stderr, runErr := runView(r.dir, pkg, "versions", "--json")
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return nil, fmt.Errorf("%s: %v", pkg, runErr)
		}
		return nil, errors.New(viewError(pkg, stdout, stderr))
	}
	return parseVersions(pkg, stdout)
}

// parseVersions decodes the two shapes `pnpm view <pkg> versions --json` produces: a JSON
// array normally, but a bare JSON string when the package has exactly one release.
func parseVersions(pkg string, out []byte) ([]*semver.Version, error) {
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, fmt.Errorf("%s: no versions published", pkg)
	}

	var raw []string
	if err := json.Unmarshal(out, &raw); err != nil {
		var single string
		if err2 := json.Unmarshal(out, &single); err2 != nil {
			return nil, fmt.Errorf("%s: unexpected version list %s", pkg, truncate(string(out), 120))
		}
		raw = []string{single}
	}

	versions := make([]*semver.Version, 0, len(raw))
	for _, s := range raw {
		// A registry can carry a tag that is not semver at all; it can never be a
		// resolution target, so dropping it is safe.
		if v, err := semver.NewVersion(s); err == nil {
			versions = append(versions, v)
		}
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("%s: no parseable versions", pkg)
	}
	sort.Sort(semver.Collection(versions))
	return versions, nil
}

// declaredRange reports the range parent@version declares for child. present is false
// when that version simply does not depend on child; err is non-nil only when the
// registry could not answer. Conflating the two would let a registry outage read as
// "this version dropped the dependency", i.e. as a fix.
func (r *rangeLookup) declaredRange(parentName, parentVersion, child string) (rng string, present bool, err error) {
	m, err := r.manifest(parentName, parentVersion)
	if err != nil {
		return "", false, err
	}
	rng, present = m.rangeFor(child)
	return rng, present, nil
}

// prefetch resolves the manifest behind every distinct edge across all chains
// concurrently, so that the render pass afterwards is a pure cache read.
func (r *rangeLookup) prefetch(chains [][]hop) {
	if r.disabled {
		return
	}

	pending := make(map[string][2]string)
	for _, c := range chains {
		for _, h := range c {
			if h.parentName == "" || h.parentVersion == "" {
				continue
			}
			pending[specOf(h.parentName, h.parentVersion)] = [2]string{h.parentName, h.parentVersion}
		}
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxRegistryJobs)
	for _, p := range pending {
		wg.Add(1)
		sem <- struct{}{}
		go func(name, version string) {
			defer wg.Done()
			defer func() { <-sem }()
			r.manifest(name, version) //nolint:errcheck // recorded via noteErr
		}(p[0], p[1])
	}
	wg.Wait()
}

// prefetchVersions warms the version list of every named package concurrently. The fix
// search is sequential by nature, so this is the only place its registry work parallelises.
func (r *rangeLookup) prefetchVersions(names []string) {
	if r.disabled {
		return
	}

	distinct := make(map[string]struct{}, len(names))
	for _, n := range names {
		if n != "" {
			distinct[n] = struct{}{}
		}
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxRegistryJobs)
	for n := range distinct {
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			r.publishedVersions(name) //nolint:errcheck // recorded via noteErr
		}(n)
	}
	wg.Wait()
}

// get returns the range a parent declares for a child, or "" when it is unknown, absent,
// or lookups are disabled. The tree printer renders all three as "?".
func (r *rangeLookup) get(parentName, parentVersion, child string) string {
	if r.disabled || parentName == "" || parentVersion == "" {
		return ""
	}
	rng, _, err := r.declaredRange(parentName, parentVersion, child)
	if err != nil {
		return ""
	}
	return rng
}

// viewError turns a failed `pnpm view` into one readable line, preferring the JSON
// error object pnpm prints on stdout over raw stderr.
func viewError(spec string, stdout, stderr []byte) string {
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(stdout, &payload); err == nil && payload.Error.Code != "" {
		return fmt.Sprintf("%s: %s (%s)", spec, payload.Error.Message, payload.Error.Code)
	}
	if msg := strings.TrimSpace(string(stderr)); msg != "" {
		return fmt.Sprintf("%s: %s", spec, truncate(msg, 200))
	}
	return spec + ": pnpm view failed"
}

func (r *rangeLookup) noteErr(msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs[msg] = struct{}{}
}

// problems returns the distinct registry failures seen, sorted for stable output.
func (r *rangeLookup) problems() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]string, 0, len(r.errs))
	for msg := range r.errs {
		out = append(out, msg)
	}
	sort.Strings(out)
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// warmManifests fetches a batch of candidate manifests concurrently. The fix search scans
// candidate versions in order and stops at the first one that works, so it cannot be
// parallelised itself; warming the batch it is about to walk through is the next best
// thing. Failures are recorded, not returned -- the search asks for each one again and
// gets the cached answer.
func (r *rangeLookup) warmManifests(pkg string, versions []string) {
	if r.disabled {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxRegistryJobs)
	for _, v := range versions {
		wg.Add(1)
		sem <- struct{}{}
		go func(version string) {
			defer wg.Done()
			defer func() { <-sem }()
			r.manifest(pkg, version) //nolint:errcheck // recorded via noteErr
		}(v)
	}
	wg.Wait()
}
