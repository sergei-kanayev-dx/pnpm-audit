package main

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestParseVersions(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string // joined, or "" when an error is expected
	}{
		{
			name: "list",
			out:  `["1.0.0","1.2.0","2.0.0"]`,
			want: "1.0.0,1.2.0,2.0.0",
		},
		{
			// pnpm prints a bare JSON string when the package has exactly one release.
			name: "single release",
			out:  `"1.0.0"`,
			want: "1.0.0",
		},
		{
			name: "sorted, not registry order",
			out:  `["2.0.0","1.0.0","1.10.0","1.2.0"]`,
			want: "1.0.0,1.2.0,1.10.0,2.0.0",
		},
		{
			// A tag that is not semver can never be a resolution target.
			name: "unparseable entries dropped",
			out:  `["1.0.0","not-a-version"]`,
			want: "1.0.0",
		},
		{name: "empty output", out: ``, want: ""},
		{name: "nothing parseable", out: `["nope"]`, want: ""},
		{name: "unexpected shape", out: `{"error":{"code":"E404"}}`, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseVersions("pkg", []byte(tt.out))
			if tt.want == "" {
				if err == nil {
					t.Fatalf("got %v, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var parts []string
			for _, v := range got {
				parts = append(parts, v.Original())
			}
			if joined := strings.Join(parts, ","); joined != tt.want {
				t.Errorf("got %s, want %s", joined, tt.want)
			}
		})
	}
}

// stubView swaps the `pnpm view` call out for the duration of a test.
func stubView(t *testing.T, fn func(dir string, args ...string) ([]byte, []byte, error)) {
	t.Helper()
	prev := runView
	runView = fn
	t.Cleanup(func() { runView = prev })
}

// A missing dependency field and an unreachable package both used to look like "",
// which for the fix search is the difference between "this version dropped the
// dependency, so the path is fixed" and "we know nothing".
func TestDeclaredRangeTellsAbsentFromUnreachable(t *testing.T) {
	stubView(t, func(dir string, args ...string) ([]byte, []byte, error) {
		switch args[0] {
		case "present@1.0.0":
			return []byte(`{"dependencies":{"child":"^1.0.0"},"peerDependencies":{"peer":"^2.0.0"}}`), nil, nil
		default:
			return []byte(`{"error":{"code":"E404","message":"Not found"}}`), nil, &exec.ExitError{}
		}
	})
	r := newRangeLookup(".", false)

	rng, present, err := r.declaredRange("present", "1.0.0", "child")
	if err != nil || !present || rng != "^1.0.0" {
		t.Errorf("declared child: got (%q, %v, %v), want (^1.0.0, true, nil)", rng, present, err)
	}

	// A peer dependency is a real edge in pnpm's graph and must be found too.
	if rng, present, err := r.declaredRange("present", "1.0.0", "peer"); err != nil || !present || rng != "^2.0.0" {
		t.Errorf("declared peer: got (%q, %v, %v), want (^2.0.0, true, nil)", rng, present, err)
	}

	_, present, err = r.declaredRange("present", "1.0.0", "absent")
	if err != nil || present {
		t.Errorf("absent field: got (present=%v, err=%v), want (false, nil)", present, err)
	}

	if _, _, err := r.declaredRange("gone", "1.0.0", "child"); err == nil {
		t.Error("unreachable package: got no error, want one")
	}
}

// A manifest answers every edge of one version, so a second child costs no extra call.
func TestManifestIsFetchedOncePerVersion(t *testing.T) {
	calls := 0
	stubView(t, func(dir string, args ...string) ([]byte, []byte, error) {
		calls++
		return []byte(`{"dependencies":{"a":"^1.0.0","b":"^2.0.0"}}`), nil, nil
	})
	r := newRangeLookup(".", false)

	r.declaredRange("p", "1.0.0", "a") //nolint:errcheck
	r.declaredRange("p", "1.0.0", "b") //nolint:errcheck
	r.declaredRange("p", "1.0.0", "a") //nolint:errcheck

	if calls != 1 {
		t.Errorf("pnpm view called %d times, want 1", calls)
	}
}

func TestLookupsDisabled(t *testing.T) {
	stubView(t, func(dir string, args ...string) ([]byte, []byte, error) {
		t.Fatal("registry must not be touched with lookups disabled")
		return nil, nil, nil
	})
	r := newRangeLookup(".", true)

	if got := r.get("p", "1.0.0", "a"); got != "" {
		t.Errorf("get = %q, want empty", got)
	}
	if _, err := r.publishedVersions("p"); !errors.Is(err, errLookupsDisabled) {
		t.Errorf("publishedVersions err = %v, want errLookupsDisabled", err)
	}
}
