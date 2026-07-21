package npmsemver

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
)

// Satisfies reports whether version satisfies the npm-style semver range rangeStr.
func Satisfies(version, rangeStr string) (bool, error) {
	v, err := semver.NewVersion(version)
	if err != nil {
		return false, fmt.Errorf("invalid version %q: %w", version, err)
	}
	c, err := semver.NewConstraint(rangeStr)
	if err != nil {
		return false, fmt.Errorf("invalid range %q: %w", rangeStr, err)
	}
	return c.Check(v), nil
}

// MinVersionAbove returns the smallest version in sorted that is strictly
// greater than current and for which predicate returns true.
// sorted must be in ascending semver order.
func MinVersionAbove(sorted []string, current string, predicate func(string) bool) (string, bool) {
	cur, err := semver.NewVersion(current)
	if err != nil {
		return "", false
	}
	for _, v := range sorted {
		sv, err := semver.NewVersion(v)
		if err != nil {
			continue
		}
		if sv.GreaterThan(cur) && predicate(v) {
			return v, true
		}
	}
	return "", false
}
