package lockfile

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// SupportedVersions lists the lockfile versions this tool can handle.
var SupportedVersions = map[string]bool{
	"9.0": true,
}

type lockfileHeader struct {
	LockfileVersion string `yaml:"lockfileVersion"`
}

// DetectVersion reads the lockfileVersion field from the given pnpm-lock.yaml
// path and returns it. Returns an error if the file cannot be read, lacks a
// version field, or declares a version this tool does not support.
func DetectVersion(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening lockfile %q: %w", path, err)
	}
	defer f.Close()

	var hdr lockfileHeader
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&hdr); err != nil {
		return "", fmt.Errorf("parsing lockfile %q: %w", path, err)
	}

	if hdr.LockfileVersion == "" {
		return "", fmt.Errorf("lockfile %q: missing lockfileVersion field", path)
	}

	if !SupportedVersions[hdr.LockfileVersion] {
		return "", fmt.Errorf(
			"lockfile version %q is not supported (supported: 9.0); "+
				"only pnpm v9/v10 lockfiles are handled in this release",
			hdr.LockfileVersion,
		)
	}

	return hdr.LockfileVersion, nil
}
