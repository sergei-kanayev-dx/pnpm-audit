package main

import (
	"testing"
)

func TestParsePackageArg(t *testing.T) {
	tests := []struct {
		arg         string
		wantName    string
		wantVersion string
		wantErr     bool
	}{
		{
			arg:         "lodash@4.17.10",
			wantName:    "lodash",
			wantVersion: "4.17.10",
		},
		{
			arg:         "@babel/traverse@7.22.0",
			wantName:    "@babel/traverse",
			wantVersion: "7.22.0",
		},
		{
			arg:         "@scope/name@1.2.3",
			wantName:    "@scope/name",
			wantVersion: "1.2.3",
		},
		{
			arg:         "express@4.18.2",
			wantName:    "express",
			wantVersion: "4.18.2",
		},
		{
			arg:         "@my-org/my-pkg@0.0.1",
			wantName:    "@my-org/my-pkg",
			wantVersion: "0.0.1",
		},
		{
			// no version at all
			arg:     "lodash",
			wantErr: true,
		},
		{
			// starts with @ but no version
			arg:     "@scope/name",
			wantErr: true,
		},
		{
			// empty string
			arg:     "",
			wantErr: true,
		},
		{
			// leading @ only, no name after scope
			arg:     "@4.17.10",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.arg, func(t *testing.T) {
			name, ver, err := ParsePackageArg(tc.arg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParsePackageArg(%q) = (%q, %q, nil), want error", tc.arg, name, ver)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePackageArg(%q) unexpected error: %v", tc.arg, err)
			}
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
			if ver != tc.wantVersion {
				t.Errorf("version = %q, want %q", ver, tc.wantVersion)
			}
		})
	}
}
