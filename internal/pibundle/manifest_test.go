package pibundle

import (
	"errors"
	"testing"
)

func TestPinnedManifestIdentityAndRuntimeResources(t *testing.T) {
	entries, err := Entries()
	if err != nil {
		t.Fatalf("Entries() error = %v", err)
	}
	if len(entries) != FileCount {
		t.Fatalf("entry count = %d", len(entries))
	}
	want := map[string]string{
		"pi/pi":                "443bd83f30e4dbc7bac2eed9c6aa2461b9a15016fd555f48c92a0591d028c403",
		"pi/package.json":      "f1738e4b42203e5f22bcb513f13fb2fb224f1e98d1f129ff042f87048665a94c",
		"pi/theme/dark.json":   "103a5aecb74a2dab5cc903c9741845ee6158658ce2ff6e5445948784116eaef8",
		"pi/photon_rs_bg.wasm": "10468181565c56004c867f3a4af96f89a0ef5a63a72f2b5fb12c1f1992a3615c",
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if digest, ok := want[entry.Path]; ok {
			if entry.SHA256 != digest {
				t.Fatalf("%s digest = %s", entry.Path, entry.SHA256)
			}
			seen[entry.Path] = true
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("required runtime assets found = %#v", seen)
	}
	if err := ValidateRuntimeEntries(entries, true); err != nil {
		t.Fatalf("strict manifest rejected: %v", err)
	}
}

func TestRuntimeInventoryRejectsMissingExtraModeAndDigestDrift(t *testing.T) {
	entries, err := Entries()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]Entry{
		"missing": append([]Entry(nil), entries[:len(entries)-1]...),
		"extra":   append(append([]Entry(nil), entries...), Entry{Path: "pi/unlisted", Mode: 0o644, SHA256: entries[0].SHA256}),
		"mode":    append([]Entry(nil), entries...),
		"digest":  append([]Entry(nil), entries...),
	}
	if cases["mode"][0].Mode == 0o644 {
		cases["mode"][0].Mode = 0o755
	} else {
		cases["mode"][0].Mode = 0o644
	}
	cases["digest"][0].SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			strict := name == "digest"
			if err := ValidateRuntimeEntries(candidate, strict); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("ValidateRuntimeEntries() error = %v", err)
			}
		})
	}
}
