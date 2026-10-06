package main

import (
	"context"
	"opensamguk-deployer/internal/d101custody"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCurrentFreezeNegativeInstallationNeverConstructsUnknownProducer(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		p, err := readCurrentFreezeInstallationNegative(ctx, d101custody.Original{})
		if p != nil || err == nil {
			t.Fatal("unknown codecs became supplier")
		}
	}
}
func TestCurrentFreezeAuthorityPinsRejectAliasAndReadbackTrust(t *testing.T) {
	op := strings.Repeat("a", 32)
	sha := strings.Repeat("b", 64)
	pin := d101custody.NativeFilePin{SHA256: sha, FileMode: 0400, LinkCount: 1, ParentMode: 0700, Snapshot: d101custody.PrivateSnapshot{Inode: 1}, ParentSnapshot: d101custody.PrivateSnapshot{Inode: 2}}
	v := currentFreezeAuthorityExpected{operationID: op, targetSHA: sha, revision: "2", freezeSHA: sha, readerSHA: sha, cutoff: time.Now().Add(time.Minute), anchorPath: "/etc/opensamguk/d101/installation-anchor.spki", anchorPin: pin, leaves: map[string]d101custody.NativeFilePin{}}
	for _, leaf := range currentFreezeAuthorityLeaves {
		v.leaves[filepath.Join("/etc/opensamguk/d101/current-authority", op, leaf)] = pin
	}
	// Shape validation is data only; it never yields a supplier.
	if validateCurrentFreezeAuthorityExpected(&v, d101custody.Original{SHA256: sha}) != nil {
		t.Fatal("fixture data")
	}
	if validateCurrentFreezeAuthorityExpected(&v, d101custody.Original{SHA256: strings.Repeat("c", 64)}) == nil {
		t.Fatal("adopted actual reader SHA")
	}
	for p := range v.leaves {
		delete(v.leaves, p)
		v.leaves[p+"/../alias"] = pin
		break
	}
	if validateCurrentFreezeAuthorityExpected(&v, d101custody.Original{SHA256: sha}) == nil {
		t.Fatal("alias leaf accepted")
	}
}
