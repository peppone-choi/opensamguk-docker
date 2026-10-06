package main

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"testing"
)

// Fixture ownership is limited to disposable files. It never authenticates an
// installer, management session, human approval, or an operating target.
func productionOriginalsFixture(t *testing.T) (*resetD101ProductionOriginals, []resetD101Key3OriginalRef) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		t.Skip("actual native root descriptor regression requires isolated Linux UID0 QA")
	}
	v := &resetD101ProductionOriginals{held: make(map[string]*resetD101NativeHeldInput)}
	t.Cleanup(v.close)
	for i := 0; i < 2; i++ {
		path, pin, uid := nativeInstallInputFixture(t)
		h, err := openResetD101NativeInputWithAncestors(context.Background(), path, pin, 0400, uid, func(string, uint32) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		ref := resetD101Key3OriginalRef{Path: path, Bytes: uint64(len(h.wire)), SHA256: pin.SHA256}
		v.refs = append(v.refs, ref)
		v.held[path] = h
	}
	return v, append([]resetD101Key3OriginalRef(nil), v.refs...)
}

func TestNativeProductionOriginalsRejectSiblingReplacement(t *testing.T) {
	v, refs := productionOriginalsFixture(t)
	ctx := context.Background()
	if _, err := v.original(ctx, refs[0]); err != nil {
		t.Fatal(err)
	}
	path := refs[1].Path
	if os.Rename(path, path+".old") != nil || os.WriteFile(path, v.held[path].wire, 0400) != nil {
		t.Fatal("fixture replacement")
	}
	if raw, err := v.original(ctx, refs[0]); err == nil || len(raw.Bytes) != 0 {
		t.Fatal("matching original hid a replaced sibling")
	}
}

func TestNativeProductionOriginalsCopiesAndClosesHeldBytes(t *testing.T) {
	v, refs := productionOriginalsFixture(t)
	ctx := context.Background()
	raw, err := v.original(ctx, refs[0])
	if err != nil {
		t.Fatal(err)
	}
	held := v.held[refs[0].Path]
	want := bytes.Clone(held.wire)
	raw.Bytes[0] ^= 1
	if !bytes.Equal(held.wire, want) || v.recheck(ctx) != nil {
		t.Fatal("caller buffer aliases the held original")
	}
	private := held.wire
	v.close()
	v.close()
	if !bytes.Equal(private, make([]byte, len(private))) || held.wire != nil {
		t.Fatal("retained private bytes survived close")
	}
	if _, err := held.file.Stat(); err == nil {
		t.Fatal("original descriptor survived close")
	}
	if _, err := held.directory.Stat(); err == nil {
		t.Fatal("parent descriptor survived close")
	}
	if raw, err := v.original(ctx, refs[0]); err == nil || len(raw.Bytes) != 0 {
		t.Fatal("closed collection remained readable")
	}
}

func TestNativeProductionOriginalsRejectCancelledAndDifferentReference(t *testing.T) {
	v, refs := productionOriginalsFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if raw, err := v.original(ctx, refs[0]); err == nil || len(raw.Bytes) != 0 {
		t.Fatal("cancelled collection read")
	}
	wrong := refs[0]
	wrong.Bytes++
	if raw, err := v.original(context.Background(), wrong); err == nil || len(raw.Bytes) != 0 {
		t.Fatal("path-only reference accepted")
	}
}
