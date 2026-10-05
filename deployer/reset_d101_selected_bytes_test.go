package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func selectedD101Fixture(t *testing.T) (resetD101SelectedBytePins, map[string][]byte) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(base, "selected")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	pins := resetD101SelectedBytePins{Directory: directory, Pins: make(map[string]resetD101RawBytePin)}
	originals := make(map[string][]byte)
	for _, leaf := range []string{"tiles.json", "world.json", "roads.json", "selected-scenario.json", "classpath-scenario.json"} {
		// Preserve whitespace and binary bytes: this reader imposes no JSON schema.
		wire := append([]byte(" \n"+leaf+"\r\n"), 0, 0xff)
		sum := sha256.Sum256(wire)
		pins.Pins[leaf] = resetD101RawBytePin{SHA256: hex.EncodeToString(sum[:]), ByteLength: uint64(len(wire))}
		originals[leaf] = wire
		if err := os.WriteFile(filepath.Join(directory, leaf), wire, 0400); err != nil {
			t.Fatal(err)
		}
	}
	return pins, originals
}

func TestResetD101SelectedBytesOriginalsAndDefensiveCopies(t *testing.T) {
	pins, originals := selectedD101Fixture(t)
	selected, err := readResetD101SelectedBytesWithCustodyUID(pins, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	for leaf, original := range originals {
		wire, ok := selected.Bytes(leaf)
		if !ok || !bytes.Equal(wire, original) {
			t.Fatalf("original bytes differ for %s", leaf)
		}
		wire[0] ^= 0xff
		again, _ := selected.Bytes(leaf)
		if !bytes.Equal(again, original) {
			t.Fatalf("Bytes exposed mutable storage for %s", leaf)
		}
		if observed := selected.ObservedPins()[leaf]; observed != pins.Pins[leaf] {
			t.Fatalf("computed observation differs for %s", leaf)
		}
	}
	observed := selected.ObservedPins()
	delete(observed, "tiles.json")
	pins.Pins["world.json"] = resetD101RawBytePin{}
	if len(selected.ObservedPins()) != 5 || selected.ObservedPins()["world.json"].ByteLength == 0 {
		t.Fatal("pin maps exposed mutable storage")
	}
	if wire, ok := selected.Bytes("../tiles.json"); ok || wire != nil {
		t.Fatal("unknown leaf was returned")
	}
	var empty resetD101SelectedBytes
	if len(empty.ObservedPins()) != 0 {
		t.Fatal("zero result contains pins")
	}
}

func TestResetD101SelectedBytesRejectsPins(t *testing.T) {
	mutations := map[string]func(*testing.T, *resetD101SelectedBytePins){
		"empty":   func(t *testing.T, p *resetD101SelectedBytePins) { p.Pins = nil },
		"unknown": func(t *testing.T, p *resetD101SelectedBytePins) { p.Pins["other.json"] = p.Pins["tiles.json"] },
		"traversal": func(t *testing.T, p *resetD101SelectedBytePins) {
			p.Pins["../tiles.json"] = p.Pins["tiles.json"]
			delete(p.Pins, "tiles.json")
		},
		"wrong digest": func(t *testing.T, p *resetD101SelectedBytePins) {
			pin := p.Pins["roads.json"]
			pin.SHA256 = strings.Repeat("0", 64)
			p.Pins["roads.json"] = pin
		},
		"invalid digest": func(t *testing.T, p *resetD101SelectedBytePins) {
			pin := p.Pins["tiles.json"]
			pin.SHA256 = strings.Repeat("z", 64)
			p.Pins["tiles.json"] = pin
		},
		"uppercase digest": func(t *testing.T, p *resetD101SelectedBytePins) {
			pin := p.Pins["tiles.json"]
			pin.SHA256 = strings.ToUpper(pin.SHA256)
			p.Pins["tiles.json"] = pin
		},
		"short digest": func(t *testing.T, p *resetD101SelectedBytePins) {
			pin := p.Pins["tiles.json"]
			pin.SHA256 = "00"
			p.Pins["tiles.json"] = pin
		},
		"zero length": func(t *testing.T, p *resetD101SelectedBytePins) {
			pin := p.Pins["tiles.json"]
			pin.ByteLength = 0
			p.Pins["tiles.json"] = pin
		},
		"wrong length": func(t *testing.T, p *resetD101SelectedBytePins) {
			pin := p.Pins["tiles.json"]
			pin.ByteLength++
			p.Pins["tiles.json"] = pin
		},
		"over cap": func(t *testing.T, p *resetD101SelectedBytePins) {
			pin := p.Pins["tiles.json"]
			pin.ByteLength = resetD101SelectedByteLimit + 1
			p.Pins["tiles.json"] = pin
		},
	}
	for _, leaf := range []string{"tiles.json", "world.json", "roads.json", "selected-scenario.json", "classpath-scenario.json"} {
		leaf := leaf
		mutations["missing "+leaf] = func(t *testing.T, p *resetD101SelectedBytePins) { delete(p.Pins, leaf) }
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			pins, _ := selectedD101Fixture(t)
			mutate(t, &pins)
			assertSelectedD101Rejected(t, pins, uint32(os.Getuid()))
		})
	}
}

func TestResetD101SelectedBytesRejectsCustody(t *testing.T) {
	mutations := map[string]func(*testing.T, *resetD101SelectedBytePins){
		"file writable": func(t *testing.T, p *resetD101SelectedBytePins) {
			mustSelectedD101(t, os.Chmod(filepath.Join(p.Directory, "tiles.json"), 0600))
		},
		"file group readable": func(t *testing.T, p *resetD101SelectedBytePins) {
			mustSelectedD101(t, os.Chmod(filepath.Join(p.Directory, "tiles.json"), 0440))
		},
		"root group accessible": func(t *testing.T, p *resetD101SelectedBytePins) { mustSelectedD101(t, os.Chmod(p.Directory, 0750)) },
		"root wrong mode":       func(t *testing.T, p *resetD101SelectedBytePins) { mustSelectedD101(t, os.Chmod(p.Directory, 0500)) },
		"root special mode": func(t *testing.T, p *resetD101SelectedBytePins) {
			mustSelectedD101(t, os.Chmod(p.Directory, 0700|os.ModeSticky))
		},
		"missing file": func(t *testing.T, p *resetD101SelectedBytePins) {
			mustSelectedD101(t, os.Remove(filepath.Join(p.Directory, "classpath-scenario.json")))
		},
		"changed original": func(t *testing.T, p *resetD101SelectedBytePins) {
			path := filepath.Join(p.Directory, "roads.json")
			wire, err := os.ReadFile(path)
			mustSelectedD101(t, err)
			wire[0] ^= 1
			mustSelectedD101(t, os.Chmod(path, 0600))
			mustSelectedD101(t, os.WriteFile(path, wire, 0400))
			mustSelectedD101(t, os.Chmod(path, 0400))
		},
		"hard link": func(t *testing.T, p *resetD101SelectedBytePins) {
			mustSelectedD101(t, os.Link(filepath.Join(p.Directory, "tiles.json"), filepath.Join(filepath.Dir(p.Directory), "alias.json")))
		},
		"leaf symlink": func(t *testing.T, p *resetD101SelectedBytePins) {
			path := filepath.Join(p.Directory, "tiles.json")
			target := filepath.Join(filepath.Dir(p.Directory), "outside.json")
			mustSelectedD101(t, os.Rename(path, target))
			mustSelectedD101(t, os.Symlink(target, path))
		},
		"root symlink": func(t *testing.T, p *resetD101SelectedBytePins) {
			alias := filepath.Join(filepath.Dir(p.Directory), "alias")
			mustSelectedD101(t, os.Symlink(p.Directory, alias))
			p.Directory = alias
		},
		"relative root": func(t *testing.T, p *resetD101SelectedBytePins) { p.Directory = "selected" },
		"unclean root":  func(t *testing.T, p *resetD101SelectedBytePins) { p.Directory += "/." },
		"directory leaf": func(t *testing.T, p *resetD101SelectedBytePins) {
			path := filepath.Join(p.Directory, "tiles.json")
			mustSelectedD101(t, os.Remove(path))
			mustSelectedD101(t, os.Mkdir(path, 0400))
		},
		"FIFO leaf": func(t *testing.T, p *resetD101SelectedBytePins) {
			path := filepath.Join(p.Directory, "tiles.json")
			mustSelectedD101(t, os.Remove(path))
			mustSelectedD101(t, syscall.Mkfifo(path, 0400))
		},
		"oversize file": func(t *testing.T, p *resetD101SelectedBytePins) {
			path := filepath.Join(p.Directory, "tiles.json")
			mustSelectedD101(t, os.Chmod(path, 0600))
			mustSelectedD101(t, os.Truncate(path, int64(resetD101SelectedByteLimit)+1))
			mustSelectedD101(t, os.Chmod(path, 0400))
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			pins, _ := selectedD101Fixture(t)
			mutate(t, &pins)
			assertSelectedD101Rejected(t, pins, uint32(os.Getuid()))
		})
	}
	t.Run("wrong custody UID", func(t *testing.T) {
		pins, _ := selectedD101Fixture(t)
		assertSelectedD101Rejected(t, pins, uint32(os.Getuid())+1)
	})
	t.Run("production fixes root UID", func(t *testing.T) {
		pins, _ := selectedD101Fixture(t)
		result, err := readResetD101SelectedBytes(pins)
		if os.Getuid() == 0 {
			if err != nil || len(result.ObservedPins()) != 5 {
				t.Fatal("root fixture rejected")
			}
		} else if err == nil || len(result.ObservedPins()) != 0 {
			t.Fatal("production reader accepted non-root custody")
		}
	})
}

func assertSelectedD101Rejected(t *testing.T, pins resetD101SelectedBytePins, uid uint32) {
	t.Helper()
	selected, err := readResetD101SelectedBytesWithCustodyUID(pins, uid)
	if err == nil || len(selected.ObservedPins()) != 0 {
		t.Fatal("invalid selection returned success or partial observations")
	}
	for leaf := range pins.Pins {
		if wire, ok := selected.Bytes(leaf); ok || wire != nil {
			t.Fatal("invalid selection returned partial original bytes")
		}
	}
}

func mustSelectedD101(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
