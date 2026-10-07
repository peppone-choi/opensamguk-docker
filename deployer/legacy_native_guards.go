package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
)

// Retained only for the existing image linker argument; it installs no authority.
var rootBuiltSourceSHA string

// Native presence is independent of D101 supplier availability. Missing D101
// inputs deny only D101 paths; genuinely absent owner preserves normal startup.
type resetD101RootOwnerState int32

const (
	resetD101RootOwnerAbsent resetD101RootOwnerState = iota
	resetD101RootOwnerPresent
	resetD101RootOwnerUnknown
)

type resetD101RootOwnerGate struct {
	state  atomic.Int32
	frozen atomic.Bool
	// Immutable after publication under coordinator -> jobs -> store locks.
	preparation *operationPreparation
}

func (g *resetD101RootOwnerGate) blocksAdmission() bool {
	return g != nil && resetD101RootOwnerState(g.state.Load()) != resetD101RootOwnerAbsent
}
func (g *resetD101RootOwnerGate) blocksMutation() bool {
	return g != nil && (g.frozen.Load() || resetD101RootOwnerState(g.state.Load()) == resetD101RootOwnerUnknown)
}
func (g *resetD101RootOwnerGate) blocksPromotion(p *operationPreparation) bool {
	return g.blocksAdmission() && (g.blocksMutation() || g.preparation != p)
}
func resetD101RootOwnerPath(servers string) string {
	return filepath.Join(servers, ".deployer-d101-native-owner")
}

// An observed unresolved owner cannot become absent merely because its path
// disappears. No create/open/chmod/prune/authentication occurs during this probe.
func probeResetD101RootOwner(path string, unresolved bool) resetD101RootOwnerState {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return resetD101RootOwnerUnknown
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if unresolved {
				return resetD101RootOwnerUnknown
			}
			return resetD101RootOwnerAbsent
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return resetD101RootOwnerUnknown
		}
		if i < len(parts)-1 {
			if !info.IsDir() {
				return resetD101RootOwnerUnknown
			}
			continue
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 || info.Mode().Perm() != 0400 {
			return resetD101RootOwnerUnknown
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || st.Nlink != 1 {
			return resetD101RootOwnerUnknown
		}
		return resetD101RootOwnerPresent
	}
	return resetD101RootOwnerUnknown
}
func resetD101RootStartupOwner(servers string, unresolved bool) error {
	if probeResetD101RootOwner(resetD101RootOwnerPath(servers), unresolved) != resetD101RootOwnerAbsent {
		return errResetExecutionEvidence
	}
	return nil
}

func (g *resetD101RootOwnerGate) allowsPreparationDrain(operationID, fingerprint string, kind lifecycleKind) bool {
	if g == nil {
		return false
	}
	p := g.preparation
	return g != nil && !g.blocksMutation() && p != nil && p.operationID != "" && p.operationID == operationID && p.fingerprint == fingerprint && p.kind == kind
}
func (c *operationCoordinator) nativeMutationBlocked() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.d101NativeOwner.blocksMutation()
}
func (c *operationCoordinator) nativeAdmissionBlocked() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.d101NativeOwner.blocksAdmission()
}

func resetD101RestoreGatePath(marker string) string {
	if marker == "" {
		return ""
	}
	return marker + ".d101-restore1"
}
