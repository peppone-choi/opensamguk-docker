package d101hostlaunch

import (
	"context"
	"errors"
	"testing"
)

func TestExistingHostLauncherMissingInheritedDescriptorNeverStartsHelper(t *testing.T) {
	for _, mode := range []string{"nil-context", "cancelled", "missing-fd", "missing-pins"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			if mode == "nil-context" {
				ctx = nil
			}
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			result, err := RunCurrent(ctx, nil, Pins{})
			if !errors.Is(err, ErrUnavailable) || len(result.Original()) != 0 {
				t.Fatal("uninstalled/missing keeper launched reader", err)
			}
		})
	}
}
func TestExistingHostLauncherBoundedOriginalAndDefensiveCopy(t *testing.T) {
	w := limitedOutput{limit: 4}
	if n, e := w.Write([]byte("1234")); n != 4 || e != nil {
		t.Fatal(n, e)
	}
	if n, e := w.Write([]byte("5")); n != 0 || !errors.Is(e, ErrUncertain) || !w.overflow || string(w.bytes) != "1234" {
		t.Fatal(n, e)
	}
	r := Result{original: []byte("raw8")}
	copy := r.Original()
	copy[0] = 'X'
	if string(r.Original()) != "raw8" {
		t.Fatal("shared mutable raw")
	}
}
