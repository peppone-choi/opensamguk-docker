package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"opensamguk-deployer/internal/d101native"
)

func TestInstalledEntryRejectsMissingSource(t *testing.T) {
	bounded, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cancelled, stop := context.WithCancel(bounded)
	stop()
	for _, item := range []struct { name string; ctx context.Context }{
		{"nil", nil}, {"unbounded", context.Background()}, {"bounded", bounded}, {"cancelled", cancelled},
	} {
		t.Run(item.name, func(t *testing.T) {
			if err := run(item.ctx); !errors.Is(err, d101native.ErrUnavailable) {
				t.Fatalf("missing installed source accepted: %v", err)
			}
		})
	}
}
