package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPreStopGatewayUninstalledAuthorityNeverReadsRemoteOrRunsDocker(t *testing.T) {
	remoteCalls, dockerCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteCalls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	for _, mode := range []string{"nil-context", "cancelled", "nil-preparation", "invalid-prepare-sha", "uninstalled-authority"} {
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
			s := &resetD101PreStopPreparation{}
			if mode == "nil-preparation" {
				s = nil
			}
			sha := strings.Repeat("a", 64)
			if mode == "invalid-prepare-sha" {
				sha = ""
			}
			c := config{gatewayAPIURL: server.URL, dockerRunner: func(args ...string) (string, error) {
				dockerCalls++
				return "", nil
			}}
			observed, err := c.readResetD101PreStopGateway(ctx, s, sha)
			if err == nil || len(observed.gateway.Original()) != 0 || !observed.publication.ObservedAt.IsZero() || remoteCalls != 0 || dockerCalls != 0 {
				t.Fatal("uninstalled pre-stop authority reached a source or returned an observation")
			}
		})
	}
}
