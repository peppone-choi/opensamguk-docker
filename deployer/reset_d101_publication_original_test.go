package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestD101PublicationOriginalWholeBytesAndDefensiveCopy(t *testing.T) {
	value, binding := resetAdminPublicationFixture(t)
	body, _ := json.Marshal(value)
	wire := append(append([]byte(" \n"), body...), []byte("\n\t")...)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	observed, err := getResetAdminPublication(context.Background(), server.URL, "aaa.bbb.ccc", binding, "2")
	if err != nil || calls != 1 || !bytes.Equal(observed.Original(), wire) || observed.BodySHA256 != resetD101OriginalSHA(wire) || requireResetD101PublicationOriginal(observed, binding, "2") != nil {
		t.Fatal("actual whole GET body was replaced or not bound")
	}
	copy := observed.Original()
	copy[0] = '!'
	if !bytes.Equal(observed.Original(), wire) || requireResetD101PublicationOriginal(observed, binding, "2") != nil {
		t.Fatal("caller changed retained publication original")
	}
}

func TestD101PublicationOriginalRejectsDigestTypedOrBodyDrift(t *testing.T) {
	value, binding := resetAdminPublicationFixture(t)
	wire, _ := json.Marshal(value)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(wire) }))
	defer server.Close()
	observed, err := getResetAdminPublication(context.Background(), server.URL, "aaa.bbb.ccc", binding, "2")
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	for _, name := range []string{"digest", "typed", "bytes", "missing"} {
		t.Run(name, func(t *testing.T) {
			bad := observed
			bad.original = bytes.Clone(observed.original)
			switch name {
			case "digest":
				bad.BodySHA256 = strings.Repeat("f", 64)
			case "typed":
				bad.Current.Revision = "3"
			case "bytes":
				bad.original = append(bad.original, '\n')
			case "missing":
				bad.original = nil
			}
			if requireResetD101PublicationOriginal(bad, binding, "2") == nil {
				t.Fatal("digest/typed/body mismatch became original evidence")
			}
		})
	}
}

func TestD101PublicationOriginalRejectsCaseAliasBeforeRetention(t *testing.T) {
	value, binding := resetAdminPublicationFixture(t)
	wire, _ := json.Marshal(value)
	wire = []byte(strings.Replace(string(wire), `"serverId":`, `"ServerID":`, 1))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(wire) }))
	defer server.Close()
	observed, err := getResetAdminPublication(context.Background(), server.URL, "aaa.bbb.ccc", binding, "2")
	if err == nil || len(observed.Original()) != 0 || observed.BodySHA256 != "" {
		t.Fatal("case-insensitive alias became strict ADMIN original")
	}
}
