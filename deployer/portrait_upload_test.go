package main

import (
	"os"
	"regexp"
	"testing"
)

func TestPortraitOriginalUploadHasScopedBodyLimit(t *testing.T) {
	data, err := os.ReadFile("../infra/nginx/nginx.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"/api/account/profile-icon", "/api/gateway/auth/account/profile-icon"} {
		pattern := regexp.MustCompile(`(?s)location = ` + regexp.QuoteMeta(endpoint) + `\s*\{([^}]+)\}`)
		blocks := pattern.FindAllSubmatch(data, -1)
		if len(blocks) != 2 {
			t.Fatalf("%s must cover HTTP and HTTPS, got%d", endpoint, len(blocks))
		}
		for _, block := range blocks {
			if !regexp.MustCompile(`client_max_body_size\s+9m;`).Match(block[1]) {
				t.Fatalf("%s must accept8MiB original plus multipart", endpoint)
			}
			if !regexp.MustCompile(`limit_req zone=api_limit`).Match(block[1]) {
				t.Fatalf("%s lost rate limit", endpoint)
			}
		}
	}
	general := regexp.MustCompile(`(?s)location /api/\s*\{([^}]+)\}`).FindAllSubmatch(data, -1)
	if len(general) != 2 {
		t.Fatal("missing genericAPI blocks")
	}
	for _, block := range general {
		if !regexp.MustCompile(`client_max_body_size\s+2m;`).Match(block[1]) {
			t.Fatal("unrelatedAPI limit widened")
		}
	}
}
