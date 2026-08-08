package oauthprovider

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestOAuthProviderPublicTypesCompile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "run", "-mod=readonly", "./oauth-provider-public-types")
	command.Dir = "../../testdata/typecheck-smoke/consumers"
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("OAuth public-types external consumer timed out: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("OAuth public-types external consumer failed: %v\n%s", err, output)
	}
	if got, want := strings.TrimSpace(string(output)), "ok:oauth-provider-public-types"; got != want {
		t.Fatalf("OAuth public-types external consumer output=%q, want %q", got, want)
	}
}
