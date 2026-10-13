package analyzer

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"github.com/hi-donwi/OPS-Toolkit/pkg/sysexec"
)

func TestEvaluateMongoHelloRequiresReplicaSet(t *testing.T) {
	healthy := evaluateMongoHello(`{"ok":1,"setName":"app","isWritablePrimary":true}`)
	if healthy[0].Severity != model.SeverityPass || healthy[0].Metadata["role"] != "primary" {
		t.Fatalf("healthy hello = %+v", healthy)
	}
	standalone := evaluateMongoHello(`{"ok":1,"isWritablePrimary":true}`)
	if standalone[0].Severity != model.SeverityWarning {
		t.Fatalf("standalone must warn, got %+v", standalone)
	}
	if got := evaluateMongoHello("not-json"); got[0].Severity != model.SeverityWarning {
		t.Fatalf("bad payload must warn, got %+v", got)
	}
}

func TestMongoUsesExplicitURIWithoutCredentialsInArguments(t *testing.T) {
	t.Setenv("OPSKIT_MONGO_URI", "mongodb://audit:synthetic-password@127.0.0.1:1/admin")
	runner := &sysexec.Fake{Outputs: map[string]string{"mongosh": `{"ok":1,"setName":"fixture","secondary":true}`}}
	engine := NewEngine(model.EnvironmentContext{}, WithRunner(runner))
	engine.checkMongo(context.Background())
	call := strings.Join(runner.Calls, " ")
	if !strings.Contains(call, "--nodb") || !strings.Contains(call, "process.env.OPSKIT_MONGO_URI") || !strings.Contains(call, "--norc") {
		t.Fatalf("probe must explicitly connect without ambient shell configuration: %s", call)
	}
	if strings.Contains(call, "synthetic-password") || strings.Contains(call, "mongodb://audit") {
		t.Fatal("credentials reached process arguments")
	}
}

func TestMongoNonServingMemberDoesNotPass(t *testing.T) {
	if got := evaluateMongoHello(`{"ok":1,"setName":"fixture"}`); got[0].Severity == model.SeverityPass {
		t.Fatalf("non-serving member must not pass: %+v", got)
	}
}

func TestRedisUnknownRoleDoesNotPass(t *testing.T) {
	if got := evaluateRedisReplication("role:sentinel\n"); got[0].Severity == model.SeverityPass {
		t.Fatalf("unknown role must not pass: %+v", got)
	}
}

func TestRedisInvalidPortNeverInvokesClient(t *testing.T) {
	t.Setenv("OPSKIT_REDIS_ADDR", "127.0.0.1:invalid")
	runner := &sysexec.Fake{}
	NewEngine(model.EnvironmentContext{}, WithRunner(runner)).checkRedis(context.Background())
	if len(runner.Calls) != 0 {
		t.Fatalf("invalid target was invoked: %v", runner.Calls)
	}
}

func TestRedisIPv6AndVerifiedTLS(t *testing.T) {
	t.Setenv("OPSKIT_REDIS_ADDR", "[::1]:6379")
	t.Setenv("OPSKIT_REDIS_TLS", "1")
	t.Setenv("OPSKIT_REDIS_CA", "/fixture/ca.pem")
	runner := &sysexec.Fake{Outputs: map[string]string{"redis-cli": "role:slave\nmaster_link_status:up\n"}}
	NewEngine(model.EnvironmentContext{}, WithRunner(runner)).checkRedis(context.Background())
	if len(runner.Calls) != 1 || !strings.Contains(runner.Calls[0], "-h ::1 -p 6379 --tls --cacert /fixture/ca.pem") {
		t.Fatalf("IPv6/TLS target was not preserved: %v", runner.Calls)
	}
	if strings.Contains(runner.Calls[0], "--insecure") {
		t.Fatal("TLS certificate validation must not be disabled")
	}
}

func TestCollectionErrorsRedactURIAndQuotedPasswords(t *testing.T) {
	f := collectionUnavailable("fixture", model.TargetHost, "database:fixture", fmt.Errorf("mongodb://audit:synthetic-password@host password='alpha beta'"))
	if strings.Contains(f.RootCause, "synthetic-password") || strings.Contains(f.RootCause, "alpha") || strings.Contains(f.RootCause, "beta") {
		t.Fatalf("error leaked credentials: %s", f.RootCause)
	}
}

func TestEvaluateRedisReplication(t *testing.T) {
	up := evaluateRedisReplication("role:slave\nmaster_link_status:up\nconnected_slaves:0\n")
	if up[0].Severity != model.SeverityPass {
		t.Fatalf("up replica = %+v", up)
	}
	down := evaluateRedisReplication("role:slave\nmaster_link_status:down\n")
	if down[0].Severity != model.SeverityCritical {
		t.Fatalf("down replica = %+v", down)
	}
}
