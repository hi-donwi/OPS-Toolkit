package sysexec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRealRunCapturesStdout(t *testing.T) {
	out, err := Real{}.Run(context.Background(), 5*time.Second, "echo", "hello")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("stdout = %q, want %q", out, "hello")
	}
}

func TestRealRunEnforcesTimeout(t *testing.T) {
	// A diagnostic tool must not outlive the incident. An unreachable API
	// server otherwise blocks the run indefinitely.
	start := time.Now()
	_, err := Real{}.Run(context.Background(), 200*time.Millisecond, "sleep", "10")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %v, want a timeout message", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("command ran for %v; the timeout did not kill it", elapsed)
	}
}

func TestRealRunRespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := Real{}.Run(ctx, 30*time.Second, "sleep", "10")

	if err == nil {
		t.Fatal("expected an error when the context is cancelled")
	}
	if time.Since(start) > 3*time.Second {
		t.Error("cancellation did not interrupt the command")
	}
}

func TestRealRunIncludesStderrInError(t *testing.T) {
	_, err := Real{}.Run(context.Background(), 5*time.Second, "sh", "-c", "echo boom >&2; exit 3")
	if err == nil {
		t.Fatal("expected an error for a non-zero exit")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v, want it to surface stderr", err)
	}
}

func TestRealAvailable(t *testing.T) {
	if !(Real{}).Available("sh") {
		t.Error("sh should be available")
	}
	if (Real{}).Available("opskit-definitely-not-a-real-binary") {
		t.Fatal("nonexistent binary reported as available")
	}
}

func TestFakeMatchesLongestPrefix(t *testing.T) {
	fake := &Fake{Outputs: map[string]string{
		"docker ps":    "short",
		"docker ps -a": "long",
	}}

	out, err := fake.Run(context.Background(), 0, "docker", "ps", "-a", "--format", "{{.ID}}")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(out) != "long" {
		t.Errorf("output = %q, want the longest matching prefix %q", out, "long")
	}

	out, _ = fake.Run(context.Background(), 0, "docker", "ps")
	if string(out) != "short" {
		t.Errorf("output = %q, want %q", out, "short")
	}
}

func TestFakeDoesNotMatchPartialWord(t *testing.T) {
	// "docker ps" must not match "docker psx"; prefix matching has to respect
	// argument boundaries.
	fake := &Fake{Outputs: map[string]string{"docker ps": "x"}}

	if _, err := fake.Run(context.Background(), 0, "docker", "psx"); err == nil {
		t.Error("expected no match for a different subcommand")
	}
}

func TestFakeReturnsRecordedErrors(t *testing.T) {
	sentinel := errors.New("connection refused")
	fake := &Fake{Errors: map[string]error{"kubectl get": sentinel}}

	_, err := fake.Run(context.Background(), 0, "kubectl", "get", "pods")
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the recorded error", err)
	}
}

func TestFakeRecordsCalls(t *testing.T) {
	fake := &Fake{Outputs: map[string]string{"echo": "ok"}}
	_, _ = fake.Run(context.Background(), 0, "echo", "one")
	_, _ = fake.Run(context.Background(), 0, "echo", "two")

	if len(fake.Calls) != 2 {
		t.Fatalf("recorded %d calls, want 2", len(fake.Calls))
	}
	if fake.Calls[0] != "echo one" {
		t.Errorf("Calls[0] = %q", fake.Calls[0])
	}
}
