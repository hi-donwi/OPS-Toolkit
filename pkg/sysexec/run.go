// Package sysexec runs external diagnostic binaries (docker, kubectl, systemctl,
// ping) under a mandatory deadline.
//
// A diagnostic tool must never outlive the incident it is diagnosing: an
// unreachable API server or a wedged container runtime routinely leaves the CLI
// blocked forever. Every command therefore carries a timeout, and the caller's
// context can cancel the whole run.
package sysexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/ai"
)

// DefaultTimeout bounds a single external command invocation.
const DefaultTimeout = 10 * time.Second

// ErrNotFound reports that the binary is not present in PATH.
var ErrNotFound = errors.New("binary not found in PATH")

// Runner executes external commands. The interface exists so rule evaluators can
// be unit tested against recorded fixtures instead of a live cluster.
type Runner interface {
	Run(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error)
	Available(name string) bool
}

// Real is the production Runner backed by os/exec.
type Real struct{}

// Run executes name with args, returning stdout. The command is killed once
// timeout elapses or ctx is cancelled, whichever happens first.
func (Real) Run(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	name, args = applyTargetContext(name, args)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = commandEnv(name)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return stdout.Bytes(), fmt.Errorf("%s timed out after %s", name, timeout)
	}
	if err != nil {
		if stderr.Len() > 0 {
			return stdout.Bytes(), fmt.Errorf("%s: %w: %s", name, err, trim(stderr.Bytes()))
		}
		return stdout.Bytes(), fmt.Errorf("%s: %w", name, err)
	}

	return stdout.Bytes(), nil
}

// Available reports whether the binary is resolvable in PATH.
func (Real) Available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func trim(b []byte) string {
	const max = 240
	s := ai.SanitizeLog(string(bytes.TrimSpace(b)))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// Fake is a Runner that replays recorded output, keyed by "name arg1 arg2".
// Only the first len(key-args) arguments need to match, so tests can key on a
// command prefix rather than restating every flag.
type Fake struct {
	Outputs map[string]string
	Errors  map[string]error
	Missing map[string]bool
	Calls   []string
}

// Run returns the recorded output whose key is the longest matching prefix of
// the invocation.
func (f *Fake) Run(_ context.Context, _ time.Duration, name string, args ...string) ([]byte, error) {
	invocation := name
	for _, a := range args {
		invocation += " " + a
	}
	f.Calls = append(f.Calls, invocation)

	best := ""
	for key := range f.Outputs {
		if matchesPrefix(invocation, key) && len(key) > len(best) {
			best = key
		}
	}
	for key := range f.Errors {
		if matchesPrefix(invocation, key) && len(key) > len(best) {
			best = key
		}
	}

	if best == "" {
		return nil, fmt.Errorf("fake runner: no recorded output for %q", invocation)
	}
	if err, ok := f.Errors[best]; ok {
		return nil, err
	}
	return []byte(f.Outputs[best]), nil
}

// Available reports true unless the binary was explicitly marked missing.
func (f *Fake) Available(name string) bool { return !f.Missing[name] }

func applyTargetContext(name string, args []string) (string, []string) {
	switch name {
	case "docker":
		if ctx := strings.TrimSpace(os.Getenv("OPSKIT_DOCKER_CONTEXT")); ctx != "" && !hasFlag(args, "--context") {
			return name, append([]string{"--context", ctx}, args...)
		}
	case "kubectl":
		if ctx := strings.TrimSpace(os.Getenv("OPSKIT_KUBE_CONTEXT")); ctx != "" && !hasFlag(args, "--context") {
			return name, append([]string{"--context", ctx}, args...)
		}
	}
	return name, args
}

func hasFlag(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag || strings.HasPrefix(arg, flag+"=") {
			return true
		}
	}
	return false
}

func commandEnv(name string) []string {
	env := os.Environ()
	switch name {
	case "redis-cli":
		if auth := os.Getenv("OPSKIT_REDIS_PASSWORD"); auth != "" {
			filtered := make([]string, 0, len(env)+1)
			for _, entry := range env {
				if !strings.HasPrefix(entry, "REDISCLI_AUTH=") {
					filtered = append(filtered, entry)
				}
			}
			env = filtered
			env = append(env, "REDISCLI_AUTH="+auth)
		}
	}
	return env
}

func matchesPrefix(invocation, key string) bool {
	if invocation == key {
		return true
	}
	return len(invocation) > len(key) && invocation[:len(key)] == key && invocation[len(key)] == ' '
}
