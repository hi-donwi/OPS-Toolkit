# Contributing

Issues and pull requests are welcome. This is a spare-time project, so I may be
slow, but I read everything.

## Before you open a PR

```bash
gofmt -l .          # must print nothing
go vet ./...        # must be clean
go test -race ./... # must pass
```

CI runs the same, plus `go mod tidy` being a no-op, a static cross-compile, a
`govulncheck` scan, and a check that `THIRD_PARTY_LICENSES.md` is current.

If you add or bump a dependency, run `make licenses` and commit the result. The
binaries are statically linked, so every dependency ships inside them and its
attribution has to travel too.

## Adding a rule

This is the most likely reason you are here, so it is worth spelling out.

A rule is two functions. Keep them separate — this is the thing to get right.

```go
// Collector: touches the machine, does no scoring.
func (e *Engine) checkMemory() []model.Finding {
    content, err := e.readProc("meminfo")
    if err != nil {
        return nil // a check we cannot run is skipped, never reported as a pass
    }
    return evaluateMemory(parseMeminfo(content))
}

// Evaluator: pure, and therefore directly testable.
func evaluateMemory(stats meminfoStats) []model.Finding { ... }
```

The evaluator does no I/O. That is what lets the Kubernetes and Swarm rules be
tested against captured fixtures instead of a live cluster, and it is why the
test suite runs on a laptop. A rule that calls `exec.Command` from inside its
scoring logic cannot be tested and will not be merged.

Shell out through `pkg/sysexec`, never `os/exec` directly, so the command gets a
deadline. Read procfs through `e.readProc`, so tests can point it at a fixture
tree.

Steps:

1. Give it an ID and add it to [SPEC.md](SPEC.md) section 4. That table is
   authoritative for rule IDs — code that disagrees with it gets changed, not the
   other way round.
2. Put the code in the file for its target: `host_resources.go`,
   `host_kernel.go`, `host_services.go`, `docker.go`, `swarm.go`,
   `kubernetes_workloads.go`, `kubernetes_network.go`, `kubernetes_cluster.go`,
   or `security.go`.
3. Write the evaluator test first, against a fixture. Capture the fixture from a
   real system — a trimmed `kubectl get pods -o json`, the relevant lines of a
   real `/proc/meminfo` — rather than inventing one. Fixtures that do not match
   reality prove nothing.
4. Cover the healthy case too. A rule that only has a failing test will
   eventually fire on a healthy system and nobody will notice.

## Writing a good finding

A finding is read by someone who is stressed and wants to stop reading. Every
field earns its place:

- **Symptom** — what was observed, with the number. "Disk usage on / is at
  94.2%", not "disk usage is high".
- **RootCause** — the mechanism, not a restatement of the symptom. "The kernel
  remounted the filesystem read-only after an I/O error" tells someone what to
  do next; "the filesystem is read-only" does not.
- **RemedySteps** — ordered, and the first one should usually be *diagnose
  further*, not *change something*. Give the exact command.
- **QuickFixCmd** — only when it is genuinely safe and genuinely fixes the
  finding. Leave it empty rather than offering something destructive; it feeds
  `opskit fix`, which will run it.

Severity: `CRITICAL` means something is broken or about to be. `WARNING` means
it will break if nothing changes. `INFO` is context. Grade-inflating a rule
trains people to ignore all of them.

## Custom rules instead

If your check is site-specific, you may not need Go at all — `rules.d/*.yaml`
handles file, port, environment, and command checks without a rebuild. See the
README.

## Commit messages

Explain why, not what; the diff already shows what. If you fixed a bug, say what
the broken behaviour was, so the next person understands what the change is
protecting against.

## Licence

Contributions are under Apache-2.0, per section 5 of the licence. There is no
CLA.
