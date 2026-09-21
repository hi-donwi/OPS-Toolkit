# opskit — OPS Toolkit

[![CI](https://github.com/hi-donwi/OPS-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/hi-donwi/OPS-Toolkit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey)]()

A command-line diagnostic tool for Linux hosts, Docker, Docker Swarm, and
Kubernetes.

When something breaks at 3am you usually end up running the same twenty
commands — `dmesg`, `journalctl -u`, `docker inspect`, `docker service ps`,
`kubectl describe`, `kubectl logs --previous`, `df -ih`, `ss -tan` — and piecing
the story together by hand. `opskit` runs those checks for you and reports what
it found: the symptom, the mechanism behind it, the evidence, and what to do
about it.

It ships as a single static binary with no runtime dependencies, so you can
`scp` it onto a sick host and run it there.

```
$ opskit diag
Summary:  2 CRITICAL, 1 WARNING, 14 PASS

[CRITICAL] #1: Kernel OOM-Killer Terminated Process: node (process:node)
  Rule ID:     HOST-MEM-001
  Symptom:     The kernel killed "node" 3 time(s) to reclaim memory.
  Root Cause:  Total memory demand exceeded physical RAM plus swap, so the
               kernel selected the highest-scoring process and killed it. The
               victim is usually the biggest consumer, not necessarily the culprit.
  Evidence:    [Mon Sep 1 10:22:14 2026] Out of memory: Killed process 21534 (node)
```

## What it checks

**Linux host.** Kernel OOM-killer kills (parsed out of `dmesg` and grouped by
victim process), memory and swap pressure, CPU run queue against core count,
disk and inode exhaustion, filesystems the kernel has remounted read-only,
zombie process build-up, `TIME_WAIT` socket exhaustion, failed systemd units,
and DNS resolution latency.

**Docker.** Exit-code forensics — 137 is an OOM kill, 139 a segfault, 127 a
missing entrypoint — plus containers stuck in a restart loop behind a restart
policy, failing healthchecks, and how much of the disk Docker itself is using.

**Docker Swarm.** Services that have not converged to their desired replica
count, with the per-task error classified into an actual cause (not enough
memory, not enough CPU, unsatisfiable placement constraint, port conflict,
missing image). Also unreachable and drained nodes, and overlay VXLAN MTU drops.

**Kubernetes.** `CrashLoopBackOff` reported together with the termination reason
that explains it, `OOMKilled`, `ImagePullBackOff`, pods that were never
scheduled, evicted pods, missing ConfigMap/Secret references, restart churn,
services routing to nothing, ingress rules pointing at services or TLS secrets
that do not exist, CoreDNS health, unbound volume claims, and node conditions.

**Security.** File permissions graded per file rather than by one blanket rule,
SSH hardening, unauthenticated service ports, privileged containers, containers
running as root, sensitive host paths mounted into containers, Pod Security
Standards violations, RBAC wildcard grants, and certificate expiry for both
local files and remote endpoints.

Output goes to the terminal, to JSON for pipelines, or to a Markdown incident
report. You can add your own checks as YAML without rebuilding.

Every rule, its threshold, and where it reads its data from is listed in
[SPEC.md](SPEC.md#4-rule-catalog-specification).

## How it works

```
detect environment → collect → evaluate rules → report
```

The detector works out what is actually running on the box — systemd, a Docker
daemon, a Swarm node, a reachable cluster — and only the relevant checks run.
Collection shells out to the `kubectl` and `docker` you already have rather than
embedding client libraries; see [PLANNING.md](PLANNING.md#21-why-no-client-go-and-no-docker-sdk)
for why.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/hi-donwi/OPS-Toolkit/main/install.sh | bash
```

The installer picks the binary for your platform and checks its SHA-256 against
the release checksums before installing anything. It will not install a binary
it cannot verify.

| Variable | Default | |
|---|---|---|
| `OPSKIT_VERSION` | `latest` | Install a specific tag. A tag with no matching build is an error, not a quiet fallback. |
| `INSTALL_DIR` | `/usr/local/bin` | Where to put it. |
| `OPSKIT_SKIP_CHECKSUM` | unset | Set to `1` to skip verification. Don't. |

### From source

Needs Go 1.25 or later and nothing else.

```bash
make build          # ./bin/opskit
make build-linux    # static linux/amd64 and linux/arm64
```

## Commands

### Diagnose

```bash
opskit diag                           # everything it detects
opskit diag --json                    # for a pipeline
opskit diag -o incident.md            # Markdown incident report

opskit diag host                      # memory, CPU, disk, mounts, sockets, systemd, DNS, OOM kills
opskit diag docker                    # exit codes, restart loops, healthchecks, disk footprint
opskit diag swarm                     # nodes, replica convergence, task placement
opskit diag k8s                       # all namespaces
opskit diag k8s -n production         # one namespace
```

### Global flags

| Flag | Default | |
|---|---|---|
| `--timeout` | `2m` | Deadline for the whole run. Each external command is bounded separately too, so one unreachable API server can't hang the CLI. `0` turns the overall deadline off. |
| `--json` | off | Machine-readable output. |
| `-o`, `--output` | — | Write to a file; `.json` and `.md` pick the format. |
| `--no-color` | off | No ANSI escapes. Also honours `NO_COLOR`, and turns itself off when output isn't a terminal. |

Ctrl-C and `SIGTERM` cancel a run in progress instead of leaving child processes
behind.

### Audit

```bash
opskit audit sec                      # host, container, and cluster posture
opskit audit certs                    # certificates on local disk
opskit audit certs example.com:443    # a remote endpoint
```

### Fix things

`--dry-run` is on by default, so `opskit fix` on its own only shows you what it
would do. Each command is graded first: `LOW` is additive, `MEDIUM` restarts or
reconfigures something, `HIGH` deletes data or stops a service.

```bash
opskit fix                            # preview, with risk grades
opskit fix --dry-run=false            # apply, after one confirmation
opskit fix --dry-run=false --max-risk medium   # nothing that deletes or stops
opskit fix --only HOST-DSK-001 --dry-run=false # just this one
opskit fix docker -y                  # no prompt, for cron or CI
```

It refuses to apply anything when stdin isn't a terminal unless you pass `-y`,
so a piped invocation can't be approved by stray input. Exits non-zero if a fix
fails.

### Gate a pipeline

```bash
opskit verify --fail-on critical
opskit verify --fail-on warning -n production
```

| Exit | |
|---|---|
| `0` | Nothing at or above the threshold |
| `1` | Threshold breached |
| `2` | The run itself failed — cancelled, timed out, or errored |

An unrecognised `--fail-on` value is rejected rather than quietly treated as
`critical`.

### Export metrics

```bash
opskit export-metrics --port 9876 --interval 30s
```

| Series | Type | |
|---|---|---|
| `opskit_up` | gauge | `1` once an evaluation has completed, `0` while starting |
| `opskit_findings_total{target,severity}` | gauge | Counts per target and severity |
| `opskit_severity_count{severity}` | gauge | Flat totals, cheaper to alert on |
| `opskit_finding_active{id,severity,target,resource,namespace}` | gauge | One series per open finding, so an alert can name the rule |
| `opskit_health_score` | gauge | `100 - 30×critical - 10×warning`, floored at 0 |
| `opskit_last_evaluation_timestamp_seconds` | gauge | When the last run finished |
| `opskit_evaluation_errors_total` | counter | Runs that failed |

`/healthz` is a plain liveness probe. `PASS` findings are deliberately left out
of `opskit_finding_active` to keep cardinality down.

### Watch continuously

```bash
opskit daemon --interval 60s --alert-on critical   --webhook-url "https://hooks.slack.com/services/XXX"
```

A finding stays suppressed for 30 minutes after it alerts, so a persistent fault
doesn't page you every cycle.

### Network checks

```bash
opskit net                            # DNS benchmark, TCP latency, path MTU
opskit net 10.0.0.1
opskit net dns example.com
opskit net mtu 10.0.0.1
```

MTU probing sends a small ping first. Most cloud endpoints drop ICMP entirely,
and without that baseline every one of them looks like a broken VXLAN overlay.

### Terminal dashboard

```bash
opskit tui
```

Findings on the left, detail on the right. `↑`/`↓` to move, `r` to rescan, `e`
for a runbook, `f` to stage a fix — then `y` to actually run it, or `n` to back
out. A fix is never one keystroke away.

### Explain a finding

```bash
opskit explain K8S-POD-002
```

Writes an incident runbook. Uses a local Ollama if one is reachable
(`OLLAMA_HOST`, `SRE_AI_MODEL`), otherwise falls back to built-in templates.
Passwords, tokens, and private keys are stripped before anything is sent.

### Shell completion

```bash
opskit completion install             # zsh, bash, or fish
```

### Your own rules

Drop YAML into `rules.d/` or `~/.opskit/rules.d/`. No rebuild. One file can hold
several rules separated by `---`.

```yaml
id: "CUSTOM-APP-PORT"
title: "In-Memory Database Port Exposed Without TLS"
target: "SECURITY"          # HOST | DOCKER | SWARM | KUBERNETES | SECURITY
severity: "CRITICAL"        # CRITICAL | WARNING | INFO | PASS
category: "Enterprise Policy"
resource: "port:6379"
symptom: "Port 6379 accepts connections without TLS"
root_cause: "The in-memory database is reachable unencrypted"
remedy_steps:
  - "Enforce TLS termination in front of the service"
quick_fix_cmd: "systemctl stop redis-server"
conditions:
  port_listening: 6379
```

**Every condition you list has to hold** — they're ANDed, not ORed. A rule that
names a file and a pattern is describing one situation ("this file contains this
string"), not two separate alarms.

| Condition | Fires when |
|---|---|
| `file_exists` | The path exists |
| `file_contains` | `file_exists` matches this regex |
| `file_not_contains` | `file_exists` does *not* match this regex |
| `port_listening` | The TCP port accepts a local connection |
| `env_not_set` | The variable is unset or empty |
| `env_equals` | `NAME=value` matches exactly |
| `command_exists` | The binary is on `PATH` |

Rules are validated when loaded. Missing `id`, missing `title`, no conditions, a
bad regex, an unknown severity, or a content match with no `file_exists` gets
skipped and reported — a typo can't silently switch a check off.

```yaml
# Only fires if sshd is installed AND hasn't been hardened.
id: "CORP-SSH-HARDENING"
title: "sshd Does Not Enforce Key-Only Authentication"
target: "SECURITY"
severity: "WARNING"
resource: "file:/etc/ssh/sshd_config"
symptom: "PasswordAuthentication is not explicitly disabled"
root_cause: "Policy requires public-key authentication only"
conditions:
  file_exists: "/etc/ssh/sshd_config"
  file_not_contains: "^PasswordAuthentication\\s+no"
```

## Deploying it

Everything under `deploy/` is ready to apply.

| | |
|---|---|
| [`deploy/helm/opskit`](deploy/helm/opskit) | Helm v3 chart, with a Prometheus Operator `ServiceMonitor` |
| [`deploy/kubernetes/daemonset.yaml`](deploy/kubernetes/daemonset.yaml) | Plain DaemonSet running the exporter on every node, with RBAC |
| [`deploy/docker-swarm/docker-compose.yml`](deploy/docker-swarm/docker-compose.yml) | Global Swarm service |
| [`deploy/systemd/opskit.service`](deploy/systemd/opskit.service) | Runs `opskit daemon` on a plain VM |
| [`deploy/grafana/opskit-dashboard.json`](deploy/grafana/opskit-dashboard.json) | Health score and finding breakdown |
| [`action.yml`](action.yml) | GitHub Action wrapping `opskit verify` |

The container deployments set `OPSKIT_PROC_ROOT=/host/proc` and bind-mount the
node's procfs. Without that the host checks would measure the container instead
of the machine, which is not what you want from a node agent.

## Sample output

Most severe first. `PASS` checks are counted but not listed, so the incident is
at the top of the screen rather than page three.

```text
================================================================================
               OPS TOOLKIT (OPSKIT) DIAGNOSTIC & HEALTH REPORT
================================================================================
Host OS:      Ubuntu 22.04 LTS (5.15.0-89-generic, amd64)
Deployments:  Host/Systemd, Docker, Kubernetes
Duration:     184ms | Timestamp: 2026-09-01 17:58:00 UTC
Summary:      2 CRITICAL, 1 WARNING, 14 PASS
--------------------------------------------------------------------------------

[CRITICAL] #1: Pod Terminated (OOMKilled): prod/api-gateway-7d84bc86 (pod/api-gateway-7d84bc86)
  Rule ID:     K8S-POD-002
  Category:    Resource Saturation
  Symptom:     Container "api" was killed with exit code 137 after exceeding its memory limit.
  Root Cause:  Container memory usage surpassed spec.resources.limits.memory, so the kernel
               cgroup OOM killer terminated it.
  Remediation:
    1. Measure the real working set before raising the limit: kubectl top pod api-gateway-7d84bc86 -n prod
    2. Raise resources.limits.memory in the workload manifest to cover peak usage plus headroom
    3. For JVM workloads set -XX:MaxRAMPercentage so the heap respects the cgroup limit

[CRITICAL] #2: Kernel OOM-Killer Terminated Process: node (process:node)
  Rule ID:     HOST-MEM-001
  Category:    Kernel & Memory
  Symptom:     The kernel killed "node" 3 time(s) to reclaim memory.
  Root Cause:  Total memory demand exceeded physical RAM plus swap, so the kernel selected the
               highest-scoring process and killed it. The victim is usually the biggest consumer,
               not necessarily the culprit.
  Evidence:    [Mon Sep  1 10:22:14 2026] Out of memory: Killed process 21534 (node) total-vm:4194304kB
  Remediation:
    1. Correlate the kill timestamp with your application metrics to find the allocation spike
    2. Cap the service so it fails predictably: systemctl set-property node MemoryMax=<limit>
    3. Add memory limits to every container on this host, and size the instance for peak, not average

[WARNING] #3: Root Disk Usage Approaching Capacity (filesystem:/)
  Rule ID:     HOST-DSK-001
  Category:    Storage Saturation
  Symptom:     Disk usage on / is at 88.4% (Total: 460.4 GiB, Used: 406.9 GiB, Available: 53.5 GiB)
  Root Cause:  Disk capacity approaching threshold (>80%).
  Remediation:
    1. Plan storage expansion, archive old logs, or prune unused container images.
  Quick Fix:   docker system prune -f

[OK] 14 checks passed successfully.
================================================================================
```

## Status

Working and useful, with one honest caveat.

**Verified.** All rules have unit tests — 154 of them, run under `-race` on Go
1.26 and 1.27. The Docker, Swarm, and Kubernetes rules are tested against
captured fixtures (real `kubectl -o json` payloads, real `docker` CLI output),
which proves the parsing and the scoring. Every command has been exercised
end to end against a real macOS host, a live TLS endpoint, and an unreachable
cluster context.

**Not verified.** The Linux-only host rules — the ones reading `/proc/meminfo`,
`/proc/loadavg`, `/proc/mounts`, `/proc/<pid>/stat`, `/proc/net/tcp`, and
`dmesg` — have never run on a Linux machine. Their logic is fixture-tested, but
"the fixtures match a real kernel's output" is an assumption, not a
measurement. If you run this on Linux and something looks wrong, that is the
first place to look, and an issue would be welcome.

Everything else is honest about its own limits at runtime too: if a target
ignores ICMP the MTU check says so rather than inventing a fault, and if the
kubeconfig points nowhere the report says the API server is unreachable rather
than quietly finding nothing.

## Working on it

```bash
make build          # ./bin/opskit
make build-linux    # static binaries for linux/amd64 and linux/arm64
make test
make licenses       # refresh THIRD_PARTY_LICENSES.md after a dependency change
go vet ./...        # keep this clean
```

Each rule is two pieces: a **collector**, which is the only part allowed to touch
the machine, and an **evaluator**, which is a plain function over data the
collector already gathered. Collectors go through `pkg/sysexec`, which puts a
deadline on every external command.

That split is the whole reason the Kubernetes and Swarm rules are testable — the
evaluators run against captured fixtures, and `sysexec.Fake` replays recorded
command output for tests that exercise the engine end to end. If you add a rule,
keep it in that shape; one that calls `exec.Command` from inside its scoring
logic can't be tested.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the rest.

## More detail

- [SPEC.md](SPEC.md) — every rule, threshold, and data source. The rule IDs there
  are authoritative.
- [PLANNING.md](PLANNING.md) — architecture and the reasoning behind the awkward
  decisions: why there's no `client-go`, why cluster state is decoded from JSON
  rather than jsonpath, why the collector/evaluator split exists.
- [ROADMAP.md](ROADMAP.md) — what's been built.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to add a rule.
- [SECURITY.md](SECURITY.md) — what the tool touches on your machine, and how to
  report a vulnerability.

## Licence

Apache 2.0 — see [LICENSE](LICENSE).

Apache rather than MIT for two practical reasons: it carries an explicit patent
grant, which matters for infrastructure software that companies deploy, and it
is what the tools this sits beside already use (kubectl, Helm, Prometheus,
containerd). Matching them removes a review step for anyone bringing it inside
an organisation.

The published binaries are statically linked, so they embed their dependencies.
Every one is permissive (MIT, BSD-3-Clause, or Apache-2.0); the full list and
notices are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md), regenerated
by `make licenses` from the modules actually linked into the release builds. CI
fails if it drifts.
