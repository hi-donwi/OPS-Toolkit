# Roadmap

What has been built, roughly in the order it was built.

---

## 1. Architecture and CLI foundation
- [x] Write the engineering plan (`PLANNING.md`).
- [x] Write the architecture spec and rule catalog (`SPEC.md`).
- [x] Initialize Go module and Cobra CLI framework with subcommands (`diag`, `audit`, `version`).
- [x] Implement core data models (`pkg/model`) and runtime environment detector (`pkg/detector`).
- [x] Implement terminal output formatter with high-contrast ANSI colors and JSON serializer (`pkg/report`).
- [x] Cross-compilation automation via `Makefile` for Linux (`amd64` and `arm64`).

---

## 2. Docker and Swarm inspection
- [x] Docker exit code forensic triage (`137` OOMKilled, `139` Segfault, `1` runtime errors).
- [x] Container healthcheck status inspection (`unhealthy` container extraction).
- [x] Docker Swarm service replica convergence auditing (`Running < Desired`).
- [x] Docker Swarm per-task failure forensics and placement rejection analysis.
- [x] Docker Swarm node state monitoring (`Down`, `Drain`, `Active`).

---

## 3. Security and certificate auditing
- [x] Real X.509 SSL/TLS certificate parser for both local certificate files and remote endpoints (`host:port`).
- [x] Sensitive file permission auditing (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`).
- [x] Container security auditing (flags `--privileged`, root UID execution, `/var/run/docker.sock` host mounts).
- [x] SSH server configuration auditing (`PermitRootLogin`, `PasswordAuthentication`).
- [x] Open listening port scanner for unauthenticated database and control-plane exposures.

---

## 4. Kubernetes diagnostics
- [x] Pod crash triage (`CrashLoopBackOff`, with the `lastState` termination reason as evidence).
- [x] Pod OOMKilled detection, including while the container is backing off.
- [x] Pod `Pending` scheduler analysis, excluding pods the kubelet is actively creating.
- [x] Pod `ImagePullBackOff` / `ErrImagePull` and missing pull-secret inspection.
- [x] Pod `Evicted`, `CreateContainerConfigError`, and restart-churn detection.
- [x] Orphan Service detection, separated from services whose pods all fail readiness.
- [x] Ingress backend and TLS secret reference validation (`K8S-ING-001`, `K8S-ING-002`).
- [x] CoreDNS availability check — fully down, partially degraded, or healthy.
- [x] PersistentVolumeClaim `Pending` and `Lost` diagnostics.
- [x] Node `Ready`, `MemoryPressure`, `DiskPressure`, `PIDPressure` condition monitoring.
- [x] API-server reachability reported explicitly instead of silently producing no findings.
- [x] Cluster state read via `kubectl -o json` into typed structs, replacing a `{len .subsets}`
      jsonpath query that kubectl rejects (`unrecognized identifier len`).

---

## 5. Linux host and kernel diagnostics
- [x] Root filesystem disk usage (>80% Warning, >90% Critical), computed the way `df(1)` does
      so the root-reserved block pool is not counted as free headroom.
- [x] Inode exhaustion detector (>80% Warning, >90% Critical).
- [x] Systemd failed unit discovery with per-unit journal guidance.
- [x] Upstream DNS resolution latency benchmark, with an `OPSKIT_DNS_PROBE` override for
      air-gapped and split-horizon estates.
- [x] `/proc/loadavg` saturation analysis scaled by CPU core count (`HOST-CPU-001`).
- [x] `/proc/meminfo` memory and swap pressure, measured against `MemAvailable` (`HOST-MEM-002/003`).
- [x] Kernel `dmesg` scanner for OOM-killer invocations, grouped per victim process (`HOST-MEM-001`).
- [x] `/proc/net/tcp` and `/proc/net/tcp6` socket table parser for `TIME_WAIT` exhaustion (`HOST-NET-001`).
- [x] Read-only remounted filesystem detection, excluding pseudo-filesystems (`HOST-ROF-001`).
- [x] Zombie process accumulation detection (`HOST-ZOM-001`).

---

## 6. Operations, remediation, telemetry
- [x] Automated and interactive remediation engine (`opskit fix`) with safe `--dry-run` default.
- [x] CI/CD verification quality gate (`opskit verify`) with configurable failure threshold (`--fail-on`).
- [x] Native Prometheus metrics HTTP exporter (`opskit export-metrics`).
- [x] Background continuous daemon watcher with webhook alerting (`opskit daemon`).
- [x] Interactive live cluster/host dashboard powered by `charmbracelet/bubbletea` (`opskit tui`).
- [x] AI Incident Copilot runbook generator with sensitive data masking (`opskit explain`).
- [x] Custom YAML-based rule engine (`rules.d/*.yaml`).
- [x] Production packaging manifests (Kubernetes DaemonSet, Docker Swarm, Systemd, install.sh).
- [x] Network connectivity, DNS benchmark, and Path MTU drop inspector (`opskit net`).
- [x] Automated shell autocompletion installer (`opskit completion install`).

---

## 7. Correctness, safety, test coverage

**Defects fixed**
- [x] Docker `ps` parsing indexed past the end of a short row, panicking the whole run.
- [x] Orphan-service detection used a `{len .subsets}` jsonpath expression kubectl rejects,
      so the check never executed.
- [x] Custom rule conditions were ORed, so a rule naming a file *and* a pattern fired on the
      file's mere existence; `file_not_contains` was declared but never evaluated.
- [x] IPv6 nameservers were built as `addr:53` without brackets, making every IPv6 resolver
      check fail to dial.
- [x] MTU probes reported a critical VXLAN fault for any target that filters ICMP; a baseline
      reachability probe now gates the verdict.
- [x] `verify --fail-on` silently fell back to `critical` on an unrecognised value.
- [x] `fix <target>` silently fell back to scanning everything on an unrecognised target.
- [x] `opskit net` reported a hardcoded `240ms` duration instead of the measured one.
- [x] Console findings were numbered by their index in the full list, so the visible list
      skipped numbers wherever a `PASS` row was hidden.
- [x] The daemon's alert-suppression map grew without bound for the process lifetime.
- [x] The exporter returned `ErrServerClosed` on `SIGTERM`, so every clean shutdown looked
      like a crash to systemd and Kubernetes.
- [x] `go.mod` required Go 1.26.5 while CI built on 1.22/1.23 and the Dockerfile on 1.22.
- [x] `README` claimed Apache 2.0 with no `LICENSE` file committed.

**Safety and robustness**
- [x] Every external command runs under a deadline through `pkg/sysexec`; a global `--timeout`
      and `SIGINT`/`SIGTERM` cancel a run instead of hanging on an unreachable API server.
- [x] `opskit fix` grades each command `LOW`/`MEDIUM`/`HIGH`, supports `--max-risk` and
      `--only`, refuses to apply anything from a non-terminal stdin without `-y`, and exits
      non-zero when a fix fails.
- [x] The TUI stages a quick-fix for `[y]` confirmation rather than executing on one keystroke.
- [x] Prometheus label values are escaped and duplicate series collapsed, so a quote in a
      resource name can no longer corrupt an entire scrape.
- [x] Explicit read, write, and idle timeouts on the exporter's HTTP server.

**Verification**
- [x] Rule engine split into thin collectors and pure evaluators, making every rule testable
      against captured fixtures without a live cluster.
- [x] Test suite grown from 11 to 145 tests, passing under `-race`.
- [x] CI extended with `gofmt`, `go vet`, `go mod tidy`, `-race`, static cross-compilation,
      and `govulncheck`.


