# Engineering notes: `opskit` (OPS Toolkit)

> Module: `github.com/hi-donwi/OPS-Toolkit`
> Last reconciled with the code: 2026-09-01

These are the design notes — what the tool is for, what it's built on, and why
the awkward decisions were made the way they were. The rule catalog lives in
[SPEC.md](SPEC.md); user-facing instructions live in [README.md](README.md).

---

## 1. What this is, and why

Incidents don't stay inside one layer. A slow API turns out to be a node under
memory pressure; a 503 turns out to be a service whose selector stopped matching
anything; a deploy that "worked yesterday" turns out to be a VXLAN overlay
dropping any packet over 1422 bytes.

Working that out means running a lot of commands — `dmesg`, `journalctl -u`,
`docker inspect`, `docker service ps --no-trunc`, `kubectl describe`,
`kubectl logs --previous`, `ss -tan`, `df -ih` — and holding the results in your
head while you correlate them. That's fine when you do it often. It's error-prone
at 3am, and it's slow for whoever is on call and hasn't seen this system before.

`opskit` runs those checks and reports what it found. Five things shape the design:

1. **One static binary, no runtime.** No Python, no Node, no libc assumptions.
   You can copy it onto a host that's already unhappy and run it.
2. **It figures out the environment itself.** systemd, Docker, Swarm, a reachable
   cluster — it checks what's there and skips the rest.
3. **It explains, rather than dumps.** Exit code 137 isn't reported as "137"; it's
   reported as a cgroup OOM kill, with the memory limit that caused it and what
   to do about it.
4. **Security is part of the same pass.** Permissions, exposed ports, privileged
   containers, RBAC wildcards, certificate expiry — these break systems the same
   way resource exhaustion does.
5. **Every finding comes with a next step.** Ordered remediation, and where it's
   safe, a command you can run. Dry-run first, always.

---

## 2. What it's built on, and why

| Component | Selected Technology | SRE Engineering Rationale |
|---|---|---|
| **Core Language** | **Go 1.25+** | De-facto cloud-native standard (`kubectl`, `docker`, `helm`, `trivy`, `k9s`, `crictl`). Produces static binaries (`CGO_ENABLED=0`) with no dynamic library dependency on any target platform. |
| **CLI Framework** | `github.com/spf13/cobra` | Subcommands, POSIX flags, and generated shell autocompletion. |
| **Kubernetes Access** | The operator's own `kubectl`, read as `-o json` | See below. |
| **Docker & Swarm Access** | The operator's own `docker` CLI, plus a raw HTTP probe of `/var/run/docker.sock` for detection | See below. |
| **OS & Kernel Telemetry** | `procfs`, `syscall.Statfs`, `dmesg`, `systemctl` | Direct kernel probing for memory, load, mounts, socket tables, and process state. |
| **Custom Rules** | `gopkg.in/yaml.v3` | User-authored rules loaded from `rules.d/` at runtime, with no rebuild. |
| **Terminal UI** | `charmbracelet/bubbletea` + `lipgloss` | Full-screen interactive dashboard (`opskit tui`). |
| **Reporting** | Native ANSI, `encoding/json`, hand-rolled Markdown | Severity-coloured console output, machine-readable JSON, and Markdown incident reports. |

### 2.1. Why no client-go and no Docker SDK

Both were considered and deliberately rejected.

- **Binary size and dependency surface.** `k8s.io/client-go` pulls in a very
  large transitive tree. The product promise is a single static binary an
  engineer can `scp` onto a broken host; that promise outranks type-safe API
  access.
- **Version skew.** A vendored client-go is pinned to the API versions it was
  built against. Shelling out to whatever `kubectl` the operator already has
  means opskit inherits a client that is, by definition, compatible with the
  cluster the operator is already administering.
- **Credentials.** Delegating to `kubectl` inherits the full kubeconfig stack —
  exec credential plugins, cloud IAM helpers, contexts, proxies — without
  reimplementing any of it.

The cost is that cluster state arrives as text. That cost is contained by
decoding `kubectl get <kind> -o json` into narrow typed structs rather than
parsing jsonpath templates or scraping table output. See §8.1.

`viper` is not used: opskit has no configuration file. Behaviour comes from
flags, a small number of environment overrides (`OPSKIT_PROC_ROOT`,
`OPSKIT_DNS_PROBE`, `OLLAMA_HOST`, `SRE_AI_MODEL`), and `rules.d/*.yaml`.

---

## 3. What it runs on

```
                                  ┌────────────────────────┐
                                  │   opskit CLI Engine    │
                                  └───────────┬────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
         ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
         │  Linux Host / VM    │   │   Docker & Swarm    │   │     Kubernetes      │
         └──────────┬──────────┘   └──────────┬──────────┘   └──────────┬──────────┘
                    │                         │                         │
     ┌──────────────┴──────────┐   ┌──────────┴──────────┐   ┌──────────┴──────────┐
     │ • Ubuntu / Debian       │   │ • Standalone Engine │   │ • Managed (EKS/GKE) │
     │ • RHEL/Rocky/Alma/CentOS│   │ • Docker Compose    │   │ • K3s / RKE2 / Edge │
     │ • Alpine (musl libc)    │   │ • Swarm Managers    │   │ • In-Cluster / Pod  │
     │ • Amazon Linux 2 / 2023 │   │ • Swarm Workers     │   │ • Multi-Namespace   │
     │ • Arch / openSUSE       │   │ • Overlay (VXLAN)   │   │ • Ingress & CNI     │
     └─────────────────────────┘   └─────────────────────┘   └─────────────────────┘
```

### 3.1. Supported Linux Distributions
- **Debian Family**: Ubuntu (18.04, 20.04, 22.04, 24.04 LTS), Debian 10/11/12.
- **RHEL Family**: Red Hat Enterprise Linux, Rocky Linux, AlmaLinux, CentOS Stream, Fedora.
- **Lightweight & Edge**: Alpine Linux (musl libc static binary, perfect for micro-containers and edge devices).
- **Cloud-Native Linux**: Amazon Linux 2 / 2023, Google Container-Optimized OS (COS).
- **Kernel Compatibility**: Linux Kernel 3.10+ (full support for both cgroups v1 and cgroups v2).

### 3.2. Automated Environment Detection
When a user runs `opskit diag`, the CLI dynamically inspects the local runtime:
- Verifies `KUBECONFIG`, `~/.kube/config`, or `/var/run/secrets/kubernetes.io/serviceaccount` → Activates **Kubernetes Mode**.
- Checks `/var/run/docker.sock` and queries `/info` for `LocalNodeState == "active"` → Activates **Docker Swarm Mode** or **Docker Standalone Mode**.
- Inspects `/etc/os-release`, `/run/systemd/system`, and kernel procfs → Activates **Linux Host / VM Mode**.
- Dedicated subcommands allow targeted diagnostic runs: `opskit diag k8s`, `opskit diag swarm`, `opskit diag docker`, `opskit diag host`.

---

## 4. What it diagnoses

### 4.1. Linux Host / VM Diagnostics (`opskit diag host`)
Essential SRE incident diagnostics for degraded or unresponsive virtual machines and bare-metal nodes:

1. **Systemd Services & Unit Failures**:
   - Discovers all units in `failed` or flapping `activating (auto-restart)` states.
   - Automatically parses recent `journalctl -u <unit>` error traces for root causes.
2. **Memory Saturation & Kernel OOM Events**:
   - Inspects `dmesg` / kernel log ring buffers for `Out of memory: Kill process <pid> (<name>) score <score>`.
   - Analyzes swap utilization and detects *Swap Thrashing* (excessive page faulting degrading I/O performance).
3. **CPU Contention & Zombie Processes**:
   - Compares 1-min, 5-min, and 15-min Load Averages against online CPU core counts.
   - Discovers `Z` (Zombie / defunct) processes and runaway processes consuming excessive CPU cycles.
4. **Storage & Inode Exhaustion**:
   - Triggers warnings at > 80% usage and critical alerts at > 90% filesystem capacity.
   - **Inode Saturation**: Flags filesystems where block storage has space remaining, but inodes are 100% full (a classic SRE blind spot).
   - Detects filesystems remounted as **Read-Only** following storage errors or I/O corruption.
5. **Network Sockets & DNS Benchmarking**:
   - Monitors socket tables for `TIME_WAIT` or `CLOSE_WAIT` connection leaks (> 10,000 sockets).
   - Runs micro-benchmarks against `/etc/resolv.conf` upstream nameservers to detect resolution delays (> 250ms).
   - Verifies open file descriptor counts against `ulimit -n` and `/proc/sys/fs/file-max`.

---

### 4.2. Docker Standalone & Compose Diagnostics (`opskit diag docker`)
1. **Container Crash Triage & Exit Code Forensic Analysis**:
   - Identifies non-zero exited containers and categorizes their failure modes:
     - `Exit Code 137`: SIGKILL, predominantly **OOMKilled** by Docker cgroup limits or kernel OOM killer.
     - `Exit Code 139`: SIGSEGV (Segmentation Fault, native memory corruption or incompatible C library).
     - `Exit Code 1` / `2`: Uncaught runtime exceptions, syntax errors, or invalid environment configurations.
     - `Exit Code 127`: Executable command not found (bad Dockerfile `ENTRYPOINT` or broken path).
   - Automatically extracts and scans the last 100 lines of container logs for critical signatures (`panic:`, `FATAL`, `NullPointerException`, `Connection refused`).
2. **Container Flapping & Restart Loops**:
   - Detects containers restarting excessively over short inspection windows.
3. **Healthcheck Failures**:
   - Identifies containers marked as `unhealthy` and extracts the failure output from `docker inspect`.
4. **Engine Storage Health**:
   - Measures storage overhead under `/var/lib/docker/overlay2`.
   - Identifies dangling images, unused volumes, and accumulated build cache.

---

### 4.3. Docker Swarm Deep Inspection (`opskit diag swarm`)
Specialized SRE features tailored for Docker Swarm multi-node orchestration:

1. **Swarm Cluster & Quorum Health**:
   - Checks Swarm Manager nodes for unreachable states and Raft split-brain conditions.
   - Detects worker nodes in `Down` or `Drain` availability.
2. **Service Replica Convergence**:
   - Flags services where `Running Replicas < Desired Replicas` (e.g., service configured for 5 replicas, but only 1 running).
3. **Per-Container Task Forensics**:
   - Automatically audits all underlying tasks for degraded Swarm services.
   - Captures failed task states (`Rejected`, `Failed`, `Shutdown`).
   - Diagnoses scheduler rejection reasons:
     - *"no suitable node (insufficient memory)"*
     - *"no suitable node (placement constraint [node.labels.zone == us-east-1a] not satisfied)"*
     - *"port 8080 is already allocated"*
   - Connects to target worker nodes to extract crash logs from dead container instances.
4. **Overlay Network & Ingress Routing Mesh**:
   - Validates reachability across core Swarm ports:
     - TCP 2377 (Cluster management)
     - TCP/UDP 7946 (Gossip control plane)
     - UDP 4789 (Overlay network VXLAN data plane)
   - Checks for **MTU Mismatch**: Identifies cases where packets exceeding 1450 bytes are dropped across the overlay mesh.

---

### 4.4. Kubernetes Comprehensive Diagnostics (`opskit diag k8s`)
Complete SRE health and topology analysis across Pods, Services, Ingress, DNS, Storage, and Nodes:

1. **Pod & Workload Health**:
   - Scans across all namespaces or specific targets (`--namespace`).
   - Diagnoses common workload failure states:
     - `CrashLoopBackOff`: Automatically fetches previous container logs (`kubectl logs --previous`) and extracts stack traces.
     - `OOMKilled`: Inspects `lastState.terminated.exitCode == 137` and correlates memory limits with peak usage.
     - `ImagePullBackOff` / `ErrImagePull`: Validates image repository paths, missing tags, or invalid `imagePullSecrets`.
     - `Pending`: Parses scheduler events for resource shortages (*Insufficient cpu/memory*, *0/N nodes match PodAffinity*, *untolerated taints*).
     - `Evicted`: Detects node storage or memory pressure evictions.
   - Identifies flapping Liveness and Readiness probes.
2. **Service & Endpoints Topology**:
   - **Orphan Service (Zero Endpoints)**: Detects Services (ClusterIP, NodePort, LoadBalancer) with 0 active Pod endpoints behind them (`Endpoints.subsets == nil`), commonly caused by label selector typos.
   - Port Mismatches: Detects mismatches between Service target ports and Pod container ports.
3. **Ingress Controller & DNS**:
   - Identifies Ingress resources referencing non-existent Services.
   - Checks Ingress TLS secrets for validity and impending expiration.
   - Verifies CoreDNS cluster pods, resolution latencies, and upstream forwarding.
4. **Storage (PVC & PV)**:
   - Identifies PersistentVolumeClaims stuck in `Pending` state.
   - Diagnoses volume attachment errors (*FailedAttachVolume*, *Multi-Attach error*).
5. **Node Infrastructure Pressure**:
   - Audits Node conditions: `DiskPressure`, `MemoryPressure`, `PIDPressure`, `NetworkUnavailable`, `NotReady`.
   - Evaluates node resource overcommit ratios (> 120% CPU/Memory requests).

---

## 5. Security auditing

Subcommand **`opskit audit sec`** implements security checks mapped to **CIS Benchmarks**, **NSA/CISA Kubernetes Hardening Guidance**, and **Docker Security Best Practices**.

### 5.1. Linux Host Security (CIS Benchmark Alignment)
- **SSH Configuration**:
  - `PermitRootLogin` (must be `no` or `prohibit-password`).
  - `PasswordAuthentication` (enforce key-based authentication).
  - Flags default SSH port exposure without IP whitelisting.
- **Sensitive File Permissions**:
  - Scans for world-writable system files (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/cron*`).
- **Unauthenticated Port Exposure**:
  - Flags dangerous services bound to `0.0.0.0` or `::`:
    - Databases: MySQL (3306), PostgreSQL (5432), MongoDB (27017).
    - In-Memory Stores: Redis (6379), Memcached (11211) without password auth.
    - Control Planes: Docker daemon socket (2375), Etcd (2379), Kubelet (10250/10255).
- **SSL/TLS Certificate Expiration**:
  - Scans local certificate directories (`/etc/ssl/certs`, Let's Encrypt, Nginx/Traefik certs) and remote endpoints.
  - Alerts when certificates expire within < 30 days (Warning) or < 7 days (Critical).

### 5.2. Docker & Container Security
- **Privileged Containers**: Flags containers executed with `--privileged` (bypasses container isolation).
- **Root User Execution**: Flags containers running as user `root` (UID 0) without non-root directives.
- **Sensitive Host Mounts**:
  - Mounting `/var/run/docker.sock` inside containers (grants host-level control).
  - Mounting host root (`/`), `/etc`, `/proc`, or `/sys`.
- **Exposed Environment Secrets**:
  - Scans container environment variables for plaintext secrets, credentials, or private keys.
- **Missing Resource Limits**:
  - Flags production containers without memory (`--memory`) or CPU (`--cpus`) limits.

### 5.3. Kubernetes Security (Pod Security Standards & RBAC)
- **Pod Security Standards (PSS)**:
  - Containers with `allowPrivilegeEscalation: true`.
  - Pods configured with `hostNetwork: true`, `hostPID: true`, or `hostIPC: true`.
  - Containers without `readOnlyRootFilesystem: true`.
  - Dangerous Linux capabilities: `CAP_SYS_ADMIN`, `CAP_NET_ADMIN` not dropped.
- **RBAC Over-Privilege**:
  - ServiceAccounts or ClusterRoleBindings granted unrestricted `cluster-admin` privileges.
  - Wildcard (`*`) permissions on verbs or resources.
  - Default ServiceAccount tokens mounted where cluster API communication is unnecessary.
- **Network Segmentation**:
  - Namespaces lacking active `NetworkPolicy` resources (unrestricted east-west traffic).

---

## 6. Report format

Every anomaly follows a structured Root-Cause Analysis format: what was observed,
the mechanism behind it, the evidence, ordered remediation, and a runnable
quick-fix. Findings are ordered most-severe-first; `PASS` checks are summarised
as a count rather than listed, so the incident is the first thing on screen.

```text
================================================================================
               OPS TOOLKIT (OPSKIT) DIAGNOSTIC & HEALTH REPORT
================================================================================
Host OS:      Ubuntu 22.04 LTS (5.15.0-89-generic, amd64)
Deployments:  Host/Systemd, Docker, Kubernetes
Duration:     184ms | Timestamp: 2026-09-01 18:00:00 UTC
Summary:      2 CRITICAL, 1 WARNING, 18 PASS
--------------------------------------------------------------------------------

[CRITICAL] #1: Pod Terminated (OOMKilled): production/payment-846bf499db-8d2qx (pod/payment-846bf499db-8d2qx)
  Rule ID:     K8S-POD-002
  Category:    Resource Saturation
  Symptom:     Container "payment-app" was killed with exit code 137 after exceeding its memory limit.
  Root Cause:  Container memory usage surpassed spec.resources.limits.memory, so the
               kernel cgroup OOM killer terminated it.
  Remediation:
    1. Measure the real working set before raising the limit: kubectl top pod payment-846bf499db-8d2qx -n production
    2. Raise resources.limits.memory in the workload manifest to cover peak usage plus headroom
    3. For JVM workloads set -XX:MaxRAMPercentage so the heap respects the cgroup limit

[CRITICAL] #2: Swarm Service Replica Discrepancy: notification_worker (0/4) (service:notification_worker)
  Rule ID:     SWM-REP-001
  Category:    Service Convergence
  Symptom:     Service is running 0 of 4 desired replicas.
  Root Cause:  Placement constraints or node labels exclude every node in the cluster.
  Evidence:    n3k2p1 \ Ready Rejected "no suitable node (scheduling constraints not satisfied)"
  Remediation:
    1. Read the full task error: docker service ps notification_worker --no-trunc
    2. Inspect application logs across tasks: docker service logs --tail 50 notification_worker
    3. Compare the service's resource reservations and constraints against actual node capacity
  Quick Fix:   docker service update --force notification_worker

[WARNING] #3: SSH Password Authentication Allowed (file:/etc/ssh/sshd_config)
  Rule ID:     SEC-SSH-002
  Category:    Authentication Hardening
  Symptom:     Password authentication is enabled instead of enforcing public key authentication only.
  Root Cause:  Passwords are prone to brute-force credential stuffing attacks.
  Remediation:
    1. Deploy SSH public keys for authorized engineers
    2. Set 'PasswordAuthentication no' in /etc/ssh/sshd_config

[OK] 18 checks passed successfully.
================================================================================
```

The `Rule ID` row is what an operator passes to `opskit explain <id>` for a full
runbook, and to `opskit fix --only <id>` to apply just that finding's fix.

The same report is available as JSON (`--json`) and as a Markdown incident
document (`-o report.md`); both carry the full finding set including `PASS`.

---

## 7. Commands

```bash
# Automated diagnostics (auto-detects the active environment)
opskit diag                          # Every detected subsystem
opskit diag --json                   # Machine-readable output for CI/CD
opskit diag --output report.md       # Markdown incident document

# Targeted diagnostics
opskit diag host                     # Memory, CPU load, disk, inodes, mounts, sockets, systemd, DNS, OOM killer
opskit diag docker                   # Container exit codes, restart loops, healthchecks, storage footprint
opskit diag swarm                    # Nodes, service convergence, task placement forensics
opskit diag k8s                      # Pods, services, ingress, PVCs, nodes, CoreDNS
opskit diag k8s -n production        # Restrict to one namespace (default: all)

# Security audits
opskit audit sec                     # Host, Docker, and Kubernetes posture
opskit audit certs                   # Local certificate paths
opskit audit certs example.com:443   # A specific remote TLS endpoint

# Remediation — --dry-run is the default
opskit fix                           # Preview each fix with its LOW/MEDIUM/HIGH risk grade
opskit fix --dry-run=false           # Apply, with one interactive confirmation
opskit fix --max-risk medium         # Refuse anything that deletes data or stops a service
opskit fix --only HOST-DSK-001       # Apply one specific finding's fix
opskit fix docker -y                 # Non-interactive (CI, cron)

# CI/CD quality gate — exit 0 pass, 1 threshold breached, 2 run failed
opskit verify --fail-on critical
opskit verify --fail-on warning -n production

# Telemetry and continuous operation
opskit export-metrics --port 9876 --interval 30s
opskit daemon --interval 60s --alert-on critical --webhook-url "https://hooks.slack.com/..."

# Investigation
opskit explain K8S-POD-002           # Incident runbook (local Ollama, or built-in heuristics)
opskit net 1.1.1.1                   # DNS benchmark, TCP latency, Path MTU
opskit net dns example.com
opskit net mtu 10.0.0.1
opskit tui                           # Interactive terminal dashboard

# Setup
opskit completion install            # zsh, bash, or fish
opskit version
```

### 7.1. Global flags

| Flag | Default | Purpose |
|---|---|---|
| `--timeout` | `2m` | Deadline for the whole run. Every external command is additionally bounded on its own, so an unreachable API server cannot hang the CLI. `0` disables. |
| `--json` | off | Machine-readable output. |
| `--output`, `-o` | — | Write the report to a file; `.json` and `.md` select the format. |
| `--no-color` | off | Suppress every ANSI escape, for CI logs. |
| `--verbose`, `-v` | off | Additional diagnostic logging. |

`SIGINT` and `SIGTERM` cancel a run in progress rather than leaving orphaned
child processes behind.

### 7.2. Environment overrides

| Variable | Purpose |
|---|---|
| `OPSKIT_PROC_ROOT` | Where to read procfs from. Set to `/host/proc` in the container deployments, because a container's own `/proc` describes the container rather than the node. |
| `OPSKIT_DNS_PROBE` | The name `HOST-DNS-001` resolves. Point this at a resolvable internal name on air-gapped or split-horizon estates, otherwise every run reports a false `CRITICAL`. |
| `OLLAMA_HOST`, `SRE_AI_MODEL` | Local LLM endpoint and model for `opskit explain`. Falls back to built-in heuristics when unreachable. |

---

## 8. Code layout

```text
opskit/
├── main.go                       # Entrypoint; delegates to cmd.Execute()
├── cmd/                          # Cobra command layer — flag parsing and output only
│   ├── root.go                   # Global flags, CommandContext() (timeout + signal cancellation)
│   ├── diag.go                   # 'diag' and its host/docker/swarm/k8s subcommands
│   ├── audit.go                  # 'audit sec' and 'audit certs'
│   ├── fix.go                    # 'fix' — risk grading, --max-risk, --only, TTY guard
│   ├── verify.go                 # 'verify' — CI gate, threshold validation, exit codes
│   ├── net.go                    # 'net', 'net dns', 'net mtu'
│   ├── explain.go                # 'explain' — incident runbook
│   ├── daemon.go                 # 'daemon' — continuous watcher
│   ├── metrics.go                # 'export-metrics' — Prometheus exporter
│   ├── tui.go                    # 'tui' — interactive dashboard
│   ├── completion.go             # 'completion' — shell autocompletion installer
│   └── version.go                # 'version'
├── pkg/
│   ├── model/                    # Finding, Report, Severity, TargetType — the shared contract
│   ├── detector/                 # Probes OS/distro, docker.sock, swarm state, kubeconfig
│   ├── sysexec/                  # Runner interface: every external command under a deadline.
│   │                             #   Real{} shells out; Fake{} replays recorded output in tests.
│   ├── analyzer/                 # The rule engine (see §8.1)
│   │   ├── analyzer.go           #   Engine, orchestration, severity ordering, injectable seams
│   │   ├── host.go               #   HOST-*  rules
│   │   ├── docker.go             #   DOC-*   rules
│   │   ├── swarm.go              #   SWM-*   rules
│   │   ├── kubernetes.go         #   K8S-*   rules
│   │   ├── security.go           #   SEC-*   rules
│   │   ├── custom_rules.go       #   User-authored YAML rules from rules.d/
│   │   └── fsusage.go            #   df(1)-accurate filesystem occupancy (unix build tag)
│   ├── security/                 # SSH config, exposed ports, local + remote X.509 audit
│   ├── netdiag/                  # DNS benchmark, TCP handshake, Path MTU probing
│   ├── remediation/              # Fix planning, risk classification, bounded execution
│   ├── report/                   # Console / JSON / Markdown renderers
│   ├── exporter/                 # Prometheus /metrics HTTP server
│   ├── daemon/                   # Continuous watcher with webhook alerting
│   └── ui/                       # Bubbletea TUI
├── rules.d/                      # Custom YAML rules (also read from ~/.opskit/rules.d)
├── deploy/                       # Helm chart, K8s DaemonSet, Swarm stack, systemd unit, Grafana dashboard
├── .github/workflows/            # CI (fmt, vet, tidy, -race, cross-compile, govulncheck) and release
├── Dockerfile                    # Multi-stage static build; runs as UID 65532
├── action.yml                    # Reusable GitHub Action wrapping 'opskit verify'
├── install.sh                    # One-line installer
├── Makefile                      # build, build-linux, test, clean
├── LICENSE                       # Apache 2.0
├── PLANNING.md                   # This document
├── SPEC.md                       # Technical specification & rule catalog (source of truth for rule IDs)
├── ROADMAP.md                    # Milestones
└── README.md                     # User guide
```

### 8.1. Collectors and evaluators

Every rule is split in two.

- A **collector** is a method on `*Engine`. It is the only part that touches the
  machine: it shells out through `sysexec.Runner`, reads a file under
  `procRoot`, or calls `statfs`. It does no scoring.
- An **evaluator** is a package-level function taking already-collected data and
  returning `[]model.Finding`. It performs no I/O.

```go
// collector — touches the machine, no scoring
func (e *Engine) checkMemory() []model.Finding {
    content, err := e.readProc("meminfo")
    if err != nil {
        return nil
    }
    return evaluateMemory(parseMeminfo(content))
}

// evaluator — pure, and therefore directly testable
func evaluateMemory(stats meminfoStats) []model.Finding { ... }
```

This is what makes the rule set testable without a live Docker daemon or
Kubernetes cluster: the evaluators are exercised against captured fixtures
(`kubectl -o json` payloads, `/proc` file contents, `docker` CLI output), and
`sysexec.Fake` replays recorded command output for engine-level tests.

`Engine` exposes injectable seams for everything else that would otherwise make a
test depend on the host — `WithRunner`, `WithProcRoot`, `WithStatfs`,
`WithResolver`, `WithClock`.

**When adding a rule, keep this shape.** A rule that inlines `exec.Command` into
its scoring logic cannot be tested and will not be reviewable.

### 8.2. How a run flows

```
CommandContext()  --timeout + SIGINT/SIGTERM
      │
      ▼
detector.Detect() ──▶ analyzer.NewEngine(env) ──▶ RunDiagnostics(ctx, target, ns)
                                                        │
                          ┌─────────────────────────────┤ per active target
                          ▼                             ▼
                   collectors (sysexec, procfs)   custom rules (rules.d)
                          │                             │
                          ▼                             ▼
                     evaluators ──────────────▶ []model.Finding
                                                        │
                                          sort by severity, summarise
                                                        │
                          ┌─────────────────────────────┼──────────────────┐
                          ▼                             ▼                  ▼
                    report.PrintConsole          report.PrintJSON   report.GenerateMarkdown
```

Cancelling the context aborts in-flight external commands and stops further
rules. Each command additionally carries its own deadline, so one wedged
`kubectl` cannot consume the entire run budget.
