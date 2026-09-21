# opskit specification

The authoritative reference for rule IDs, thresholds, and the data contract.
Design reasoning lives in [PLANNING.md](PLANNING.md); usage lives in
[README.md](README.md).

## 1. Pipeline

```
detector → collectors → rule evaluators → reporters
```

**Detector** (`pkg/detector`) works out what is actually present: the OS and
distribution, whether `/run/systemd/system` exists, whether `/var/run/docker.sock`
answers and whether that daemon is in Swarm mode, and whether a kubeconfig or an
in-cluster service account token is available. Only the relevant checks then run.

**Collectors** are methods on `analyzer.Engine`. They are the only code allowed
to touch the machine: they shell out through `pkg/sysexec`, read a file under the
configured procfs root, or call `statfs`. They do no scoring.

**Evaluators** are package-level functions taking already-collected data and
returning `[]model.Finding`. They perform no I/O, which is what makes them
testable against fixtures.

**Reporters** (`pkg/report`) render the same `model.Report` as coloured console
output, JSON, or Markdown.

## 2. Data model (`pkg/model`)

### 2.1. Severity and target
```go
type Severity string

const (
    SeverityCritical Severity = "CRITICAL" // Service down, crashloop, data loss risk, OOM
    SeverityWarning  Severity = "WARNING"  // Resource near threshold, cert expiry < 30d
    SeverityInfo     Severity = "INFO"     // Informational findings, optimization tips
    SeverityPass     Severity = "PASS"     // Check passed healthy
)

type TargetType string

const (
    TargetHost       TargetType = "HOST"
    TargetDocker     TargetType = "DOCKER"
    TargetSwarm      TargetType = "SWARM"
    TargetKubernetes TargetType = "KUBERNETES"
    TargetSecurity   TargetType = "SECURITY"
)
```

### 2.2. Finding
```go
type Finding struct {
    ID          string            `json:"id"`           // e.g. "K8S-OOM-001"
    Title       string            `json:"title"`        // e.g. "Pod Terminated with Exit Code 137"
    TargetType  TargetType        `json:"target_type"`  // HOST, DOCKER, SWARM, KUBERNETES, SECURITY
    Category    string            `json:"category"`     // e.g. "Crash & OOM", "Network", "Storage"
    Resource    string            `json:"resource"`     // e.g. "pod/payment-worker-846b-xyz"
    Namespace   string            `json:"namespace,omitempty"`
    Severity    Severity          `json:"severity"`     // CRITICAL, WARNING, INFO, PASS
    Symptom     string            `json:"symptom"`      // Observed manifestation
    RootCause   string            `json:"root_cause"`   // Deep diagnosis / RCA
    LogEvidence string            `json:"log_evidence,omitempty"` // Log snippet proving root cause
    RemedySteps []string          `json:"remedy_steps"` // Recommended remediation actions
    QuickFixCmd string            `json:"quick_fix_cmd,omitempty"` // Ready-to-run mitigation command
    Metadata    map[string]string `json:"metadata,omitempty"`
}
```

### 2.3. Report
```go
type Report struct {
    Title        string             `json:"title"`
    Timestamp    time.Time          `json:"timestamp"`
    Duration     string             `json:"duration"`
    Environment  EnvironmentContext `json:"environment"`
    Summary      Summary            `json:"summary"`
    Findings     []Finding          `json:"findings"`
}

type Summary struct {
    Critical int `json:"critical"`
    Warning  int `json:"warning"`
    Info     int `json:"info"`
    Pass     int `json:"pass"`
}
```

---

## 3. Extension points

There is no `Collector` or `Rule` interface. Rules are plain functions following
a convention, which keeps the indirection down; the seams that exist are the ones
tests actually needed.

### 3.1. Running external commands

```go
type Runner interface {
    Run(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error)
    Available(name string) bool
}
```

`sysexec.Real` shells out with a mandatory deadline. `sysexec.Fake` replays
recorded output keyed by command prefix, so engine-level tests never invoke
`docker` or `kubectl`.

### 3.2. Engine seams

`analyzer.NewEngine` accepts options that replace everything which would
otherwise tie a test to the host it runs on:

| Option | Replaces |
|---|---|
| `WithRunner` | External command execution |
| `WithProcRoot` | The procfs mount point (also settable at runtime via `OPSKIT_PROC_ROOT`) |
| `WithStatfs` | Filesystem usage probing |
| `WithResolver` | DNS lookups |
| `WithClock` | `time.Now` |

### 3.3. The rule convention

```go
// Collector: touches the machine, does no scoring.
func (e *Engine) checkMemory() []model.Finding {
    content, err := e.readProc("meminfo")
    if err != nil {
        return nil
    }
    return evaluateMemory(parseMeminfo(content))
}

// Evaluator: pure, and therefore directly testable.
func evaluateMemory(stats meminfoStats) []model.Finding { ... }
```

A rule that calls `exec.Command` from inside its scoring logic cannot be tested
and should not be merged.

### 3.4. Runtime rules

Users add checks as YAML in `rules.d/` without rebuilding. Conditions are ANDed.
See the README for the schema.

---

## 4. Rule catalog

Every rule below is implemented and unit-tested. `PASS` rules emit a healthy
result so the operator can see the check ran; the rest fire only on a fault.

### 4.1. Host (`HOST-*`)

| ID | Condition | Severity | Source |
|---|---|---|---|
| `HOST-SYS-001` | Systemd unit in `failed` state | CRITICAL | `systemctl --failed` |
| `HOST-MEM-001` | Kernel OOM-killer terminations, grouped per victim process | CRITICAL | `dmesg` |
| `HOST-MEM-002` | Memory usage ≥ 92% (CRITICAL) or ≥ 85% (WARNING), measured against `MemAvailable` | CRITICAL / WARNING | `/proc/meminfo` |
| `HOST-MEM-003` | Swap utilisation ≥ 60% | WARNING | `/proc/meminfo` |
| `HOST-CPU-001` | 5-minute load average ≥ 2.0 per core (CRITICAL) or ≥ 1.0 per core (WARNING) | CRITICAL / WARNING | `/proc/loadavg` |
| `HOST-DSK-001` | Disk usage ≥ 90% (CRITICAL) or ≥ 80% (WARNING) | CRITICAL / WARNING | `statfs` |
| `HOST-INO-001` | Inode usage ≥ 90% (CRITICAL) or ≥ 80% (WARNING) | CRITICAL / WARNING | `statfs` |
| `HOST-ROF-001` | A data filesystem is mounted read-only | CRITICAL | `/proc/mounts` |
| `HOST-ZOM-001` | More than 5 processes in defunct (`Z`) state | WARNING | `/proc/<pid>/stat` |
| `HOST-NET-001` | More than 10,000 sockets in `TIME_WAIT` | WARNING | `/proc/net/tcp`, `/proc/net/tcp6` |
| `HOST-DNS-001` | Resolution failure (CRITICAL) or latency > 400ms (WARNING) | CRITICAL / WARNING | resolver |

**Measurement notes.**

- `HOST-DSK-001` computes occupancy the way `df(1)` does — `used / (used + available)`
  — so the root-reserved block pool is not counted as headroom. On macOS the
  check targets `/System/Volumes/Data`, because `/` is a sealed read-only
  snapshot that reports ample free space on a full machine.
- `HOST-MEM-002` derives pressure from `MemAvailable`, which accounts for
  reclaimable page cache. Deriving it from `MemFree` reports a healthy host as
  nearly out of memory.
- `HOST-DNS-001` resolves `google.com` by default. Set `OPSKIT_DNS_PROBE` to a
  name the host can actually resolve on air-gapped or split-horizon estates.

### 4.2. Docker (`DOC-*`)

| ID | Condition | Severity |
|---|---|---|
| `DOC-EXT-137` | Container exited 137 (SIGKILL — cgroup or host OOM kill) | CRITICAL |
| `DOC-EXT-139` | Container exited 139 (SIGSEGV) | CRITICAL |
| `DOC-EXT-127` | Container exited 127 (entrypoint not found) | CRITICAL |
| `DOC-EXT-ERR` | Container exited with any other non-zero status | WARNING |
| `DOC-RES-001` | Restart count above 5 while the restart policy keeps reviving it | CRITICAL |
| `DOC-HLT-001` | Container `HEALTHCHECK` reporting unhealthy | WARNING |
| `DOC-DSK-001` | Docker images, containers, volumes, and build cache occupy ≥ 50% of the filesystem | WARNING |
| `DOC-ALL-001` | No container faults found | PASS |

### 4.3. Swarm (`SWM-*`)

| ID | Condition | Severity |
|---|---|---|
| `SWM-NOD-001` | Node reporting `Down`, `Unknown`, or `Unreachable` | CRITICAL |
| `SWM-NOD-002` | Node in `Drain` availability | INFO |
| `SWM-REP-001` | `RunningReplicas < DesiredReplicas` | CRITICAL |
| `SWM-MTU-001` | 1422-byte DF packets dropped (VXLAN overlay MTU too small) | CRITICAL |
| `SWM-ALL-001` | Cluster converged | PASS |

`SWM-TSK-001` task forensics are folded into `SWM-REP-001`: the per-task error is
captured as `LogEvidence` and classified into a specific root cause (insufficient
memory, insufficient CPU, unsatisfiable constraint, port conflict, missing image,
or unavailable volume) rather than reported as a separate finding.

### 4.4. Kubernetes (`K8S-*`)

| ID | Condition | Severity |
|---|---|---|
| `K8S-POD-001` | Container in `CrashLoopBackOff`, with the `lastState` exit reason as evidence | CRITICAL |
| `K8S-POD-002` | Container terminated `OOMKilled` (detected in `state` or `lastState`) | CRITICAL |
| `K8S-POD-003` | `ImagePullBackOff` or `ErrImagePull` | CRITICAL |
| `K8S-POD-004` | Pod `Pending` and not `ContainerCreating` (unschedulable) | WARNING |
| `K8S-POD-005` | Pod `Evicted` under node resource pressure | WARNING |
| `K8S-POD-006` | `CreateContainerConfigError` (missing ConfigMap or Secret) | CRITICAL |
| `K8S-POD-007` | Running container with a restart count above 5 | WARNING |
| `K8S-SVC-001` | Service with zero endpoints (selector matches no pods) | WARNING |
| `K8S-SVC-002` | Service whose backing pods all fail readiness | CRITICAL |
| `K8S-ING-001` | Ingress backend references a Service that does not exist | CRITICAL |
| `K8S-ING-002` | Ingress TLS `secretName` does not exist | CRITICAL |
| `K8S-DNS-001` | CoreDNS fully down (CRITICAL), partially degraded (WARNING), or healthy (PASS) | CRITICAL / WARNING / PASS |
| `K8S-PVC-001` | PersistentVolumeClaim `Pending` (WARNING) or `Lost` (CRITICAL) | WARNING / CRITICAL |
| `K8S-NOD-001` | Node `Ready` condition is not `True` | CRITICAL |
| `K8S-NOD-002` | Node reporting `MemoryPressure`, `DiskPressure`, `PIDPressure`, or `NetworkUnavailable` | CRITICAL |
| `K8S-API-001` | A kubeconfig exists but no resource could be listed | WARNING |
| `K8S-ALL-001` | No cluster faults found | PASS |

Cluster state is read with `kubectl get <kind> -o json` and decoded into typed
structs. An earlier implementation used a `{len .subsets}` jsonpath expression,
which kubectl rejects outright (`unrecognized identifier len`) — the orphan
service check never ran.

### 4.5. Security (`SEC-*`)

| ID | Condition | Severity |
|---|---|---|
| `SEC-SSH-001` | `PermitRootLogin yes` | CRITICAL |
| `SEC-SSH-002` | `PasswordAuthentication yes` | WARNING |
| `SEC-FIL-001` | Sensitive file readable or writable beyond its expected mode | CRITICAL / WARNING |
| `SEC-PRT-001` | Unauthenticated service port reachable (2375, 6379, 27017, 2379, 11211) | WARNING |
| `SEC-CRT-001` | Certificate expired or expiring within 7 days (CRITICAL) or 30 days (WARNING) | CRITICAL / WARNING |
| `SEC-CRT-002` | TLS handshake failure against an audited endpoint | CRITICAL |
| `SEC-DOC-001` | Container running with `--privileged` | CRITICAL |
| `SEC-DOC-002` | Container running as UID 0 | WARNING |
| `SEC-DOC-003` | Sensitive host path mounted (`docker.sock`, `/`, `/etc`, `containerd.sock`, `/var/lib/kubelet`) | CRITICAL |
| `SEC-K8S-001` | Pod Security Standards violation (`privileged`, `hostNetwork`, `hostPID`, `allowPrivilegeEscalation`) | CRITICAL / WARNING |
| `SEC-K8S-002` | Custom ClusterRole granting wildcard verbs on wildcard resources | CRITICAL |

`SEC-FIL-001` grades per file rather than checking a single world-writable bit:
`/etc/shadow` must not be group- or world-readable, while `/etc/passwd` is
world-readable by design and only world-writability is a fault.

`SEC-K8S-001` exempts `kube-system`, `kube-public`, `kube-node-lease`, and
`local-path-storage`; control-plane and CNI components legitimately need host
access, and flagging them every run trains operators to ignore the check.
`SEC-K8S-002` exempts the built-in `cluster-admin`, `admin`, `edit`, and
`system:*` roles for the same reason.

### 4.6. Network (`NET-*`)

| ID | Condition | Severity |
|---|---|---|
| `NET-DNS-FAIL` | A configured nameserver did not answer | CRITICAL |
| `NET-DNS-LATENCY` | Nameserver latency > 300ms | WARNING |
| `NET-TCP-CONNECT` | TCP handshake to the target failed | WARNING |
| `NET-MTU-001` | Path MTU below the 1280-byte IPv6 minimum | CRITICAL |
| `NET-MTU-UNKNOWN` | The target does not answer ICMP, so no MTU conclusion is possible | INFO |
| `NET-ALL-HEALTHY` | DNS, TCP, and MTU all within normal parameters | PASS |

MTU probing first sends a minimum-size ping. Without that baseline, any host
that filters ICMP — which is most cloud endpoints — reports as a critical VXLAN
MTU fault.

## 5. Command behaviour

### 5.1. `opskit fix`

Collects `QuickFixCmd` from active findings, skipping `PASS` results and
collapsing duplicate commands. Each is graded by what it can destroy:

| Grade | Meaning |
|---|---|
| `LOW` | Additive or read-mostly |
| `MEDIUM` | Restarts or reconfigures a service |
| `HIGH` | Deletes data or stops a service |

The grade is a heuristic over the command text. It decides what needs a second
look; it never decides that something is safe to run unattended.

`--dry-run` defaults to `true`. `--max-risk` sets a ceiling, `--only` restricts
to named rule IDs. Applying requires either an interactive confirmation or `-y`;
with stdin not a terminal and no `-y`, the command refuses rather than reading
approval from whatever happens to be piped in. Exits non-zero if any fix fails.

Commands run through `sh -c` because the curated fixes use shell operators. They
originate from opskit's own rules and from rule files the operator wrote, and
each is bounded by a 60-second timeout.

### 5.2. `opskit verify`

Evaluates findings against `--fail-on`, which accepts `critical`, `warning`, or
`info`. An unrecognised value is rejected — it is not treated as `critical`.

| Exit | Meaning |
|---|---|
| `0` | Nothing at or above the threshold |
| `1` | Threshold breached |
| `2` | The run itself failed (cancelled, timed out, errored) |

### 5.3. `opskit export-metrics`

HTTP server on `:9876`, `/metrics` and `/healthz`. Evaluates on start and every
`--interval`. Series: `opskit_up`, `opskit_findings_total{target,severity}`,
`opskit_severity_count{severity}`,
`opskit_finding_active{id,severity,target,resource,namespace}`,
`opskit_health_score`, `opskit_last_evaluation_timestamp_seconds`,
`opskit_evaluation_errors_total`.

Label values are escaped and duplicate series collapsed, so a quote or newline
in a resource name cannot corrupt the scrape. `PASS` findings are excluded from
`opskit_finding_active` to bound cardinality. Output ordering is deterministic.

`SIGTERM` triggers a graceful shutdown and the process exits `0`.

### 5.4. `opskit daemon`

Evaluates every `--interval` and posts new findings at or above `--alert-on` to
`--webhook-url`. A finding is suppressed for 30 minutes after alerting, keyed on
rule ID plus resource, and expired keys are pruned each cycle so the map does not
grow for the lifetime of the process. A non-2xx webhook response is reported as a
delivery failure rather than a success.

### 5.5. Cancellation

`--timeout` bounds the whole run (default 2m, `0` disables). Every external
command carries its own deadline as well, so one wedged `kubectl` cannot consume
the entire budget. `SIGINT` and `SIGTERM` cancel in-flight work.
