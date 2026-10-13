package analyzer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// -----------------------------------------------------------------------------
// HOST-ROF-001 — filesystems remounted read-only (/proc/mounts)
// -----------------------------------------------------------------------------

// pseudoFilesystems never carry application data, so their permanent read-only
// state is normal and must not be reported.
var pseudoFilesystems = map[string]bool{
	"sysfs": true, "proc": true, "devtmpfs": true, "devpts": true,
	"tmpfs": true, "securityfs": true, "cgroup": true, "cgroup2": true,
	"pstore": true, "efivarfs": true, "bpf": true, "debugfs": true,
	"tracefs": true, "hugetlbfs": true, "mqueue": true, "fusectl": true,
	"configfs": true, "ramfs": true, "binfmt_misc": true, "autofs": true,
	"squashfs": true, "iso9660": true, "overlay": true, "nsfs": true,
}

// mountEntry is one line of /proc/mounts.
type mountEntry struct {
	Device     string
	MountPoint string
	FSType     string
	Options    []string
}

// ReadOnly reports whether the mount carries the ro option.
func (m mountEntry) ReadOnly() bool {
	for _, o := range m.Options {
		if o == "ro" {
			return true
		}
	}
	return false
}

// parseMounts parses a /proc/mounts body.
func parseMounts(content string) []mountEntry {
	entries := make([]mountEntry, 0, 32)
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		entries = append(entries, mountEntry{
			Device:     fields[0],
			MountPoint: fields[1],
			FSType:     fields[2],
			Options:    strings.Split(fields[3], ","),
		})
	}
	return entries
}

// mountInfoEntry is one line of /proc/self/mountinfo.
type mountInfoEntry struct {
	MountID      int
	ParentID     int
	MajorMinor   string
	Root         string
	MountPoint   string
	MountOptions []string
	FSType       string
	Source       string
	SuperOptions []string
}

func (m mountInfoEntry) ReadOnly() bool {
	for _, o := range m.MountOptions {
		if o == "ro" {
			return true
		}
	}
	for _, o := range m.SuperOptions {
		if o == "ro" {
			return true
		}
	}
	return false
}

// parseMountInfo parses /proc/self/mountinfo.
func parseMountInfo(content string) []mountInfoEntry {
	entries := make([]mountInfoEntry, 0, 32)
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		sepIdx := -1
		for i, f := range fields {
			if f == "-" {
				sepIdx = i
				break
			}
		}
		if sepIdx < 6 || len(fields) < sepIdx+3 {
			continue
		}

		mountID, _ := strconv.Atoi(fields[0])
		parentID, _ := strconv.Atoi(fields[1])

		entry := mountInfoEntry{
			MountID:      mountID,
			ParentID:     parentID,
			MajorMinor:   fields[2],
			Root:         fields[3],
			MountPoint:   fields[4],
			MountOptions: strings.Split(fields[5], ","),
			FSType:       fields[sepIdx+1],
			Source:       fields[sepIdx+2],
		}
		if len(fields) > sepIdx+3 {
			entry.SuperOptions = strings.Split(fields[sepIdx+3], ",")
		}
		entries = append(entries, entry)
	}
	return entries
}

func evaluateReadOnlyMountInfo(entries []mountInfoEntry) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, m := range entries {
		if !m.ReadOnly() || pseudoFilesystems[m.FSType] {
			continue
		}
		// Sub-tree or single-file bind mounts (e.g. docker -v ./foo:/bar:ro) have Root != "/"
		if m.Root != "/" {
			continue
		}
		// A read-only bind of a container image layer or snap is by design.
		if strings.HasPrefix(m.MountPoint, "/snap/") ||
			strings.HasPrefix(m.MountPoint, "/var/lib/docker/") ||
			strings.HasPrefix(m.MountPoint, "/var/lib/containerd/") {
			continue
		}
		// Real data filesystems are backed by a block device.
		if !strings.HasPrefix(m.Source, "/dev/") {
			continue
		}

		findings = append(findings, model.Finding{
			ID:         "HOST-ROF-001",
			Title:      fmt.Sprintf("Filesystem Mounted Read-Only: %s", m.MountPoint),
			TargetType: model.TargetHost,
			Category:   "Storage Integrity",
			Resource:   "filesystem:" + m.MountPoint,
			Severity:   model.SeverityCritical,
			Symptom:    fmt.Sprintf("%s (%s on %s) is mounted read-only. All writes to this path will fail.", m.MountPoint, m.FSType, m.Source),
			RootCause:  "The kernel remounted the filesystem read-only after an I/O or journal error, or it was mounted ro deliberately. This is the classic signature of failing storage.",
			RemedySteps: []string{
				fmt.Sprintf("Check the kernel ring buffer for the triggering I/O error: dmesg -T | grep -i -E 'EXT4-fs|I/O error|%s'", m.Source),
				fmt.Sprintf("Run a filesystem check on the unmounted device: fsck -y %s", m.Source),
				"Inspect the underlying disk health with smartctl before remounting read-write",
			},
			Metadata: map[string]string{"device": m.Source, "fstype": m.FSType},
		})
	}

	if len(findings) == 0 {
		findings = append(findings, model.Finding{
			ID:         "HOST-ROF-001",
			Title:      "All Data Filesystems Writable",
			TargetType: model.TargetHost,
			Category:   "Storage Integrity",
			Resource:   "filesystem:mounts",
			Severity:   model.SeverityPass,
			Symptom:    "No data filesystem has been remounted read-only.",
		})
	}

	return findings
}

func (e *Engine) checkReadOnlyMounts() []model.Finding {
	if content, err := e.readProc("self/mountinfo"); err == nil && len(strings.TrimSpace(content)) > 0 {
		return evaluateReadOnlyMountInfo(parseMountInfo(content))
	}
	if content, err := e.readProc("mountinfo"); err == nil && len(strings.TrimSpace(content)) > 0 {
		return evaluateReadOnlyMountInfo(parseMountInfo(content))
	}

	content, err := e.readProc("mounts")
	if err != nil {
		return nil
	}
	return evaluateReadOnlyMounts(parseMounts(content))
}

func evaluateReadOnlyMounts(mounts []mountEntry) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, m := range mounts {
		if !m.ReadOnly() || pseudoFilesystems[m.FSType] {
			continue
		}
		// A read-only bind of a container image layer is by design.
		if strings.HasPrefix(m.MountPoint, "/snap/") ||
			strings.HasPrefix(m.MountPoint, "/var/lib/docker/") ||
			strings.HasPrefix(m.MountPoint, "/var/lib/containerd/") {
			continue
		}
		// Real data filesystems are backed by a block device.
		if !strings.HasPrefix(m.Device, "/dev/") {
			continue
		}

		findings = append(findings, model.Finding{
			ID:         "HOST-ROF-001",
			Title:      fmt.Sprintf("Filesystem Mounted Read-Only: %s", m.MountPoint),
			TargetType: model.TargetHost,
			Category:   "Storage Integrity",
			Resource:   "filesystem:" + m.MountPoint,
			Severity:   model.SeverityCritical,
			Symptom:    fmt.Sprintf("%s (%s on %s) is mounted read-only. All writes to this path will fail.", m.MountPoint, m.FSType, m.Device),
			RootCause:  "The kernel remounted the filesystem read-only after an I/O or journal error, or it was mounted ro deliberately. This is the classic signature of failing storage.",
			RemedySteps: []string{
				fmt.Sprintf("Check the kernel ring buffer for the triggering I/O error: dmesg -T | grep -i -E 'EXT4-fs|I/O error|%s'", m.Device),
				fmt.Sprintf("Run a filesystem check on the unmounted device: fsck -y %s", m.Device),
				"Inspect the underlying disk health with smartctl before remounting read-write",
			},
			Metadata: map[string]string{"device": m.Device, "fstype": m.FSType},
		})
	}

	if len(findings) == 0 {
		findings = append(findings, model.Finding{
			ID:         "HOST-ROF-001",
			Title:      "All Data Filesystems Writable",
			TargetType: model.TargetHost,
			Category:   "Storage Integrity",
			Resource:   "filesystem:mounts",
			Severity:   model.SeverityPass,
			Symptom:    "No data filesystem has been remounted read-only.",
		})
	}

	return findings
}

// -----------------------------------------------------------------------------
// HOST-ZOM-001 — zombie process accumulation
// -----------------------------------------------------------------------------

// parseProcState extracts the process state from a /proc/<pid>/stat body.
// The comm field is wrapped in parentheses and may itself contain spaces and
// parentheses, so the state is read relative to the LAST ')' rather than by
// splitting on whitespace.
func parseProcState(stat string) (string, bool) {
	closing := strings.LastIndex(stat, ")")
	if closing < 0 || closing+2 >= len(stat) {
		return "", false
	}
	rest := strings.Fields(stat[closing+1:])
	if len(rest) == 0 {
		return "", false
	}
	return rest[0], true
}

func (e *Engine) checkZombieProcesses() []model.Finding {
	entries, err := os.ReadDir(e.procRoot)
	if err != nil {
		return nil
	}

	zombies := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue // not a pid directory
		}

		stat, err := e.readProc(filepath.Join(entry.Name(), "stat"))
		if err != nil {
			continue // process exited between readdir and read
		}
		if state, ok := parseProcState(stat); ok && state == "Z" {
			zombies = append(zombies, entry.Name())
		}
	}

	return evaluateZombies(zombies)
}

func evaluateZombies(zombiePIDs []string) []model.Finding {
	if len(zombiePIDs) <= zombieWarnCount {
		return nil
	}

	sample := zombiePIDs
	if len(sample) > 10 {
		sample = sample[:10]
	}

	return []model.Finding{{
		ID:          "HOST-ZOM-001",
		Title:       "Zombie Process Accumulation",
		TargetType:  model.TargetHost,
		Category:    "Process Hygiene",
		Resource:    "process:zombies",
		Severity:    model.SeverityWarning,
		Symptom:     fmt.Sprintf("%d processes are in defunct (Z) state.", len(zombiePIDs)),
		RootCause:   "A parent process is not reaping its children with wait(). Each zombie holds a PID slot; unchecked growth exhausts the PID table.",
		LogEvidence: "Zombie PIDs: " + strings.Join(sample, ", "),
		RemedySteps: []string{
			"Identify the offending parent: ps -eo ppid,pid,stat,cmd | awk '$3 ~ /^Z/'",
			"Restart the parent process so the init process adopts and reaps the orphans",
			"In containers, run the app under an init shim (docker run --init / tini)",
		},
		Metadata: map[string]string{"zombie_count": strconv.Itoa(len(zombiePIDs))},
	}}
}

// -----------------------------------------------------------------------------
// HOST-NET-001 — socket table pressure (/proc/net/tcp)
// -----------------------------------------------------------------------------

// TCP connection states as encoded in the hex st column of /proc/net/tcp.
const (
	tcpStateEstablished = "01"
	tcpStateTimeWait    = "06"
)

// countTCPStates tallies connections per state code from a /proc/net/tcp body.
func countTCPStates(content string) map[string]int {
	counts := make(map[string]int)
	for i, line := range strings.Split(content, "\n") {
		if i == 0 {
			continue // header row
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		counts[fields[3]]++
	}
	return counts
}

func (e *Engine) checkSocketPressure() []model.Finding {
	counts := make(map[string]int)
	found := false

	// IPv4 and IPv6 socket tables are separate files; a dual-stack host leaks
	// through either one, so both are tallied together.
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		content, err := e.readProc(name)
		if err != nil {
			continue
		}
		found = true
		for state, n := range countTCPStates(content) {
			counts[state] += n
		}
	}

	if !found {
		return nil
	}
	return evaluateSocketPressure(counts)
}

func evaluateSocketPressure(counts map[string]int) []model.Finding {
	timeWait := counts[tcpStateTimeWait]
	established := counts[tcpStateEstablished]

	if timeWait < timeWaitWarn {
		return nil
	}

	return []model.Finding{{
		ID:         "HOST-NET-001",
		Title:      "Excessive TIME_WAIT Socket Accumulation",
		TargetType: model.TargetHost,
		Category:   "Network Saturation",
		Resource:   "socket:tcp",
		Severity:   model.SeverityWarning,
		Symptom:    fmt.Sprintf("%d sockets in TIME_WAIT (with %d established).", timeWait, established),
		RootCause:  "Short-lived outbound connections are being opened faster than the 2*MSL timer drains them. Once the ephemeral port range is exhausted new connections fail with EADDRNOTAVAIL.",
		RemedySteps: []string{
			"Enable connection pooling / HTTP keep-alive in the client application — this is the real fix",
			"Widen the ephemeral range: sysctl -w net.ipv4.ip_local_port_range='1024 65535'",
			"Allow reuse of TIME_WAIT sockets for outbound connections: sysctl -w net.ipv4.tcp_tw_reuse=1",
		},
		Metadata: map[string]string{
			"time_wait":   strconv.Itoa(timeWait),
			"established": strconv.Itoa(established),
		},
	}}
}

// -----------------------------------------------------------------------------
// HOST-MEM-001 — kernel OOM killer invocations (dmesg)
// -----------------------------------------------------------------------------

// oomKillEvent is one kernel OOM-killer termination.
type oomKillEvent struct {
	Process string
	Raw     string
}

// parseOOMKills extracts OOM-killer terminations from a kernel ring buffer dump.
// It matches the "Killed process" and "oom-kill:" lines the kernel emits, which
// name the victim, and ignores the surrounding memory dump lines.
func parseOOMKills(dmesg string) []oomKillEvent {
	events := make([]oomKillEvent, 0)

	for _, line := range strings.Split(dmesg, "\n") {
		lower := strings.ToLower(line)

		switch {
		case strings.Contains(lower, "killed process"):
			events = append(events, oomKillEvent{
				Process: extractQuotedName(line),
				Raw:     strings.TrimSpace(line),
			})
		case strings.Contains(lower, "oom-kill:"):
			events = append(events, oomKillEvent{
				Process: extractKeyValue(line, "task="),
				Raw:     strings.TrimSpace(line),
			})
		case strings.Contains(lower, "out of memory: kill process"):
			events = append(events, oomKillEvent{
				Process: extractQuotedName(line),
				Raw:     strings.TrimSpace(line),
			})
		}
	}

	return events
}

// extractQuotedName pulls the victim name out of a "Killed process 123 (nginx)"
// or "Killed process 123 (nginx) total-vm:..." style line.
func extractQuotedName(line string) string {
	if open := strings.Index(line, "("); open >= 0 {
		if close := strings.Index(line[open:], ")"); close > 0 {
			return line[open+1 : open+close]
		}
	}
	return "unknown"
}

// extractKeyValue pulls the value following key up to the next comma or space,
// as used by the modern "oom-kill:...,task=nginx,pid=..." format.
func extractKeyValue(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return "unknown"
	}
	rest := line[idx+len(key):]
	end := strings.IndexAny(rest, ", \t")
	if end < 0 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:end])
}

func (e *Engine) checkKernelOOMKiller(ctx context.Context) []model.Finding {
	if runtime.GOOS != "linux" || !e.run.Available("dmesg") {
		return nil
	}

	// -T renders human-readable timestamps; older busybox dmesg rejects it, so
	// fall back to the bare form rather than losing the check entirely.
	out, err := e.run.Run(ctx, 5*time.Second, "dmesg", "-T")
	if err != nil {
		out, err = e.run.Run(ctx, 5*time.Second, "dmesg")
		if err != nil {
			return nil // typically dmesg_restrict=1 without CAP_SYSLOG
		}
	}

	return evaluateOOMKills(parseOOMKills(string(out)))
}

func evaluateOOMKills(events []oomKillEvent) []model.Finding {
	if len(events) == 0 {
		return []model.Finding{{
			ID:         "HOST-MEM-001",
			Title:      "No Kernel OOM-Killer Activity",
			TargetType: model.TargetHost,
			Category:   "Kernel & Memory",
			Resource:   "kernel:oom",
			Severity:   model.SeverityPass,
			Symptom:    "The kernel ring buffer records no out-of-memory terminations.",
		}}
	}

	// Report per victim so an operator sees which service is actually dying,
	// rather than a single opaque count.
	victims := make(map[string]int)
	order := make([]string, 0)
	lastRaw := make(map[string]string)
	for _, ev := range events {
		if _, seen := victims[ev.Process]; !seen {
			order = append(order, ev.Process)
		}
		victims[ev.Process]++
		lastRaw[ev.Process] = ev.Raw
	}

	findings := make([]model.Finding, 0, len(order))
	for _, name := range order {
		findings = append(findings, model.Finding{
			ID:          "HOST-MEM-001",
			Title:       fmt.Sprintf("Kernel OOM-Killer Terminated Process: %s", name),
			TargetType:  model.TargetHost,
			Category:    "Kernel & Memory",
			Resource:    "process:" + name,
			Severity:    model.SeverityCritical,
			Symptom:     fmt.Sprintf("The kernel killed %q %d time(s) to reclaim memory.", name, victims[name]),
			RootCause:   "Total memory demand exceeded physical RAM plus swap, so the kernel selected the highest-scoring process and killed it. The victim is usually the biggest consumer, not necessarily the culprit.",
			LogEvidence: lastRaw[name],
			RemedySteps: []string{
				"Correlate the kill timestamp with your application metrics to find the allocation spike",
				fmt.Sprintf("Cap the service so it fails predictably instead of taking the host down: systemctl set-property %s MemoryMax=<limit>", name),
				"Add memory limits to every container on this host, and size the instance for peak, not average",
			},
			Metadata: map[string]string{"kill_count": strconv.Itoa(victims[name])},
		})
	}

	return findings
}

// -----------------------------------------------------------------------------
// HOST-KRN-001..004 — kernel tuning for data workloads (data-stack profile)
// -----------------------------------------------------------------------------

type dataStackKernelParams struct {
	MaxMapCount int64
	Swappiness  int64
	FileMax     int64
	THPEnabled  string
}

func evaluateDataStackKernel(p dataStackKernelParams) []model.Finding {
	findings := make([]model.Finding, 0)

	// 1. vm.max_map_count (required >= 262144 for MongoDB, Kafka, Elasticsearch)
	if p.MaxMapCount > 0 {
		if p.MaxMapCount < 262144 {
			findings = append(findings, model.Finding{
				ID:         "HOST-KRN-001",
				Title:      "Low vm.max_map_count for Data Workloads",
				TargetType: model.TargetHost,
				Category:   "Kernel Optimization",
				Resource:   "sysctl:vm.max_map_count",
				Severity:   model.SeverityWarning,
				Symptom:    fmt.Sprintf("vm.max_map_count is %d (expected >= 262144 for database and message broker workloads).", p.MaxMapCount),
				RootCause:  "Default Linux max_map_count is insufficient for high-concurrency memory-mapped storage engines (MongoDB WiredTiger, Apache Kafka, Elasticsearch). Workloads risk failing with out-of-memory or mmap errors under load.",
				RemedySteps: []string{
					"Set runtime limit: sysctl -w vm.max_map_count=262144",
					"Persist in /etc/sysctl.d/99-datastack.conf: echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-datastack.conf",
				},
				QuickFixCmd: "sysctl -w vm.max_map_count=262144",
				Metadata:    map[string]string{"max_map_count": strconv.FormatInt(p.MaxMapCount, 10)},
			})
		} else {
			findings = append(findings, model.Finding{
				ID:         "HOST-KRN-001",
				Title:      "vm.max_map_count Optimized",
				TargetType: model.TargetHost,
				Category:   "Kernel Optimization",
				Resource:   "sysctl:vm.max_map_count",
				Severity:   model.SeverityPass,
				Symptom:    fmt.Sprintf("vm.max_map_count is %d (>= 262144).", p.MaxMapCount),
			})
		}
	}

	// 2. vm.swappiness (expected <= 10 for low-latency databases like Postgres, Mongo, Redis)
	if p.Swappiness >= 0 {
		if p.Swappiness > 10 {
			findings = append(findings, model.Finding{
				ID:         "HOST-KRN-002",
				Title:      "Elevated vm.swappiness for Low-Latency Databases",
				TargetType: model.TargetHost,
				Category:   "Kernel Optimization",
				Resource:   "sysctl:vm.swappiness",
				Severity:   model.SeverityWarning,
				Symptom:    fmt.Sprintf("vm.swappiness is %d (recommended <= 10 for database instances).", p.Swappiness),
				RootCause:  "Default swappiness (60) causes kernel to swap anonymous memory pages to disk prematurely, causing latency spikes in transactional databases (PostgreSQL, MongoDB, Redis).",
				RemedySteps: []string{
					"Set runtime swappiness: sysctl -w vm.swappiness=1",
					"Persist in /etc/sysctl.d/99-datastack.conf: echo 'vm.swappiness=1' >> /etc/sysctl.d/99-datastack.conf",
				},
				QuickFixCmd: "sysctl -w vm.swappiness=1",
				Metadata:    map[string]string{"swappiness": strconv.FormatInt(p.Swappiness, 10)},
			})
		} else {
			findings = append(findings, model.Finding{
				ID:         "HOST-KRN-002",
				Title:      "vm.swappiness Tuned for Databases",
				TargetType: model.TargetHost,
				Category:   "Kernel Optimization",
				Resource:   "sysctl:vm.swappiness",
				Severity:   model.SeverityPass,
				Symptom:    fmt.Sprintf("vm.swappiness is %d (<= 10).", p.Swappiness),
			})
		}
	}

	// 3. Transparent Hugepages (THP)
	if p.THPEnabled != "" {
		if strings.Contains(p.THPEnabled, "[always]") {
			findings = append(findings, model.Finding{
				ID:         "HOST-KRN-003",
				Title:      "Transparent Huge Pages (THP) Enabled",
				TargetType: model.TargetHost,
				Category:   "Memory Optimization",
				Resource:   "kernel:transparent_hugepage",
				Severity:   model.SeverityWarning,
				Symptom:    "Transparent Huge Pages is set to [always].",
				RootCause:  "THP allocation compaction creates severe latency spikes and memory fragmentation in databases (MongoDB, Redis, PostgreSQL).",
				RemedySteps: []string{
					"Disable runtime THP: echo never > /sys/kernel/mm/transparent_hugepage/enabled",
					"Also disable defrag: echo never > /sys/kernel/mm/transparent_hugepage/defrag",
					"Add transparent_hugepage=never to kernel boot parameters in GRUB",
				},
				QuickFixCmd: "echo never > /sys/kernel/mm/transparent_hugepage/enabled",
			})
		} else {
			findings = append(findings, model.Finding{
				ID:         "HOST-KRN-003",
				Title:      "Transparent Huge Pages Disabled or Controlled",
				TargetType: model.TargetHost,
				Category:   "Memory Optimization",
				Resource:   "kernel:transparent_hugepage",
				Severity:   model.SeverityPass,
				Symptom:    fmt.Sprintf("THP setting is %s (not [always]).", strings.TrimSpace(p.THPEnabled)),
			})
		}
	}

	// 4. fs.file-max (open files limit)
	if p.FileMax > 0 {
		if p.FileMax < 65536 {
			findings = append(findings, model.Finding{
				ID:         "HOST-KRN-004",
				Title:      "Low System File Descriptors Limit (file-max)",
				TargetType: model.TargetHost,
				Category:   "Kernel Optimization",
				Resource:   "sysctl:fs.file-max",
				Severity:   model.SeverityWarning,
				Symptom:    fmt.Sprintf("fs.file-max is %d (expected >= 65536).", p.FileMax),
				RootCause:  "System file-max is too low for high-volume database or socket connections.",
				RemedySteps: []string{
					"Set runtime file-max: sysctl -w fs.file-max=2097152",
					"Persist in /etc/sysctl.d/99-datastack.conf",
				},
				QuickFixCmd: "sysctl -w fs.file-max=2097152",
				Metadata:    map[string]string{"file_max": strconv.FormatInt(p.FileMax, 10)},
			})
		}
	}

	return findings
}

func (e *Engine) checkKernelDataStack() []model.Finding {
	if e.profile != "data-stack" {
		return nil
	}

	params := dataStackKernelParams{
		Swappiness: -1,
	}

	if content, err := e.readProc("sys/vm/max_map_count"); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(content), 10, 64); err == nil {
			params.MaxMapCount = v
		}
	}
	if content, err := e.readProc("sys/vm/swappiness"); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(content), 10, 64); err == nil {
			params.Swappiness = v
		}
	}
	if content, err := e.readProc("sys/fs/file-max"); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(content), 10, 64); err == nil {
			params.FileMax = v
		}
	}
	if content, err := e.readSys("kernel/mm/transparent_hugepage/enabled"); err == nil {
		params.THPEnabled = content
	}

	return evaluateDataStackKernel(params)
}
