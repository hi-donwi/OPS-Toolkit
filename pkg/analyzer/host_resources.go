package analyzer

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// -----------------------------------------------------------------------------
// HOST-DSK-001 / HOST-INO-001 — storage and inode saturation
// -----------------------------------------------------------------------------

// rootFilesystemPath returns the mount point whose occupancy actually matters.
//
// On macOS "/" is a sealed, read-only system snapshot: df reports it at ~19%
// while the writable data volume sharing the same APFS container sits at 89%.
// Measuring "/" there would report ample headroom on a machine that is about to
// fail its next write.
func rootFilesystemPath() string {
	if runtime.GOOS == "darwin" {
		const dataVolume = "/System/Volumes/Data"
		if _, err := os.Stat(dataVolume); err == nil {
			return dataVolume
		}
	}
	return "/"
}

// checkDiskAndInodes runs the two storage-exhaustion rules together, because
// both read the same statfs snapshot.
func (e *Engine) checkDiskAndInodes() []model.Finding {
	path := rootFilesystemPath()

	usage, err := e.statfs(path)
	if err != nil {
		return nil
	}

	findings := evaluateDiskUsage(path, usage)
	return append(findings, evaluateInodeUsage(path, usage)...)
}

// evaluateDiskUsage scores filesystem occupancy (HOST-DSK-001).
func evaluateDiskUsage(path string, usage fsUsage) []model.Finding {
	pct := usage.UsedPercent()
	sizes := fmt.Sprintf("Total: %s, Used: %s, Available: %s",
		humanBytes(usage.TotalBytes()), humanBytes(usage.UsedBytes()), humanBytes(usage.AvailBytes()))
	meta := map[string]string{"used_percent": fmt.Sprintf("%.1f", pct)}

	switch {
	case pct >= diskCriticalPct:
		return []model.Finding{{
			ID:         "HOST-DSK-001",
			Title:      "Root Disk Usage Reached Critical Level",
			TargetType: model.TargetHost,
			Category:   "Storage Saturation",
			Resource:   "filesystem:" + path,
			Severity:   model.SeverityCritical,
			Symptom:    fmt.Sprintf("Disk usage on %s is at %.1f%% (%s)", path, pct, sizes),
			RootCause:  fmt.Sprintf("Storage capacity threshold (>%.0f%%) breached. Writes may already be failing.", diskCriticalPct),
			RemedySteps: []string{
				"Audit large directories: du -xh / 2>/dev/null | sort -h | tail -20",
				"Prune old system logs: journalctl --vacuum-size=500M",
				"Clean package manager cache and unused container images",
			},
			QuickFixCmd: "journalctl --vacuum-time=3d",
			Metadata:    meta,
		}}

	case pct >= diskWarningPct:
		return []model.Finding{{
			ID:          "HOST-DSK-001",
			Title:       "Root Disk Usage Approaching Capacity",
			TargetType:  model.TargetHost,
			Category:    "Storage Saturation",
			Resource:    "filesystem:" + path,
			Severity:    model.SeverityWarning,
			Symptom:     fmt.Sprintf("Disk usage on %s is at %.1f%% (%s)", path, pct, sizes),
			RootCause:   fmt.Sprintf("Disk capacity approaching threshold (>%.0f%%).", diskWarningPct),
			RemedySteps: []string{"Plan storage expansion, archive old logs, or prune unused container images."},
			QuickFixCmd: "docker system prune -f",
			Metadata:    meta,
		}}

	default:
		return []model.Finding{{
			ID:         "HOST-DSK-001",
			Title:      "Root Disk Space Healthy",
			TargetType: model.TargetHost,
			Category:   "Storage",
			Resource:   "filesystem:" + path,
			Severity:   model.SeverityPass,
			Symptom:    fmt.Sprintf("Disk usage on %s at %.1f%% capacity (%s)", path, pct, sizes),
		}}
	}
}

// evaluateInodeUsage scores inode table occupancy (HOST-INO-001).
//
// A filesystem can refuse to create files while df still reports free bytes,
// which is why this is a separate rule rather than a footnote on disk usage.
func evaluateInodeUsage(path string, usage fsUsage) []model.Finding {
	pct := usage.InodePercent()

	switch {
	case pct >= inodeCriticalPct:
		return []model.Finding{{
			ID:         "HOST-INO-001",
			Title:      "Inode Exhaustion Detected",
			TargetType: model.TargetHost,
			Category:   "Storage Saturation",
			Resource:   "filesystem:" + path,
			Severity:   model.SeverityCritical,
			Symptom:    fmt.Sprintf("Inode usage is at %.1f%% (%d of %d used)", pct, usage.Inodes-usage.InodesFree, usage.Inodes),
			RootCause:  "The inode table is nearly full. New files cannot be created even though free bytes remain.",
			RemedySteps: []string{
				"Locate directories holding the most files: find / -xdev -printf '%h\\n' 2>/dev/null | sort | uniq -c | sort -rn | head -20",
				"Remove orphan session and spool files under /tmp and /var/spool",
			},
			QuickFixCmd: "find /tmp -type f -atime +7 -delete",
		}}

	case pct >= inodeWarningPct:
		return []model.Finding{{
			ID:          "HOST-INO-001",
			Title:       "Inode Usage Approaching Exhaustion",
			TargetType:  model.TargetHost,
			Category:    "Storage Saturation",
			Resource:    "filesystem:" + path,
			Severity:    model.SeverityWarning,
			Symptom:     fmt.Sprintf("Inode usage is at %.1f%%", pct),
			RootCause:   "Large numbers of small files are consuming the inode table faster than disk bytes.",
			RemedySteps: []string{"Identify and rotate directories holding many small files before the table fills."},
		}}

	default:
		return nil
	}
}

// -----------------------------------------------------------------------------
// HOST-MEM-002 — memory and swap pressure (/proc/meminfo)
// -----------------------------------------------------------------------------

// meminfoStats holds the /proc/meminfo fields the memory rule needs, in kB.
type meminfoStats struct {
	MemTotal     uint64
	MemAvailable uint64
	MemFree      uint64
	SwapTotal    uint64
	SwapFree     uint64
}

// UsedPercent reports memory pressure against MemAvailable, the only field that
// accounts for reclaimable page cache. Deriving pressure from MemFree instead
// reports a healthy box as nearly out of memory.
func (m meminfoStats) UsedPercent() float64 {
	if m.MemTotal == 0 {
		return 0
	}
	avail := m.MemAvailable
	if avail == 0 {
		avail = m.MemFree
	}
	return float64(m.MemTotal-avail) / float64(m.MemTotal) * 100.0
}

// SwapUsedPercent reports how much of configured swap is consumed.
func (m meminfoStats) SwapUsedPercent() float64 {
	if m.SwapTotal == 0 {
		return 0
	}
	return float64(m.SwapTotal-m.SwapFree) / float64(m.SwapTotal) * 100.0
}

// parseMeminfo reads the kB-valued fields of a /proc/meminfo body.
func parseMeminfo(content string) meminfoStats {
	var m meminfoStats
	fields := map[string]*uint64{
		"MemTotal":     &m.MemTotal,
		"MemAvailable": &m.MemAvailable,
		"MemFree":      &m.MemFree,
		"SwapTotal":    &m.SwapTotal,
		"SwapFree":     &m.SwapFree,
	}

	for _, line := range strings.Split(content, "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		target, wanted := fields[strings.TrimSpace(key)]
		if !wanted {
			continue
		}
		valueFields := strings.Fields(rest)
		if len(valueFields) == 0 {
			continue
		}
		if v, err := strconv.ParseUint(valueFields[0], 10, 64); err == nil {
			*target = v
		}
	}

	return m
}

func (e *Engine) checkMemory() []model.Finding {
	content, err := e.readProc("meminfo")
	if err != nil {
		return nil
	}

	stats := parseMeminfo(content)
	if stats.MemTotal == 0 {
		return nil
	}

	return evaluateMemory(stats)
}

func evaluateMemory(stats meminfoStats) []model.Finding {
	findings := make([]model.Finding, 0, 2)
	pct := stats.UsedPercent()
	detail := fmt.Sprintf("Total: %s, Available: %s",
		humanBytes(stats.MemTotal*1024), humanBytes(stats.MemAvailable*1024))

	switch {
	case pct >= memCriticalPct:
		findings = append(findings, model.Finding{
			ID:         "HOST-MEM-002",
			Title:      "Host Memory Pressure Critical",
			TargetType: model.TargetHost,
			Category:   "Resource Saturation",
			Resource:   "memory:host",
			Severity:   model.SeverityCritical,
			Symptom:    fmt.Sprintf("Memory usage is at %.1f%% (%s)", pct, detail),
			RootCause:  "Available memory is nearly exhausted; the kernel OOM killer is likely to start terminating processes.",
			RemedySteps: []string{
				"Identify the largest consumers: ps aux --sort=-%mem | head -15",
				"Cap runaway services with systemd MemoryMax= or container memory limits",
				"Add swap or scale the instance vertically",
			},
			Metadata: map[string]string{"used_percent": fmt.Sprintf("%.1f", pct)},
		})
	case pct >= memWarningPct:
		findings = append(findings, model.Finding{
			ID:          "HOST-MEM-002",
			Title:       "Host Memory Usage Elevated",
			TargetType:  model.TargetHost,
			Category:    "Resource Saturation",
			Resource:    "memory:host",
			Severity:    model.SeverityWarning,
			Symptom:     fmt.Sprintf("Memory usage is at %.1f%% (%s)", pct, detail),
			RootCause:   "Memory headroom is shrinking; a traffic spike could trigger OOM kills.",
			RemedySteps: []string{"Review per-process memory growth and confirm services have explicit memory limits."},
			Metadata:    map[string]string{"used_percent": fmt.Sprintf("%.1f", pct)},
		})
	default:
		findings = append(findings, model.Finding{
			ID:         "HOST-MEM-002",
			Title:      "Host Memory Healthy",
			TargetType: model.TargetHost,
			Category:   "Resource",
			Resource:   "memory:host",
			Severity:   model.SeverityPass,
			Symptom:    fmt.Sprintf("Memory usage at %.1f%% (%s)", pct, detail),
		})
	}

	if swapPct := stats.SwapUsedPercent(); swapPct >= swapWarningPct {
		findings = append(findings, model.Finding{
			ID:          "HOST-MEM-003",
			Title:       "Heavy Swap Utilization",
			TargetType:  model.TargetHost,
			Category:    "Resource Saturation",
			Resource:    "swap:host",
			Severity:    model.SeverityWarning,
			Symptom:     fmt.Sprintf("Swap usage is at %.1f%% of %s", swapPct, humanBytes(stats.SwapTotal*1024)),
			RootCause:   "The working set no longer fits in RAM. Swapping adds disk-latency stalls to every page fault.",
			RemedySteps: []string{"Reduce resident memory or scale the instance", "Tune vm.swappiness for latency-sensitive workloads"},
		})
	}

	return findings
}

// -----------------------------------------------------------------------------
// HOST-CPU-001 — run-queue saturation (/proc/loadavg)
// -----------------------------------------------------------------------------

// parseLoadAverage extracts the 1, 5, and 15 minute load figures.
func parseLoadAverage(content string) (load1, load5, load15 float64, ok bool) {
	fields := strings.Fields(content)
	if len(fields) < 3 {
		return 0, 0, 0, false
	}
	var err error
	if load1, err = strconv.ParseFloat(fields[0], 64); err != nil {
		return 0, 0, 0, false
	}
	if load5, err = strconv.ParseFloat(fields[1], 64); err != nil {
		return 0, 0, 0, false
	}
	if load15, err = strconv.ParseFloat(fields[2], 64); err != nil {
		return 0, 0, 0, false
	}
	return load1, load5, load15, true
}

func (e *Engine) checkLoadAverage() []model.Finding {
	content, err := e.readProc("loadavg")
	if err != nil {
		return nil
	}
	load1, load5, load15, ok := parseLoadAverage(content)
	if !ok {
		return nil
	}
	return evaluateLoadAverage(load1, load5, load15, runtime.NumCPU())
}

func evaluateLoadAverage(load1, load5, load15 float64, cores int) []model.Finding {
	if cores <= 0 {
		cores = 1
	}
	perCore := load5 / float64(cores)
	detail := fmt.Sprintf("load average %.2f, %.2f, %.2f across %d cores (%.2f per core)",
		load1, load5, load15, cores, perCore)

	switch {
	case perCore >= loadCriticalMult:
		return []model.Finding{{
			ID:         "HOST-CPU-001",
			Title:      "CPU Run Queue Severely Saturated",
			TargetType: model.TargetHost,
			Category:   "Resource Saturation",
			Resource:   "cpu:host",
			Severity:   model.SeverityCritical,
			Symptom:    fmt.Sprintf("Sustained %s", detail),
			RootCause:  "Runnable processes exceed twice the available cores, so every request waits behind the scheduler queue.",
			RemedySteps: []string{
				"Identify the hot processes: ps aux --sort=-%cpu | head -15",
				"Check for uninterruptible I/O wait (state D) masquerading as CPU load: ps -eo state,pid,cmd | grep '^D'",
				"Scale horizontally or move the workload to a larger instance",
			},
			Metadata: map[string]string{"load_per_core": fmt.Sprintf("%.2f", perCore)},
		}}
	case perCore >= loadWarningMult:
		return []model.Finding{{
			ID:          "HOST-CPU-001",
			Title:       "CPU Run Queue Elevated",
			TargetType:  model.TargetHost,
			Category:    "Resource Saturation",
			Resource:    "cpu:host",
			Severity:    model.SeverityWarning,
			Symptom:     fmt.Sprintf("Sustained %s", detail),
			RootCause:   "The run queue is at or above one runnable process per core, leaving no scheduling headroom for bursts.",
			RemedySteps: []string{"Profile the top CPU consumers and confirm autoscaling thresholds are set below this point."},
			Metadata:    map[string]string{"load_per_core": fmt.Sprintf("%.2f", perCore)},
		}}
	default:
		return []model.Finding{{
			ID:         "HOST-CPU-001",
			Title:      "CPU Load Within Capacity",
			TargetType: model.TargetHost,
			Category:   "Resource",
			Resource:   "cpu:host",
			Severity:   model.SeverityPass,
			Symptom:    fmt.Sprintf("Healthy %s", detail),
		}}
	}
}
