package analyzer

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

func TestParseMeminfo(t *testing.T) {
	const sample = `MemTotal:       16316948 kB
MemFree:          193232 kB
MemAvailable:    1642148 kB
Buffers:          104308 kB
Cached:          2185928 kB
SwapTotal:       2097148 kB
SwapFree:        1048576 kB
`

	stats := parseMeminfo(sample)

	if stats.MemTotal != 16316948 {
		t.Errorf("MemTotal = %d, want 16316948", stats.MemTotal)
	}
	if stats.MemAvailable != 1642148 {
		t.Errorf("MemAvailable = %d, want 1642148", stats.MemAvailable)
	}
	if stats.SwapTotal != 2097148 || stats.SwapFree != 1048576 {
		t.Errorf("swap = %d/%d, want 2097148/1048576", stats.SwapFree, stats.SwapTotal)
	}

	// Pressure must be computed from MemAvailable, not MemFree. Using MemFree
	// here would report 98.8% and page on a perfectly healthy host.
	if got := stats.UsedPercent(); got < 89.5 || got > 90.5 {
		t.Errorf("UsedPercent() = %.2f, want ~89.9 (derived from MemAvailable)", got)
	}
	if got := stats.SwapUsedPercent(); got < 49.5 || got > 50.5 {
		t.Errorf("SwapUsedPercent() = %.2f, want ~50", got)
	}
}

func TestParseMeminfoFallsBackToMemFree(t *testing.T) {
	// Kernels before 3.14 do not publish MemAvailable.
	stats := parseMeminfo("MemTotal: 1000 kB\nMemFree: 400 kB\n")

	if got := stats.UsedPercent(); got != 60 {
		t.Errorf("UsedPercent() = %.2f, want 60 when MemAvailable is absent", got)
	}
}

func TestEvaluateMemorySeverity(t *testing.T) {
	tests := []struct {
		name     string
		total    uint64
		avail    uint64
		expected model.Severity
	}{
		{"healthy", 1000, 500, model.SeverityPass},
		{"warning at 85%", 1000, 150, model.SeverityWarning},
		{"critical at 92%", 1000, 80, model.SeverityCritical},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := evaluateMemory(meminfoStats{MemTotal: tc.total, MemAvailable: tc.avail})
			if len(findings) == 0 {
				t.Fatal("expected a memory finding")
			}
			if findings[0].Severity != tc.expected {
				t.Errorf("severity = %s, want %s", findings[0].Severity, tc.expected)
			}
			if findings[0].ID != "HOST-MEM-002" {
				t.Errorf("ID = %s, want HOST-MEM-002", findings[0].ID)
			}
		})
	}
}

func TestParseLoadAverage(t *testing.T) {
	load1, load5, load15, ok := parseLoadAverage("2.15 1.87 1.42 3/1523 88291\n")
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if load1 != 2.15 || load5 != 1.87 || load15 != 1.42 {
		t.Errorf("got %.2f %.2f %.2f, want 2.15 1.87 1.42", load1, load5, load15)
	}

	if _, _, _, ok := parseLoadAverage("garbage"); ok {
		t.Error("expected malformed loadavg to be rejected")
	}
}

func TestEvaluateLoadAverageScalesWithCores(t *testing.T) {
	// The same absolute load is healthy on 16 cores and critical on 2.
	onManyCores := evaluateLoadAverage(4, 4, 4, 16)
	if onManyCores[0].Severity != model.SeverityPass {
		t.Errorf("load 4 on 16 cores = %s, want PASS", onManyCores[0].Severity)
	}

	onFewCores := evaluateLoadAverage(4, 4, 4, 2)
	if onFewCores[0].Severity != model.SeverityCritical {
		t.Errorf("load 4 on 2 cores = %s, want CRITICAL", onFewCores[0].Severity)
	}
}

func TestParseMounts(t *testing.T) {
	const sample = `sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0
/dev/sdb1 /data ext4 ro,relatime 0 0
tmpfs /run/lock tmpfs ro,nosuid,nodev,noexec 0 0
`

	mounts := parseMounts(sample)
	if len(mounts) != 4 {
		t.Fatalf("parsed %d mounts, want 4", len(mounts))
	}
	if !mounts[2].ReadOnly() {
		t.Error("/data should be detected as read-only")
	}
	if mounts[1].ReadOnly() {
		t.Error("/ is rw and must not be flagged (errors=remount-ro is a policy, not a state)")
	}
}

func TestEvaluateReadOnlyMountsIgnoresPseudoFilesystems(t *testing.T) {
	mounts := parseMounts(`sysfs /sys sysfs ro,nosuid 0 0
tmpfs /run/lock tmpfs ro,nosuid 0 0
/dev/sdb1 /data ext4 ro,relatime 0 0
`)

	findings := evaluateReadOnlyMounts(mounts)

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want exactly 1 (only the real ext4 mount)", len(findings))
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Errorf("severity = %s, want CRITICAL", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Resource, "/data") {
		t.Errorf("resource = %s, want it to name /data", findings[0].Resource)
	}
}

func TestEvaluateReadOnlyMountsPassesWhenAllWritable(t *testing.T) {
	findings := evaluateReadOnlyMounts(parseMounts("/dev/sda1 / ext4 rw,relatime 0 0\n"))

	if len(findings) != 1 || findings[0].Severity != model.SeverityPass {
		t.Fatalf("expected a single PASS finding, got %+v", findings)
	}
}

func TestParseProcState(t *testing.T) {
	tests := []struct {
		name string
		stat string
		want string
	}{
		{"simple", "1234 (bash) S 1 1234 1234 0 -1", "S"},
		{"zombie", "4321 (defunct) Z 1 4321", "Z"},
		// A process can rename itself to anything, including text with spaces
		// and parentheses. Splitting on whitespace reads the wrong column.
		{"parens in comm", "99 (my (weird) proc) R 1 99", "R"},
		{"spaces in comm", "77 (Web Content) S 1 77", "S"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseProcState(tc.stat)
			if !ok {
				t.Fatalf("parse failed for %q", tc.stat)
			}
			if got != tc.want {
				t.Errorf("state = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEvaluateZombiesThreshold(t *testing.T) {
	few := make([]string, zombieWarnCount)
	if got := evaluateZombies(few); len(got) != 0 {
		t.Errorf("expected no finding at the threshold, got %d", len(got))
	}

	many := make([]string, zombieWarnCount+1)
	for i := range many {
		many[i] = "100"
	}
	if got := evaluateZombies(many); len(got) != 1 {
		t.Errorf("expected a finding above the threshold, got %d", len(got))
	}
}

func TestCountTCPStates(t *testing.T) {
	const sample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000
   1: 0100007F:8B32 0100007F:1F90 01 00000000:00000000 00:00000000 00000000
   2: 0100007F:8B33 0100007F:1F90 06 00000000:00000000 00:00000000 00000000
   3: 0100007F:8B34 0100007F:1F90 06 00000000:00000000 00:00000000 00000000
`

	counts := countTCPStates(sample)

	if counts[tcpStateTimeWait] != 2 {
		t.Errorf("TIME_WAIT = %d, want 2", counts[tcpStateTimeWait])
	}
	if counts[tcpStateEstablished] != 1 {
		t.Errorf("ESTABLISHED = %d, want 1", counts[tcpStateEstablished])
	}
}

func TestEvaluateSocketPressure(t *testing.T) {
	quiet := evaluateSocketPressure(map[string]int{tcpStateTimeWait: 100})
	if len(quiet) != 0 {
		t.Errorf("expected no finding below the threshold, got %d", len(quiet))
	}

	saturated := evaluateSocketPressure(map[string]int{
		tcpStateTimeWait:    timeWaitWarn + 1,
		tcpStateEstablished: 42,
	})
	if len(saturated) != 1 {
		t.Fatalf("expected one finding, got %d", len(saturated))
	}
	if saturated[0].ID != "HOST-NET-001" {
		t.Errorf("ID = %s, want HOST-NET-001", saturated[0].ID)
	}
}

func TestParseOOMKills(t *testing.T) {
	const dmesg = `[Mon Sep  1 10:00:01 2026] some unrelated kernel message
[Mon Sep  1 10:22:14 2026] node invoked oom-killer: gfp_mask=0x100cca
[Mon Sep  1 10:22:14 2026] Out of memory: Killed process 21534 (node) total-vm:4194304kB
[Mon Sep  1 11:02:44 2026] oom-kill:constraint=CONSTRAINT_MEMCG,task=postgres,pid=8812
`

	events := parseOOMKills(dmesg)

	if len(events) != 2 {
		t.Fatalf("parsed %d OOM events, want 2: %+v", len(events), events)
	}
	if events[0].Process != "node" {
		t.Errorf("first victim = %q, want %q", events[0].Process, "node")
	}
	if events[1].Process != "postgres" {
		t.Errorf("second victim = %q, want %q", events[1].Process, "postgres")
	}
}

func TestEvaluateOOMKillsGroupsByVictim(t *testing.T) {
	events := []oomKillEvent{
		{Process: "node", Raw: "first"},
		{Process: "node", Raw: "second"},
		{Process: "postgres", Raw: "third"},
	}

	findings := evaluateOOMKills(events)

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per distinct victim)", len(findings))
	}
	if findings[0].Metadata["kill_count"] != "2" {
		t.Errorf("node kill_count = %q, want 2", findings[0].Metadata["kill_count"])
	}
	for _, f := range findings {
		if f.Severity != model.SeverityCritical {
			t.Errorf("%s severity = %s, want CRITICAL", f.ID, f.Severity)
		}
	}
}

func TestEvaluateOOMKillsPassesWhenClean(t *testing.T) {
	findings := evaluateOOMKills(nil)
	if len(findings) != 1 || findings[0].Severity != model.SeverityPass {
		t.Fatalf("expected a single PASS finding, got %+v", findings)
	}
}

func TestParseFailedUnits(t *testing.T) {
	const sample = `nginx.service loaded failed failed A high performance web server
redis-server.service loaded failed failed Advanced key-value store
`

	units := parseFailedUnits(sample)

	if len(units) != 2 {
		t.Fatalf("parsed %d units, want 2", len(units))
	}
	if units[0] != "nginx.service" || units[1] != "redis-server.service" {
		t.Errorf("units = %v", units)
	}
}

func TestParseFailedUnitsIgnoresEmptyOutput(t *testing.T) {
	if units := parseFailedUnits("\n  \n"); len(units) != 0 {
		t.Errorf("expected no units from blank output, got %v", units)
	}
}

func TestFsUsageMatchesDfSemantics(t *testing.T) {
	// 1000 blocks total, 100 free to root, 50 available to a normal user.
	// df reports used/(used+avail) = 900/950 = 94.7%, not 900/1000 = 90%.
	// The reserved pool is not headroom for an application.
	u := fsUsage{BlockSize: 4096, Blocks: 1000, BlocksFree: 100, BlocksAvail: 50}

	if got := u.UsedPercent(); got < 94.6 || got > 94.8 {
		t.Errorf("UsedPercent() = %.2f, want ~94.7 (df semantics)", got)
	}
	if u.AvailBytes() != 50*4096 {
		t.Errorf("AvailBytes() = %d, want %d", u.AvailBytes(), 50*4096)
	}
}

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{512, "512 B"},
		{2048, "2.0 KiB"},
		{5 * 1024 * 1024, "5.0 MiB"},
		{3 * 1024 * 1024 * 1024, "3.0 GiB"},
	}

	for _, tc := range tests {
		if got := humanBytes(tc.in); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRootFilesystemPathTargetsWritableVolume(t *testing.T) {
	path := rootFilesystemPath()

	switch runtime.GOOS {
	case "darwin":
		// "/" on macOS is a sealed read-only snapshot reporting ~19% while the
		// writable volume beside it sits at 89%.
		if _, err := os.Stat("/System/Volumes/Data"); err == nil {
			if path != "/System/Volumes/Data" {
				t.Errorf("path = %q, want the writable data volume on macOS", path)
			}
		}
	default:
		if path != "/" {
			t.Errorf("path = %q, want / on %s", path, runtime.GOOS)
		}
	}
}
