package analyzer

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// Host rule thresholds. Collected here so operators can see every trip point in
// one place rather than hunting through the evaluators.
const (
	diskCriticalPct  = 90.0
	diskWarningPct   = 80.0
	inodeCriticalPct = 90.0
	inodeWarningPct  = 80.0
	memCriticalPct   = 92.0
	memWarningPct    = 85.0
	swapWarningPct   = 60.0
	loadCriticalMult = 2.0 // load1 per core
	loadWarningMult  = 1.0
	zombieWarnCount  = 5
	timeWaitWarn     = 10000
	dnsSlowThreshold = 400 * time.Millisecond
)

func defaultLookupHost(ctx context.Context, host string) ([]string, error) {
	var r net.Resolver
	return r.LookupHost(ctx, host)
}

// evaluateHost runs every HOST-* rule.
func (e *Engine) evaluateHost(ctx context.Context) []model.Finding {
	findings := make([]model.Finding, 0, 12)

	findings = append(findings, e.checkDiskAndInodes()...)
	findings = append(findings, e.checkMemory()...)
	findings = append(findings, e.checkLoadAverage()...)
	findings = append(findings, e.checkReadOnlyMounts()...)
	findings = append(findings, e.checkZombieProcesses()...)
	findings = append(findings, e.checkSocketPressure()...)
	findings = append(findings, e.checkKernelOOMKiller(ctx)...)
	findings = append(findings, e.checkDNS(ctx)...)
	findings = append(findings, e.checkSystemdUnits(ctx)...)

	return findings
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// readProc reads a file relative to the configured procfs root.
func (e *Engine) readProc(name string) (string, error) {
	data, err := os.ReadFile(filepath.Join(e.procRoot, name))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// humanBytes renders a byte count in the largest unit that keeps it readable.
func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTP"[exp])
}
