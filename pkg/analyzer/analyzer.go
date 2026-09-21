// Package analyzer holds the opskit rule engine: it turns raw host, container,
// and cluster telemetry into scored model.Finding results with root-cause
// analysis and remediation guidance.
//
// Rules are grouped per target (host, docker, swarm, kubernetes, security). Each
// group is split into a thin collector that shells out through sysexec.Runner
// and a pure evaluator that scores already-collected text. Only the collectors
// touch the machine, so every rule stays unit-testable against fixtures.
package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"github.com/hi-donwi/OPS-Toolkit/pkg/sysexec"
)

// Engine orchestrates diagnostic rule evaluation across targets.
type Engine struct {
	env model.EnvironmentContext
	run sysexec.Runner

	// procRoot is the mount point of procfs. Tests point it at a fixture tree.
	procRoot string
	// statfs reports filesystem usage; swapped out in tests.
	statfs func(path string) (fsUsage, error)
	// now supplies the clock, so time-sensitive rules stay deterministic.
	now func() time.Time
	// lookupHost resolves a hostname; swapped out to keep tests offline.
	lookupHost func(ctx context.Context, host string) ([]string, error)
}

// Option customizes an Engine. Tests use these to run hermetically.
type Option func(*Engine)

// WithRunner replaces the external-command runner.
func WithRunner(r sysexec.Runner) Option { return func(e *Engine) { e.run = r } }

// WithProcRoot points procfs reads at an alternate tree.
func WithProcRoot(root string) Option { return func(e *Engine) { e.procRoot = root } }

// WithClock replaces the time source.
func WithClock(now func() time.Time) Option { return func(e *Engine) { e.now = now } }

// WithStatfs replaces the filesystem usage probe.
func WithStatfs(fn func(path string) (fsUsage, error)) Option {
	return func(e *Engine) { e.statfs = fn }
}

// WithResolver replaces the DNS resolver used by the host DNS rule.
func WithResolver(fn func(ctx context.Context, host string) ([]string, error)) Option {
	return func(e *Engine) { e.lookupHost = fn }
}

// DefaultProcRoot is the procfs mount point.
const DefaultProcRoot = "/proc"

// ProcRootFromEnv returns the procfs root to read host telemetry from.
//
// Inside a container, "/proc" is the container's own view: its meminfo, load
// average, mounts, and socket tables describe the container, not the node. The
// DaemonSet and Swarm manifests therefore bind-mount the host's /proc and set
// OPSKIT_PROC_ROOT so the host rules measure the machine they are deployed to
// diagnose.
func ProcRootFromEnv() string {
	if custom := strings.TrimSpace(os.Getenv("OPSKIT_PROC_ROOT")); custom != "" {
		return custom
	}
	if custom := strings.TrimSpace(os.Getenv("OPSKIT_PROC_ROOT")); custom != "" {
		return custom
	}
	return DefaultProcRoot
}

// NewEngine creates an analyzer engine bound to a detected environment.
func NewEngine(env model.EnvironmentContext, opts ...Option) *Engine {
	e := &Engine{
		env:        env,
		run:        sysexec.Real{},
		procRoot:   ProcRootFromEnv(),
		statfs:     statfsUsage,
		now:        time.Now,
		lookupHost: defaultLookupHost,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// RunDiagnostics executes diagnostic rules matching the requested target filter.
// Targets are evaluated concurrently for maximum diagnostic speed.
// Cancelling ctx aborts in-flight external commands and stops further rules.
func (e *Engine) RunDiagnostics(ctx context.Context, targetFilter model.TargetType, namespace string) (*model.Report, error) {
	start := e.now()
	report := &model.Report{
		Title:       "SRE Diagnostic & Health Evaluation",
		Timestamp:   start,
		Environment: e.env,
		Findings:    make([]model.Finding, 0),
	}

	targets := e.env.ActiveTargets
	if targetFilter != "" {
		targets = []model.TargetType{targetFilter}
	}

	results := make([][]model.Finding, len(targets))
	var wg sync.WaitGroup

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for i, target := range targets {
		i, target := i, target
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
			}
			switch target {
			case model.TargetHost:
				results[i] = e.evaluateHost(ctx)
			case model.TargetDocker:
				results[i] = e.evaluateDocker(ctx)
			case model.TargetSwarm:
				results[i] = e.evaluateSwarm(ctx)
			case model.TargetKubernetes:
				results[i] = e.evaluateKubernetes(ctx, namespace)
			case model.TargetSecurity:
				results[i] = e.evaluateSecurity(ctx)
			}
		}()
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for _, res := range results {
		report.Findings = append(report.Findings, res...)
	}

	report.Findings = append(report.Findings, e.evaluateCustomRuleDirs(targetFilter)...)

	sortFindings(report.Findings)
	report.Summary = Summarize(report.Findings)
	report.Duration = e.now().Sub(start).Round(time.Millisecond).String()

	return report, nil
}

// evaluateCustomRuleDirs loads user rules from ./rules.d and ~/.opskit/rules.d,
// filtered by targetFilter if specified.
func (e *Engine) evaluateCustomRuleDirs(targetFilter model.TargetType) []model.Finding {
	rules, err := LoadCustomRules("rules.d")
	var problems []string
	if err != nil {
		problems = append(problems, err.Error())
	}
	if home, errHome := os.UserHomeDir(); errHome == nil {
		homeDir := filepath.Join(home, ".opskit", "rules.d")
		homeRules, errLoad := LoadCustomRules(homeDir)
		if errLoad != nil {
			problems = append(problems, errLoad.Error())
		}
		rules = append(rules, homeRules...)
	}

	var findings []model.Finding
	for _, prob := range problems {
		findings = append(findings, model.Finding{
			ID:         "RULE-PARSE-ERR",
			Title:      "Custom Rule Syntax or Validation Error",
			TargetType: model.TargetHost,
			Category:   "Custom Rules",
			Resource:   "rules.d",
			Severity:   model.SeverityWarning,
			Symptom:    prob,
			RootCause:  "A custom rule YAML file contains invalid YAML syntax or fails schema validation.",
			RemedySteps: []string{
				"Check the YAML syntax in rules.d/",
				"Verify required fields: 'id', 'title', and at least one condition",
			},
		})
	}

	if len(rules) == 0 {
		return findings
	}

	if targetFilter != "" {
		filtered := make([]CustomRule, 0, len(rules))
		for _, r := range rules {
			t := model.TargetType(strings.ToUpper(strings.TrimSpace(r.Target)))
			if t == "" {
				t = model.TargetHost
			}
			if t == targetFilter {
				filtered = append(filtered, r)
			}
		}
		rules = filtered
	}

	findings = append(findings, e.EvaluateCustomRules(rules)...)
	return findings
}

// Summarize counts findings per severity.
func Summarize(findings []model.Finding) model.Summary {
	var s model.Summary
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			s.Critical++
		case model.SeverityWarning:
			s.Warning++
		case model.SeverityInfo:
			s.Info++
		case model.SeverityPass:
			s.Pass++
		}
	}
	return s
}

// severityRank orders severities most-urgent first for reporting.
func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 0
	case model.SeverityWarning:
		return 1
	case model.SeverityInfo:
		return 2
	default:
		return 3
	}
}

// sortFindings puts the most urgent findings first while keeping the relative
// order of equally severe ones deterministic across concurrent runs.
func sortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if findings[i].TargetType != findings[j].TargetType {
			return findings[i].TargetType < findings[j].TargetType
		}
		return findings[i].ID < findings[j].ID
	})
}
