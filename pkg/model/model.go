package model

import "time"

// Severity represents the criticality level of an SRE finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL" // Service down, crashloop, data loss risk, OOM
	SeverityWarning  Severity = "WARNING"  // Resource near saturation (>85%), cert expiry < 30d
	SeverityInfo     Severity = "INFO"     // Informational findings, optimization opportunities
	SeverityPass     Severity = "PASS"     // Diagnostic check passed healthy
)

// TargetType represents the environment or subsystem being inspected.
type TargetType string

const (
	TargetHost       TargetType = "HOST"
	TargetDocker     TargetType = "DOCKER"
	TargetSwarm      TargetType = "SWARM"
	TargetKubernetes TargetType = "KUBERNETES"
	TargetK8s        TargetType = "KUBERNETES" // Alias for TargetKubernetes
	TargetSecurity   TargetType = "SECURITY"
)

// EnvironmentContext holds detected runtime environment details.
type EnvironmentContext struct {
	OS            string       `json:"os"`
	Platform      string       `json:"platform"`
	Distro        string       `json:"distro"`
	Arch          string       `json:"arch"`
	Kernel        string       `json:"kernel"`
	HasSystemd    bool         `json:"has_systemd"`
	HasDocker     bool         `json:"has_docker"`
	IsDockerSwarm bool         `json:"is_docker_swarm"`
	HasKubernetes bool         `json:"has_kubernetes"`
	ActiveTargets []TargetType `json:"active_targets"`
}

// Finding represents an individual diagnostic result or detected issue.
type Finding struct {
	ID          string            `json:"id"`          // e.g. "K8S-OOM-001"
	Title       string            `json:"title"`       // e.g. "Pod Terminated with Exit Code 137"
	TargetType  TargetType        `json:"target_type"` // HOST, DOCKER, SWARM, KUBERNETES, SECURITY
	Category    string            `json:"category"`    // e.g. "Crash & OOM", "Network", "Storage"
	Resource    string            `json:"resource"`    // e.g. "pod/payment-worker-846b-xyz"
	Namespace   string            `json:"namespace,omitempty"`
	Severity    Severity          `json:"severity"`
	Symptom     string            `json:"symptom"`                 // What was observed
	RootCause   string            `json:"root_cause"`              // Deep diagnosis / RCA
	LogEvidence string            `json:"log_evidence,omitempty"`  // Log snippet proving root cause
	RemedySteps []string          `json:"remedy_steps"`            // Recommended remediation actions
	QuickFixCmd string            `json:"quick_fix_cmd,omitempty"` // Ready-to-run mitigation command
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Summary provides a high-level counter of diagnostic findings.
type Summary struct {
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
	Pass     int `json:"pass"`
}

// Report holds the complete diagnostic evaluation result.
type Report struct {
	Title          string             `json:"title"`
	Timestamp      time.Time          `json:"timestamp"`
	Duration       string             `json:"duration"`
	Environment    EnvironmentContext `json:"environment"`
	ChecksExecuted int                `json:"checks_executed"`
	Summary        Summary            `json:"summary"`
	Findings       []Finding          `json:"findings"`
}
