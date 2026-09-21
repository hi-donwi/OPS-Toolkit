package analyzer

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
	"gopkg.in/yaml.v3"
)

// CustomRuleCondition defines the tests a custom rule evaluates.
//
// Every condition that is set must hold for the rule to fire. Conditions are
// ANDed, not ORed: a rule that names both a file and a pattern describes one
// situation ("this file contains this string"), not two independent alarms.
type CustomRuleCondition struct {
	FileExists      string `yaml:"file_exists,omitempty"`
	FileContains    string `yaml:"file_contains,omitempty"`
	FileNotContains string `yaml:"file_not_contains,omitempty"`
	PortListening   int    `yaml:"port_listening,omitempty"`
	EnvNotSet       string `yaml:"env_not_set,omitempty"`
	EnvEquals       string `yaml:"env_equals,omitempty"`
	CommandExists   string `yaml:"command_exists,omitempty"`
}

// IsEmpty reports whether the rule specifies no condition at all. Such a rule
// would fire unconditionally on every run, which is never what an author meant.
func (c CustomRuleCondition) IsEmpty() bool {
	return c.FileExists == "" && c.FileContains == "" && c.FileNotContains == "" &&
		c.PortListening == 0 && c.EnvNotSet == "" && c.EnvEquals == "" && c.CommandExists == ""
}

// CustomRule is a user-authored diagnostic or security rule loaded from YAML.
type CustomRule struct {
	ID          string              `yaml:"id"`
	Title       string              `yaml:"title"`
	Target      string              `yaml:"target"`
	Severity    string              `yaml:"severity"`
	Category    string              `yaml:"category"`
	Resource    string              `yaml:"resource"`
	Symptom     string              `yaml:"symptom"`
	RootCause   string              `yaml:"root_cause"`
	RemedySteps []string            `yaml:"remedy_steps"`
	QuickFixCmd string              `yaml:"quick_fix_cmd,omitempty"`
	Conditions  CustomRuleCondition `yaml:"conditions"`

	// SourceFile records where the rule came from, for error reporting.
	SourceFile string `yaml:"-"`
}

// Validate reports why a rule cannot be used, or nil when it is usable.
func (r CustomRule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("rule is missing a required 'id'")
	}
	if strings.TrimSpace(r.Title) == "" {
		return fmt.Errorf("rule %q is missing a required 'title'", r.ID)
	}
	if r.Conditions.IsEmpty() {
		return fmt.Errorf("rule %q declares no conditions and would fire on every run", r.ID)
	}
	if r.Conditions.FileContains != "" {
		if _, err := regexp.Compile(r.Conditions.FileContains); err != nil {
			return fmt.Errorf("rule %q has an invalid file_contains pattern: %w", r.ID, err)
		}
	}
	if r.Conditions.FileNotContains != "" {
		if _, err := regexp.Compile(r.Conditions.FileNotContains); err != nil {
			return fmt.Errorf("rule %q has an invalid file_not_contains pattern: %w", r.ID, err)
		}
	}
	if (r.Conditions.FileContains != "" || r.Conditions.FileNotContains != "") && r.Conditions.FileExists == "" {
		return fmt.Errorf("rule %q uses a content match but does not name a file via 'file_exists'", r.ID)
	}
	if r.Severity != "" && !validSeverity(r.Severity) {
		return fmt.Errorf("rule %q has unknown severity %q (want CRITICAL, WARNING, INFO, or PASS)", r.ID, r.Severity)
	}
	return nil
}

func validSeverity(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL", "WARNING", "INFO", "PASS":
		return true
	}
	return false
}

// LoadCustomRules reads every .yaml/.yml rule in dir. A file may hold multiple
// rules separated by YAML document markers. Rules that fail validation are
// skipped and reported through the returned error so a typo surfaces instead of
// silently disabling the rule.
func LoadCustomRules(dir string) ([]CustomRule, error) {
	rules := make([]CustomRule, 0)
	if _, err := os.Stat(dir); err != nil {
		return rules, nil // an absent rules directory is not an error
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return rules, err
	}

	problems := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if ext := filepath.Ext(entry.Name()); ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
			continue
		}

		for _, doc := range splitYAMLDocuments(string(data)) {
			if strings.TrimSpace(doc) == "" {
				continue
			}

			var rule CustomRule
			if err := yaml.Unmarshal([]byte(doc), &rule); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", path, err))
				continue
			}
			rule.SourceFile = path

			if err := rule.Validate(); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", path, err))
				continue
			}
			rules = append(rules, rule)
		}
	}

	if len(problems) > 0 {
		return rules, fmt.Errorf("skipped %d invalid custom rule(s): %s", len(problems), strings.Join(problems, "; "))
	}
	return rules, nil
}

// splitYAMLDocuments splits a multi-document YAML stream on `---` separators.
func splitYAMLDocuments(content string) []string {
	lines := strings.Split(content, "\n")
	docs := make([]string, 0, 1)
	current := make([]string, 0, len(lines))

	for _, line := range lines {
		if strings.TrimRight(line, " \t") == "---" {
			docs = append(docs, strings.Join(current, "\n"))
			current = current[:0]
			continue
		}
		current = append(current, line)
	}
	docs = append(docs, strings.Join(current, "\n"))

	return docs
}

// EvaluateCustomRules evaluates user rules against the system. A rule fires only
// when every condition it declares holds.
func (e *Engine) EvaluateCustomRules(rules []CustomRule) []model.Finding {
	findings := make([]model.Finding, 0)

	for _, r := range rules {
		matched, evidence := evaluateConditions(r.Conditions)
		if !matched {
			continue
		}
		findings = append(findings, buildCustomFinding(r, evidence))
	}

	return findings
}

// evaluateConditions reports whether every declared condition holds, along with
// the evidence for each one that did.
func evaluateConditions(cond CustomRuleCondition) (bool, string) {
	evidence := make([]string, 0, 4)

	// File content is read once and reused by both content conditions.
	var content []byte
	if cond.FileExists != "" {
		info, err := os.Stat(cond.FileExists)
		if err != nil {
			return false, ""
		}
		evidence = append(evidence, fmt.Sprintf("file %s exists", cond.FileExists))

		if cond.FileContains != "" || cond.FileNotContains != "" {
			if info.IsDir() {
				return false, ""
			}
			if content, err = os.ReadFile(cond.FileExists); err != nil {
				return false, ""
			}
		}
	}

	if cond.FileContains != "" {
		re, err := regexp.Compile(cond.FileContains)
		if err != nil || !re.Match(content) {
			return false, ""
		}
		evidence = append(evidence, fmt.Sprintf("file %s matches %q", cond.FileExists, cond.FileContains))
	}

	if cond.FileNotContains != "" {
		re, err := regexp.Compile(cond.FileNotContains)
		if err != nil || re.Match(content) {
			return false, ""
		}
		evidence = append(evidence, fmt.Sprintf("file %s does not match %q", cond.FileExists, cond.FileNotContains))
	}

	if cond.PortListening > 0 {
		portStr := strconv.Itoa(cond.PortListening)
		addr := net.JoinHostPort("127.0.0.1", portStr)
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			// Try IPv6 loopback
			addr = net.JoinHostPort("::1", portStr)
			conn, err = net.DialTimeout("tcp", addr, 200*time.Millisecond)
		}
		if err != nil {
			return false, ""
		}
		_ = conn.Close()
		evidence = append(evidence, fmt.Sprintf("port %d is accepting TCP connections", cond.PortListening))
	}

	if cond.EnvNotSet != "" {
		if os.Getenv(cond.EnvNotSet) != "" {
			return false, ""
		}
		evidence = append(evidence, fmt.Sprintf("environment variable %s is not set", cond.EnvNotSet))
	}

	if cond.EnvEquals != "" {
		name, want, ok := strings.Cut(cond.EnvEquals, "=")
		if !ok || os.Getenv(strings.TrimSpace(name)) != want {
			return false, ""
		}
		evidence = append(evidence, fmt.Sprintf("environment variable %s equals %q", strings.TrimSpace(name), want))
	}

	if cond.CommandExists != "" {
		if !commandExists(cond.CommandExists) {
			return false, ""
		}
		evidence = append(evidence, fmt.Sprintf("command %s is present in PATH", cond.CommandExists))
	}

	if len(evidence) == 0 {
		return false, ""
	}
	return true, strings.Join(evidence, "; ")
}

// commandExists reports whether name resolves in PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// buildCustomFinding converts a matched rule into a Finding.
func buildCustomFinding(r CustomRule, evidence string) model.Finding {
	severity := model.SeverityWarning
	switch strings.ToUpper(strings.TrimSpace(r.Severity)) {
	case "CRITICAL":
		severity = model.SeverityCritical
	case "INFO":
		severity = model.SeverityInfo
	case "PASS":
		severity = model.SeverityPass
	}

	target := model.TargetType(strings.ToUpper(strings.TrimSpace(r.Target)))
	switch target {
	case model.TargetHost, model.TargetDocker, model.TargetSwarm, model.TargetKubernetes, model.TargetSecurity:
	default:
		target = model.TargetHost
	}

	category := r.Category
	if category == "" {
		category = "Custom Rule"
	}

	return model.Finding{
		ID:          r.ID,
		Title:       r.Title,
		TargetType:  target,
		Category:    category,
		Resource:    r.Resource,
		Severity:    severity,
		Symptom:     r.Symptom,
		RootCause:   r.RootCause,
		LogEvidence: evidence,
		RemedySteps: r.RemedySteps,
		QuickFixCmd: r.QuickFixCmd,
		Metadata:    map[string]string{"rule_source": r.SourceFile},
	}
}
