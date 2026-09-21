package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

func writeRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

func TestLoadCustomRules(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "test-rule.yaml", `
id: "TEST-CUSTOM-001"
title: "Test Custom Rule"
target: "HOST"
severity: "WARNING"
category: "Custom Test"
resource: "test/resource"
symptom: "Test symptom"
root_cause: "Test root cause"
conditions:
  file_exists: "/bin/sh"
`)
	writeRule(t, dir, "notes.txt", "ignored, not a yaml file")

	rules, err := LoadCustomRules(dir)
	if err != nil {
		t.Fatalf("LoadCustomRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("loaded %d rules, want 1", len(rules))
	}
	if rules[0].ID != "TEST-CUSTOM-001" {
		t.Errorf("ID = %q", rules[0].ID)
	}
	if rules[0].SourceFile == "" {
		t.Error("SourceFile should record where the rule came from")
	}

	findings := (&Engine{}).EvaluateCustomRules(rules)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding since /bin/sh exists, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityWarning {
		t.Errorf("severity = %s, want WARNING", findings[0].Severity)
	}
}

func TestLoadCustomRulesMultiDocument(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "pack.yaml", `
id: "PACK-001"
title: "First"
conditions:
  file_exists: "/bin/sh"
---
id: "PACK-002"
title: "Second"
conditions:
  file_exists: "/bin/sh"
`)

	rules, err := LoadCustomRules(dir)
	if err != nil {
		t.Fatalf("LoadCustomRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("loaded %d rules from a multi-document file, want 2", len(rules))
	}
}

func TestLoadCustomRulesReportsInvalidRules(t *testing.T) {
	dir := t.TempDir()
	// No conditions: this would otherwise fire on every single run.
	writeRule(t, dir, "always.yaml", "id: \"BAD-001\"\ntitle: \"Fires always\"\n")
	writeRule(t, dir, "good.yaml", "id: \"GOOD-001\"\ntitle: \"Fine\"\nconditions:\n  file_exists: \"/bin/sh\"\n")

	rules, err := LoadCustomRules(dir)

	if err == nil {
		t.Fatal("expected an error naming the invalid rule; silently dropping it hides the typo")
	}
	if !strings.Contains(err.Error(), "BAD-001") {
		t.Errorf("error should name the offending rule, got: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "GOOD-001" {
		t.Errorf("valid rules should still load, got %+v", rules)
	}
}

func TestCustomRuleValidate(t *testing.T) {
	tests := []struct {
		name    string
		rule    CustomRule
		wantErr string
	}{
		{"missing id", CustomRule{Title: "x"}, "missing a required 'id'"},
		{"missing title", CustomRule{ID: "X"}, "missing a required 'title'"},
		{"no conditions", CustomRule{ID: "X", Title: "t"}, "declares no conditions"},
		{
			"bad regex",
			CustomRule{ID: "X", Title: "t", Conditions: CustomRuleCondition{FileExists: "/a", FileContains: "([unclosed"}},
			"invalid file_contains",
		},
		{
			"content match without a file",
			CustomRule{ID: "X", Title: "t", Conditions: CustomRuleCondition{FileContains: "abc"}},
			"does not name a file",
		},
		{
			"unknown severity",
			CustomRule{ID: "X", Title: "t", Severity: "URGENT", Conditions: CustomRuleCondition{FileExists: "/a"}},
			"unknown severity",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rule.Validate()
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestEvaluateConditionsRequiresEveryConditionToHold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	if err := os.WriteFile(path, []byte("PermitRootLogin no\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The file exists but does NOT contain the pattern. Under OR semantics the
	// existing file alone would fire the rule — reporting a problem that the
	// configuration explicitly does not have.
	matched, _ := evaluateConditions(CustomRuleCondition{
		FileExists:   path,
		FileContains: "PermitRootLogin yes",
	})
	if matched {
		t.Error("conditions must be ANDed: a matching file path alone is not a match")
	}

	matched, evidence := evaluateConditions(CustomRuleCondition{
		FileExists:   path,
		FileContains: "PermitRootLogin no",
	})
	if !matched {
		t.Fatal("expected a match when both conditions hold")
	}
	if !strings.Contains(evidence, "matches") {
		t.Errorf("evidence should record the content match, got %q", evidence)
	}
}

func TestEvaluateConditionsFileNotContains(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// file_not_contains was declared in the schema but never evaluated, so any
	// rule relying on it silently did nothing.
	matched, _ := evaluateConditions(CustomRuleCondition{
		FileExists:      path,
		FileNotContains: "PasswordAuthentication no",
	})
	if !matched {
		t.Error("file_not_contains should fire when the pattern is absent")
	}

	matched, _ = evaluateConditions(CustomRuleCondition{
		FileExists:      path,
		FileNotContains: "Port 22",
	})
	if matched {
		t.Error("file_not_contains must not fire when the pattern is present")
	}
}

func TestEvaluateConditionsEnvChecks(t *testing.T) {
	t.Setenv("OPSKIT_TEST_MODE", "production")

	matched, _ := evaluateConditions(CustomRuleCondition{EnvEquals: "OPSKIT_TEST_MODE=production"})
	if !matched {
		t.Error("env_equals should match the exported value")
	}

	matched, _ = evaluateConditions(CustomRuleCondition{EnvEquals: "OPSKIT_TEST_MODE=staging"})
	if matched {
		t.Error("env_equals must not match a different value")
	}

	matched, _ = evaluateConditions(CustomRuleCondition{EnvNotSet: "OPSKIT_TEST_MODE"})
	if matched {
		t.Error("env_not_set must not fire for a variable that is set")
	}
}

func TestBuildCustomFindingDefaults(t *testing.T) {
	f := buildCustomFinding(CustomRule{
		ID:     "X-1",
		Title:  "t",
		Target: "not-a-target",
	}, "evidence")

	if f.TargetType != model.TargetHost {
		t.Errorf("unknown target = %s, want it to fall back to HOST", f.TargetType)
	}
	if f.Severity != model.SeverityWarning {
		t.Errorf("unset severity = %s, want WARNING", f.Severity)
	}
	if f.Category != "Custom Rule" {
		t.Errorf("Category = %q, want a default", f.Category)
	}
}
