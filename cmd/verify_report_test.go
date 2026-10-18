package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

const completeReport = `{"checks_executed":1,"collection_errors":0,"summary":{"pass":1},"findings":[{"id":"HOST-DSK-001","target_type":"HOST","severity":"PASS"}]}`

func runSavedReport(t *testing.T, input string, args ...string) error {
	t.Helper()
	for _, flags := range []*pflag.FlagSet{verifyCmd.Flags(), RootCmd.PersistentFlags()} {
		flags.VisitAll(func(flag *pflag.Flag) {
			value, changed := flag.Value.String(), flag.Changed
			if slice, ok := flag.Value.(pflag.SliceValue); ok {
				values := append([]string(nil), slice.GetSlice()...)
				t.Cleanup(func() { _ = slice.Replace(values); flag.Changed = changed })
			} else {
				t.Cleanup(func() { _ = flag.Value.Set(value); flag.Changed = changed })
			}
		})
	}
	RootCmd.SetIn(strings.NewReader(input))
	RootCmd.SetArgs(append([]string{"verify", "--report", "-", "--no-color"}, args...))
	oldUsage, oldErrors := RootCmd.SilenceUsage, RootCmd.SilenceErrors
	RootCmd.SilenceUsage, RootCmd.SilenceErrors = true, true
	t.Cleanup(func() {
		RootCmd.SetIn(nil)
		RootCmd.SetArgs(nil)
		RootCmd.SilenceUsage, RootCmd.SilenceErrors = oldUsage, oldErrors
	})
	return RootCmd.Execute()
}

func TestVerifySavedReport(t *testing.T) {
	warning := strings.ReplaceAll(strings.ReplaceAll(completeReport, `"pass":1`, `"warning":1`), `"PASS"`, `"WARNING"`)
	info := strings.ReplaceAll(strings.ReplaceAll(completeReport, `"pass":1`, `"info":1`), `"PASS"`, `"INFO"`)
	critical := strings.ReplaceAll(strings.ReplaceAll(completeReport, `"pass":1`, `"critical":1`), `"PASS"`, `"CRITICAL"`)
	tests := []struct {
		name   string
		report string
		args   []string
		code   int
	}{
		{"complete healthy report", completeReport, []string{"--target", "host", "--require-rule", "HOST-DSK-001"}, 0},
		{"warning below critical", warning, nil, 0},
		{"warning breaches warning", warning, []string{"--fail-on", "warning"}, 1},
		{"critical breaches critical", critical, nil, 1},
		{"info below warning", info, []string{"--fail-on", "warning"}, 0},
		{"info breaches info", info, []string{"--fail-on", "info"}, 1},
		{"empty input", "", nil, 2},
		{"null report", "null", nil, 2},
		{"empty report", "{}", nil, 2},
		{"truncated JSON", completeReport[:len(completeReport)-1], nil, 2},
		{"trailing JSON", completeReport + "{}", nil, 2},
		{"missing collection errors", strings.ReplaceAll(completeReport, `"collection_errors":0,`, ""), nil, 2},
		{"null collection errors", strings.ReplaceAll(completeReport, `"collection_errors":0`, `"collection_errors":null`), nil, 2},
		{"collection failed", strings.ReplaceAll(completeReport, `"collection_errors":0`, `"collection_errors":1`), nil, 2},
		{"negative collection errors", strings.ReplaceAll(completeReport, `"collection_errors":0`, `"collection_errors":-1`), nil, 2},
		{"hidden collection failure", strings.ReplaceAll(completeReport, `"severity":"PASS"`, `"severity":"PASS","metadata":{"collection_error":"true"}`), nil, 2},
		{"missing check count", strings.ReplaceAll(completeReport, `"checks_executed":1,`, ""), nil, 2},
		{"zero check count", strings.ReplaceAll(completeReport, `"checks_executed":1`, `"checks_executed":0`), nil, 2},
		{"negative check count", strings.ReplaceAll(completeReport, `"checks_executed":1`, `"checks_executed":-1`), nil, 2},
		{"inconsistent check count", strings.ReplaceAll(completeReport, `"checks_executed":1`, `"checks_executed":2`), nil, 2},
		{"missing findings", `{"checks_executed":1,"collection_errors":0,"summary":{"pass":1}}`, nil, 2},
		{"empty findings", `{"checks_executed":1,"collection_errors":0,"summary":{"pass":1},"findings":[]}`, nil, 2},
		{"null findings", `{"checks_executed":1,"collection_errors":0,"summary":{"pass":1},"findings":null}`, nil, 2},
		{"missing summary", strings.ReplaceAll(completeReport, `"summary":{"pass":1},`, ""), nil, 2},
		{"inconsistent summary", strings.ReplaceAll(completeReport, `"pass":1`, `"pass":0`), nil, 2},
		{"negative summary", strings.ReplaceAll(completeReport, `"pass":1`, `"pass":-1`), nil, 2},
		{"unknown severity", strings.ReplaceAll(completeReport, `"PASS"`, `"HEALTHY"`), nil, 2},
		{"unknown target", strings.ReplaceAll(completeReport, `"HOST"`, `"UNSUPPORTED"`), nil, 2},
		{"missing rule identity", strings.ReplaceAll(completeReport, `"HOST-DSK-001"`, `""`), nil, 2},
		{"required target absent", completeReport, []string{"--target", "docker"}, 2},
		{"required namespace absent", completeReport, []string{"--namespace", "synthetic"}, 2},
		{"matching namespace", strings.ReplaceAll(completeReport, `"target_type":"HOST"`, `"target_type":"KUBERNETES","namespace":"synthetic"`), []string{"--target", "k8s", "--namespace", "synthetic", "--require-rule", "HOST-DSK-001"}, 0},
		{"required rule absent", completeReport, []string{"--require-rule", "HOST-DSK-001", "--require-rule", "HOST-MEM-002"}, 2},
		{"blank required rule", completeReport, []string{"--require-rule", ""}, 2},
		{"required rules need report mode", completeReport, []string{"--report", "", "--require-rule", "HOST-DSK-001"}, 2},
		{"invalid threshold", completeReport, []string{"--fail-on", "warnng"}, 2},
		{"invalid target", completeReport, []string{"--target", "dockr"}, 2},
		{"unexpected positional report", completeReport, []string{"another-report.json"}, 2},
		{"unknown input flag", completeReport, []string{"--repot", "another-report.json"}, 2},
		{"missing input file", completeReport, []string{"--report", filepath.Join(t.TempDir(), "missing.json")}, 2},
		{"cannot save required output", completeReport, []string{"--output", t.TempDir()}, 2},
		{"oversized report", strings.Repeat(" ", 16<<20) + completeReport, nil, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := runSavedReport(t, test.report, test.args...)
			if test.code == 0 {
				if err != nil {
					t.Fatalf("complete report rejected: %v", err)
				}
				return
			}
			var exit *ExitError
			if !errors.As(err, &exit) || exit.Code != test.code {
				t.Fatalf("exit = %v, want code %d", err, test.code)
			}
		})
	}
}

func TestVerifySavedReportFileRoundTrip(t *testing.T) {
	directory := t.TempDir()
	input, output := filepath.Join(directory, "input.json"), filepath.Join(directory, "accepted.json")
	if err := os.WriteFile(input, []byte(completeReport), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runSavedReport(t, "", "--report", input, "--json", "--output", output); err != nil {
		t.Fatalf("saved report rejected: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := runSavedReport(t, string(data), "--target", "host"); err != nil {
		t.Fatalf("exported report rejected: %v", err)
	}
}
