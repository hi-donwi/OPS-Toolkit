package daemon

import (
	"testing"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

func TestPruneSeenAlertsBoundsMemory(t *testing.T) {
	// Keys are per-resource (container ids, pod names, unit names). Without
	// pruning the map retains an entry for every resource ever seen, for the
	// life of a process designed to run for months.
	d := NewDaemon(time.Minute, "", "critical")
	d.SuppressWindow = 10 * time.Minute

	now := time.Now()
	d.seenAlerts["fresh"] = now.Add(-1 * time.Minute)
	d.seenAlerts["stale"] = now.Add(-30 * time.Minute)
	d.seenAlerts["ancient"] = now.Add(-72 * time.Hour)

	d.pruneSeenAlerts(now)

	if _, ok := d.seenAlerts["fresh"]; !ok {
		t.Error("an entry inside the suppression window must be kept")
	}
	if len(d.seenAlerts) != 1 {
		t.Errorf("map holds %d entries after pruning, want 1", len(d.seenAlerts))
	}
}

func TestNewDaemonNormalizesThreshold(t *testing.T) {
	d := NewDaemon(time.Minute, "", "  Critical  ")
	if d.AlertOn != "CRITICAL" {
		t.Errorf("AlertOn = %q, want CRITICAL", d.AlertOn)
	}
	if d.SuppressWindow != DefaultSuppressWindow {
		t.Errorf("SuppressWindow = %v, want the default", d.SuppressWindow)
	}
}

func TestSuppressionWindowIsConfigurable(t *testing.T) {
	d := NewDaemon(time.Minute, "", "critical")
	d.SuppressWindow = time.Second

	now := time.Now()
	d.seenAlerts["x"] = now.Add(-2 * time.Second)
	d.pruneSeenAlerts(now)

	if len(d.seenAlerts) != 0 {
		t.Error("pruning should honour a shortened suppression window")
	}
}

func TestBuildWebhookPayload(t *testing.T) {
	alerts := []model.Finding{
		{
			ID:          "HOST-DSK-001",
			Title:       "High Disk Space Utilization",
			Severity:    model.SeverityCritical,
			Resource:    "/dev/sda1",
			Symptom:     "Disk usage 95%",
			RemedySteps: []string{"Clean journal logs"},
			QuickFixCmd: "journalctl --vacuum-size=500M",
		},
	}
	rep := &model.Report{
		Environment: model.EnvironmentContext{Distro: "Ubuntu 22.04", Platform: "linux/amd64"},
		Summary:     model.Summary{Critical: 1, Warning: 0},
	}

	// 1. Discord URL
	dDiscord := NewDaemon(time.Minute, "https://discord.com/api/webhooks/123/abc", "critical")
	discordPayload, ok := dDiscord.buildWebhookPayload(alerts, rep).(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any for discord payload")
	}
	if _, ok := discordPayload["embeds"]; !ok {
		t.Errorf("discord payload missing 'embeds'")
	}

	// 2. Slack URL
	dSlack := NewDaemon(time.Minute, "https://hooks.slack.com/services/T00/B00/X00", "critical")
	slackPayload, ok := dSlack.buildWebhookPayload(alerts, rep).(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any for slack payload")
	}
	if _, ok := slackPayload["attachments"]; !ok {
		t.Errorf("slack payload missing 'attachments'")
	}

	// 3. Generic URL
	dGeneric := NewDaemon(time.Minute, "https://example.com/webhook", "critical")
	genericPayload, ok := dGeneric.buildWebhookPayload(alerts, rep).(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any for generic payload")
	}
	if _, ok := genericPayload["alerts"]; !ok {
		t.Errorf("generic payload missing 'alerts'")
	}
}
