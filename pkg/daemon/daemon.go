package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/analyzer"
	"github.com/hi-donwi/OPS-Toolkit/pkg/detector"
	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// DefaultSuppressWindow is how long a given finding stays suppressed after it
// has been alerted on, so a persistent fault does not page every interval.
const DefaultSuppressWindow = 30 * time.Minute

// Daemon watches infrastructure continuously and dispatches webhook alerts on
// critical events.
type Daemon struct {
	Interval       time.Duration
	WebhookURL     string
	AlertOn        string // "CRITICAL" or "WARNING"
	SuppressWindow time.Duration

	seenAlerts map[string]time.Time
	// clock is injectable so suppression and pruning can be tested without
	// waiting out real time.
	clock func() time.Time
}

// NewDaemon creates an alert daemon instance.
func NewDaemon(interval time.Duration, webhookURL, alertOn string) *Daemon {
	return &Daemon{
		Interval:       interval,
		WebhookURL:     webhookURL,
		AlertOn:        strings.ToUpper(strings.TrimSpace(alertOn)),
		SuppressWindow: DefaultSuppressWindow,
		seenAlerts:     make(map[string]time.Time),
		clock:          time.Now,
	}
}

// pruneSeenAlerts drops suppression entries that can no longer suppress.
func (d *Daemon) pruneSeenAlerts(now time.Time) {
	for key, seen := range d.seenAlerts {
		if now.Sub(seen) > d.SuppressWindow {
			delete(d.seenAlerts, key)
		}
	}
}

// Start begins the monitoring loop.
func (d *Daemon) Start(ctx context.Context) {
	fmt.Printf("[opskit-daemon] Starting continuous monitoring (interval: %s, threshold: %s)\n", d.Interval, d.AlertOn)
	ticker := time.NewTicker(d.Interval)
	defer ticker.Stop()

	// Initial check
	d.checkAndAlert(ctx)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("[opskit-daemon] Stopping daemon loop.")
			return
		case <-ticker.C:
			d.checkAndAlert(ctx)
		}
	}
}

func (d *Daemon) checkAndAlert(ctx context.Context) {
	env := detector.Detect()
	engine := analyzer.NewEngine(env)
	rep, err := engine.RunDiagnostics(ctx, model.TargetType(""), "")
	if err != nil {
		if ctx.Err() != nil {
			return // shutting down; not a diagnostic failure
		}
		fmt.Printf("[opskit-daemon] Diagnostic error: %v\n", err)
		return
	}

	newAlerts := make([]model.Finding, 0)
	now := d.clock()

	for _, f := range rep.Findings {
		if f.Severity == model.SeverityPass || f.Severity == model.SeverityInfo {
			continue
		}

		if d.AlertOn == "CRITICAL" && f.Severity != model.SeverityCritical {
			continue
		}

		alertKey := f.ID + ":" + f.Resource
		lastSeen, exists := d.seenAlerts[alertKey]

		if !exists || now.Sub(lastSeen) > d.SuppressWindow {
			d.seenAlerts[alertKey] = now
			newAlerts = append(newAlerts, f)
		}
	}

	// Keys are per-resource (container ids, pod names, unit names), so on a
	// churning host the map would otherwise grow without bound for the life of
	// the daemon. Entries past the suppression window can never suppress
	// anything again, so they are dropped.
	d.pruneSeenAlerts(now)

	if len(newAlerts) > 0 {
		fmt.Printf("[opskit-daemon] Found %d new actionable alert(s) at %s\n", len(newAlerts), now.Format("15:04:05"))
		if d.WebhookURL != "" {
			d.dispatchWebhook(ctx, newAlerts, rep)
		}
	}
}

func (d *Daemon) buildWebhookPayload(alerts []model.Finding, rep *model.Report) any {
	headline := fmt.Sprintf("[ALERT] [opskit] %d new infrastructure issues detected on `%s` (%s)",
		len(alerts), rep.Environment.Distro, rep.Environment.Platform)

	urlLower := strings.ToLower(d.WebhookURL)

	// Discord Embeds format
	if strings.Contains(urlLower, "discord.com") || strings.Contains(urlLower, "discordapp.com") {
		embeds := make([]map[string]any, 0, len(alerts))
		for _, f := range alerts {
			color := 15158332 // #e74c3c red for critical
			if f.Severity == model.SeverityWarning {
				color = 15844367 // #f1c40f yellow for warning
			}

			fields := []map[string]any{
				{"name": "Resource", "value": fmt.Sprintf("`%s`", f.Resource), "inline": true},
				{"name": "Severity", "value": string(f.Severity), "inline": true},
			}
			if len(f.RemedySteps) > 0 {
				fields = append(fields, map[string]any{
					"name":   "Recommended Remedy",
					"value":  f.RemedySteps[0],
					"inline": false,
				})
			}
			if f.QuickFixCmd != "" {
				fields = append(fields, map[string]any{
					"name":   "Quick Fix",
					"value":  fmt.Sprintf("`%s`", f.QuickFixCmd),
					"inline": false,
				})
			}

			embeds = append(embeds, map[string]any{
				"title":       fmt.Sprintf("[%s] %s", f.ID, f.Title),
				"description": f.Symptom,
				"color":       color,
				"fields":      fields,
			})
		}

		return map[string]any{
			"content": headline,
			"embeds":  embeds,
		}
	}

	// Slack Blocks / Attachments format
	if strings.Contains(urlLower, "slack.com") {
		attachments := make([]map[string]any, 0, len(alerts))
		for _, f := range alerts {
			color := "#e11d48" // red
			if f.Severity == model.SeverityWarning {
				color = "#f59e0b" // amber
			}

			text := fmt.Sprintf("*Resource:* `%s`\n*Symptom:* %s", f.Resource, f.Symptom)
			if len(f.RemedySteps) > 0 {
				text += fmt.Sprintf("\n*Remedy:* %s", f.RemedySteps[0])
			}
			if f.QuickFixCmd != "" {
				text += fmt.Sprintf("\n*Quick Fix:* `%s`", f.QuickFixCmd)
			}

			attachments = append(attachments, map[string]any{
				"color":     color,
				"title":     fmt.Sprintf("[%s] %s", f.ID, f.Title),
				"text":      text,
				"footer":    "opskit continuous monitoring",
				"ts":        time.Now().Unix(),
				"mrkdwn_in": []string{"text"},
			})
		}

		return map[string]any{
			"text":        headline,
			"attachments": attachments,
		}
	}

	// Generic universal payload (includes attachments for Slack-compatible consumers & alerts JSON array)
	attachments := make([]map[string]any, 0, len(alerts))
	for _, f := range alerts {
		color := "#e11d48"
		if f.Severity == model.SeverityWarning {
			color = "#f59e0b"
		}
		attachments = append(attachments, map[string]any{
			"color": color,
			"title": fmt.Sprintf("[%s] %s", f.ID, f.Title),
			"text":  fmt.Sprintf("*Resource:* `%s`\n*Symptom:* %s", f.Resource, f.Symptom),
		})
	}

	return map[string]any{
		"text": headline,
		"summary": map[string]int{
			"critical": rep.Summary.Critical,
			"warning":  rep.Summary.Warning,
		},
		"alerts":      alerts,
		"attachments": attachments,
	}
}

func (d *Daemon) dispatchWebhook(ctx context.Context, alerts []model.Finding, rep *model.Report) {
	payload := d.buildWebhookPayload(alerts, rep)

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("[opskit-daemon] Error marshaling webhook: %v\n", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.WebhookURL, bytes.NewReader(body))
	if err != nil {
		fmt.Printf("[opskit-daemon] Invalid webhook URL: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[opskit-daemon] Webhook delivery failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("[opskit-daemon] Webhook rejected the payload (status: %s)\n", resp.Status)
		return
	}

	fmt.Printf("[opskit-daemon] Webhook delivered successfully (status: %s)\n", resp.Status)
}
