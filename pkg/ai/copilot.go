package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hi-donwi/SRE-Toolkit/pkg/model"
)

// CopilotClient generates deep SRE incident briefings and runbooks.
type CopilotClient struct {
	Provider    string
	OllamaURL   string
	Model       string
	APIKey      string
	BaseURL     string
	HTTPClient  *http.Client
	AllowRemote bool
}

// NewCopilotClient initializes the AI copilot client with multi-provider detection.
func NewCopilotClient() *CopilotClient {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("AI_PROVIDER")))

	geminiKey := strings.TrimSpace(os.Getenv("GEMINI_API_KEY"))
	openAIKey := strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	anthropicKey := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))

	if provider == "" {
		provider = "offline"
	}

	ollama := os.Getenv("OLLAMA_HOST")
	if ollama == "" {
		ollama = "http://localhost:11434"
	}

	modelName := os.Getenv("SRE_AI_MODEL")
	baseURL := os.Getenv("OPENAI_BASE_URL")
	apiKey := ""

	switch provider {
	case "gemini":
		apiKey = geminiKey
		if modelName == "" {
			modelName = os.Getenv("GEMINI_MODEL")
		}
		if modelName == "" {
			modelName = "gemini-2.5-flash"
		}
	case "openai":
		apiKey = openAIKey
		if modelName == "" {
			modelName = os.Getenv("OPENAI_MODEL")
		}
		if modelName == "" {
			modelName = "gpt-4o-mini"
		}
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
	case "anthropic":
		apiKey = anthropicKey
		if modelName == "" {
			modelName = os.Getenv("ANTHROPIC_MODEL")
		}
		if modelName == "" {
			modelName = "claude-3-5-haiku-20241022"
		}
	case "ollama":
		if modelName == "" {
			modelName = "llama3:latest"
		}
	}

	return &CopilotClient{
		Provider:    provider,
		OllamaURL:   ollama,
		Model:       modelName,
		APIKey:      apiKey,
		BaseURL:     baseURL,
		AllowRemote: os.Getenv("SRE_AI_ALLOW_REMOTE") == "1",
		HTTPClient:  &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

// ExplainFinding generates an actionable Incident Runbook and deep RCA for an SRE finding.
func (c *CopilotClient) ExplainFinding(ctx context.Context, f model.Finding) (string, error) {
	if err := c.validateEgress(); err != nil {
		return "", err
	}
	if c.Provider == "offline" {
		return SanitizeLog(c.generateHeuristicRunbook(f)), nil
	}
	sanitizedEvidence := SanitizeLog(f.LogEvidence)

	prompt := fmt.Sprintf(`You are an elite Site Reliability Engineer (SRE).
Analyze the following infrastructure failure and provide an authoritative Incident Briefing & Runbook:

[INCIDENT DETAILS]
- Finding ID: %s
- Title: %s
- Target: %s
- Resource: %s
- Severity: %s
- Symptom: %s
- Initial Root Cause: %s
- Log Evidence: %s

Please format your response into the following Markdown sections:
1. Executive Incident Summary & Severity Assessment
2. Deep Technical Root-Cause Breakdown
3. Immediate Emergency Mitigation Steps (with copy-paste commands)
4. Permanent Remediation & Architecture Hardening
5. Recommended Alerting SLOs & Preventative Monitoring
`, f.ID, f.Title, f.TargetType, f.Resource, f.Severity, f.Symptom, f.RootCause, sanitizedEvidence)
	prompt = SanitizeLog(prompt)

	var response string
	var err error

	switch c.Provider {
	case "gemini":
		response, err = c.queryGemini(ctx, prompt)
	case "openai":
		response, err = c.queryOpenAI(ctx, prompt)
	case "anthropic":
		response, err = c.queryAnthropic(ctx, prompt)
	default:
		response, err = c.queryOllama(ctx, prompt)
	}

	if err == nil && len(strings.TrimSpace(response)) > 50 {
		return SanitizeLog(response), nil
	}

	// Fallback to built-in SRE Expert Knowledge Engine
	return SanitizeLog(c.generateHeuristicRunbook(f)), nil
}

// A credential is authentication material, never permission to send incident data.
func (c *CopilotClient) validateEgress() error {
	if c.Provider == "offline" {
		return nil
	}
	switch c.Provider {
	case "ollama":
		u, err := url.Parse(c.OllamaURL)
		if err != nil || u.User != nil || u.Hostname() == "" {
			return fmt.Errorf("invalid Ollama endpoint")
		}
		ip := net.ParseIP(u.Hostname())
		local := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
		if local && (u.Scheme == "http" || u.Scheme == "https") {
			return nil
		}
		if !c.AllowRemote || u.Scheme != "https" {
			return fmt.Errorf("remote Ollama requires HTTPS and SRE_AI_ALLOW_REMOTE=1")
		}
	case "openai":
		u, err := url.Parse(c.BaseURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return fmt.Errorf("remote AI endpoint requires HTTPS without embedded credentials")
		}
		if !c.AllowRemote {
			return fmt.Errorf("remote AI requires SRE_AI_ALLOW_REMOTE=1 for approved data")
		}
	case "gemini", "anthropic":
		if !c.AllowRemote {
			return fmt.Errorf("remote AI requires SRE_AI_ALLOW_REMOTE=1 for approved data")
		}
	default:
		return fmt.Errorf("unknown AI provider")
	}
	return nil
}

func (c *CopilotClient) queryOllama(ctx context.Context, prompt string) (string, error) {
	url := fmt.Sprintf("%s/api/generate", c.OllamaURL)
	payload := map[string]interface{}{
		"model":  c.Model,
		"prompt": prompt,
		"stream": false,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	var result struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Response, nil
}

func (c *CopilotClient) queryGemini(ctx context.Context, prompt string) (string, error) {
	if c.APIKey == "" {
		return "", fmt.Errorf("GEMINI_API_KEY is not set")
	}
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", c.Model, c.APIKey)

	payload := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini returned status %d", resp.StatusCode)
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Candidates) > 0 && len(result.Candidates[0].Content.Parts) > 0 {
		return result.Candidates[0].Content.Parts[0].Text, nil
	}

	return "", fmt.Errorf("empty gemini response")
}

func (c *CopilotClient) queryOpenAI(ctx context.Context, prompt string) (string, error) {
	if c.APIKey == "" {
		return "", fmt.Errorf("OPENAI_API_KEY is not set")
	}
	url := fmt.Sprintf("%s/chat/completions", strings.TrimRight(c.BaseURL, "/"))

	payload := map[string]interface{}{
		"model": c.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai returned status %d", resp.StatusCode)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Choices) > 0 {
		return result.Choices[0].Message.Content, nil
	}

	return "", fmt.Errorf("empty openai response")
}

func (c *CopilotClient) queryAnthropic(ctx context.Context, prompt string) (string, error) {
	if c.APIKey == "" {
		return "", fmt.Errorf("ANTHROPIC_API_KEY is not set")
	}
	url := "https://api.anthropic.com/v1/messages"

	payload := map[string]interface{}{
		"model":      c.Model,
		"max_tokens": 2048,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic returned status %d", resp.StatusCode)
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Content) > 0 {
		return result.Content[0].Text, nil
	}

	return "", fmt.Errorf("empty anthropic response")
}

func (c *CopilotClient) generateHeuristicRunbook(f model.Finding) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("## SRE Incident Copilot Runbook: %s\n\n", f.Title))
	b.WriteString(fmt.Sprintf("- **Incident ID**: `%s`\n", f.ID))
	b.WriteString(fmt.Sprintf("- **Target Subsystem**: `%s` (`%s`)\n", f.TargetType, f.Resource))
	b.WriteString(fmt.Sprintf("- **Severity**: `%s`\n\n", f.Severity))

	b.WriteString("### 1. Executive Incident Summary\n")
	b.WriteString(fmt.Sprintf("A %s event was identified on resource `%s`. The system manifested the following failure pattern: *\"%s\"*.\n\n",
		strings.ToLower(string(f.Severity)), f.Resource, f.Symptom))

	b.WriteString("### 2. Deep Root-Cause Analysis (RCA)\n")
	b.WriteString(fmt.Sprintf("The underlying mechanism triggering this event is: **%s**.\n", f.RootCause))
	if f.LogEvidence != "" {
		b.WriteString("\n**Captured Failure Evidence**:\n```text\n")
		b.WriteString(SanitizeLog(f.LogEvidence))
		b.WriteString("\n```\n")
	}

	b.WriteString("\n### 3. Immediate Emergency Mitigation Steps\n")
	if len(f.RemedySteps) > 0 {
		for i, step := range f.RemedySteps {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
	} else {
		b.WriteString("1. Inspect resource telemetry and logs immediately.\n")
		b.WriteString("2. Verify upstream connectivity and resource limits.\n")
	}

	if f.QuickFixCmd != "" {
		b.WriteString("\n**One-Click Mitigation Command**:\n```bash\n")
		b.WriteString(f.QuickFixCmd)
		b.WriteString("\n```\n")
	}

	b.WriteString("\n### 4. Permanent Architectural Hardening\n")
	b.WriteString("- Ensure production resources enforce strict cgroup requests and limits.\n")
	b.WriteString("- Configure automated health probes (liveness and readiness) with appropriate failure thresholds.\n")
	b.WriteString("- Add synthetic monitoring probes to capture regressions before production traffic is impacted.\n")

	return b.String()
}
