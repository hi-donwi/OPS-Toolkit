package ai

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/hi-donwi/SRE-Toolkit/pkg/model"
)

type captureTransport struct{ body string }

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	c.body = string(b)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"response":"A synthetic explanation long enough to be accepted by this test fixture."}`)), Header: make(http.Header)}, nil
}

func TestAmbientCredentialsDoNotEnableCloud(t *testing.T) {
	t.Setenv("AI_PROVIDER", "")
	t.Setenv("GEMINI_API_KEY", "synthetic-not-a-real-key")
	t.Setenv("OPENAI_API_KEY", "synthetic-not-a-real-key")
	if got := NewCopilotClient().Provider; got != "offline" {
		t.Fatalf("default provider = %s", got)
	}
}

func TestExplicitProviderWithoutRemoteApprovalDoesNotSend(t *testing.T) {
	t.Setenv("AI_PROVIDER", "openai")
	t.Setenv("SRE_AI_ALLOW_REMOTE", "")
	transport := &captureTransport{}
	client := NewCopilotClient()
	client.HTTPClient = &http.Client{Transport: transport}
	_, err := client.ExplainFinding(context.Background(), model.Finding{Title: "synthetic"})
	if err == nil || transport.body != "" {
		t.Fatal("remote provider must fail before sending")
	}
}

func TestAllOutboundFieldsAreSanitized(t *testing.T) {
	t.Setenv("AI_PROVIDER", "ollama")
	t.Setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
	transport := &captureTransport{}
	client := NewCopilotClient()
	client.HTTPClient = &http.Client{Transport: transport}
	_, err := client.ExplainFinding(context.Background(), model.Finding{
		Title: "password=SYNTHETIC_CANARY", Resource: "token=SYNTHETIC_CANARY",
		Symptom: "api_key=SYNTHETIC_CANARY", RootCause: "secret=SYNTHETIC_CANARY", LogEvidence: "password=SYNTHETIC_CANARY",
	})
	if err != nil {
		t.Fatal(err)
	}
	if transport.body == "" || strings.Contains(transport.body, "SYNTHETIC_CANARY") {
		t.Fatal("unredacted outbound fields")
	}
}

func TestRemoteOllamaRequiresApproval(t *testing.T) {
	t.Setenv("AI_PROVIDER", "ollama")
	t.Setenv("OLLAMA_HOST", "https://example.invalid")
	t.Setenv("SRE_AI_ALLOW_REMOTE", "")
	transport := &captureTransport{}
	client := NewCopilotClient()
	client.HTTPClient = &http.Client{Transport: transport}
	_, err := client.ExplainFinding(context.Background(), model.Finding{})
	if err == nil || transport.body != "" {
		t.Fatal("remote Ollama sent without approval")
	}
}
