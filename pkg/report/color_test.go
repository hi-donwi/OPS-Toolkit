package report

import (
	"strings"
	"testing"
)

func TestColorsSuppressedWhenAsked(t *testing.T) {
	if got := Colors(true); got != plain {
		t.Error("--no-color must yield an empty palette")
	}
}

func TestColorsRespectNoColorEnv(t *testing.T) {
	// NO_COLOR is the informal cross-tool convention; honouring it costs
	// nothing and users expect it.
	t.Setenv("NO_COLOR", "1")

	if got := Colors(false); got != plain {
		t.Error("NO_COLOR must suppress colour even without --no-color")
	}
}

func TestColorsSuppressedWhenNotATerminal(t *testing.T) {
	// `go test` does not run with a terminal on stdout, which is the same
	// situation as `opskit diag > report.txt` or a CI log. Escape sequences
	// there are noise nothing will interpret.
	if got := Colors(false); got != plain {
		t.Error("output that is not going to a terminal must not carry ANSI codes")
	}
}

func TestWrapIsANoOpOnPlainPalette(t *testing.T) {
	if got := plain.Wrap(plain.Red, "text"); got != "text" {
		t.Errorf("Wrap on a plain palette = %q, want the bare text", got)
	}
}

func TestWrapAppliesAndResets(t *testing.T) {
	got := colored.Wrap(colored.Red, "boom")

	if !strings.HasPrefix(got, colored.Red) {
		t.Error("Wrap should prefix the colour code")
	}
	if !strings.HasSuffix(got, colored.Reset) {
		t.Error("Wrap must reset afterwards, or the colour bleeds into later output")
	}
	if !strings.Contains(got, "boom") {
		t.Error("Wrap dropped the text")
	}
}
