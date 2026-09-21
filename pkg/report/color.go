package report

import "os"

// Palette holds the ANSI codes used across opskit's output. Every code lives
// here rather than being written inline, so `--no-color` is honoured by
// construction instead of by remembering to check a flag at each call site.
type Palette struct {
	Reset  string
	Bold   string
	Red    string
	Green  string
	Yellow string
	Blue   string
	Cyan   string
	Gray   string
}

var colored = Palette{
	Reset:  "\033[0m",
	Bold:   "\033[1m",
	Red:    "\033[31m",
	Green:  "\033[32m",
	Yellow: "\033[33m",
	Blue:   "\033[34m",
	Cyan:   "\033[36m",
	Gray:   "\033[90m",
}

// plain is the same palette with every code empty.
var plain = Palette{}

// Colors returns the palette to render with.
//
// Colour is suppressed when the caller asks for it, when NO_COLOR is set (the
// informal cross-tool convention), or when stdout is not a terminal — a report
// piped into a file or a CI log should not carry escape sequences that nothing
// will interpret.
func Colors(noColor bool) Palette {
	if noColor || os.Getenv("NO_COLOR") != "" || !stdoutIsTerminal() {
		return plain
	}
	return colored
}

// Wrap applies a code and resets afterwards. It is a no-op on a plain palette,
// so callers need no conditional of their own.
func (p Palette) Wrap(code, text string) string {
	if code == "" {
		return text
	}
	return code + text + p.Reset
}

// stdoutIsTerminal reports whether stdout is an interactive terminal rather than
// a pipe or a file.
func stdoutIsTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
