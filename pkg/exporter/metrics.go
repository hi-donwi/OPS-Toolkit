package exporter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/analyzer"
	"github.com/hi-donwi/OPS-Toolkit/pkg/detector"
	"github.com/hi-donwi/OPS-Toolkit/pkg/model"
)

// MetricsServer serves Prometheus metrics over HTTP.
type MetricsServer struct {
	port          int
	interval      time.Duration
	lastReport    *model.Report
	lastEvaluated time.Time
	scrapeErrors  int
	mu            sync.RWMutex
}

// NewMetricsServer creates a new metrics server.
func NewMetricsServer(port int, interval time.Duration) *MetricsServer {
	return &MetricsServer{
		port:     port,
		interval: interval,
	}
}

// Start begins periodic evaluations and listens on HTTP :port.
func (s *MetricsServer) Start(ctx context.Context) error {
	// Initial evaluation, so the first scrape after start returns real data
	// rather than the pending placeholder.
	s.evaluate(ctx)

	// Background ticker for periodic re-evaluation
	go func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.evaluate(ctx)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: mux,
		// The exporter listens on the node network in the DaemonSet and Swarm
		// deployments. Without these, a client that opens a connection and
		// never finishes its request holds a goroutine indefinitely.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *MetricsServer) evaluate(ctx context.Context) {
	env := detector.Detect()
	engine := analyzer.NewEngine(env)

	rep, err := engine.RunDiagnostics(ctx, model.TargetType(""), "")
	if err != nil {
		s.mu.Lock()
		s.scrapeErrors++
		s.mu.Unlock()
		return
	}

	s.mu.Lock()
	s.lastReport = rep
	s.lastEvaluated = time.Now()
	s.mu.Unlock()
}

func (s *MetricsServer) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	rep := s.lastReport
	errCount := s.scrapeErrors
	evaluated := s.lastEvaluated
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	if rep == nil {
		// Emit opskit_up even with no data, so a dashboard can distinguish
		// "collector is starting" from "collector is gone".
		fmt.Fprint(w, "# HELP opskit_up Whether the last diagnostic evaluation succeeded\n")
		fmt.Fprint(w, "# TYPE opskit_up gauge\n")
		fmt.Fprint(w, "opskit_up 0\n")
		return
	}

	writeMetrics(w, rep, errCount, evaluated)
}

// writeMetrics renders the Prometheus exposition format for a report.
func writeMetrics(w io.Writer, rep *model.Report, scrapeErrors int, evaluated time.Time) {
	fmt.Fprint(w, "# HELP opskit_up Whether the last diagnostic evaluation succeeded\n")
	fmt.Fprint(w, "# TYPE opskit_up gauge\n")
	fmt.Fprint(w, "opskit_up 1\n\n")

	writeFindingsTotal(w, rep)
	writeSeveritySummary(w, rep)
	writeActiveFindings(w, rep)

	fmt.Fprint(w, "# HELP opskit_health_score Overall infrastructure health score (0-100)\n")
	fmt.Fprint(w, "# TYPE opskit_health_score gauge\n")
	fmt.Fprintf(w, "opskit_health_score %d\n\n", HealthScore(rep.Summary))

	fmt.Fprint(w, "# HELP opskit_last_evaluation_timestamp_seconds Epoch timestamp of the last diagnostic run\n")
	fmt.Fprint(w, "# TYPE opskit_last_evaluation_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "opskit_last_evaluation_timestamp_seconds %d\n\n", evaluated.Unix())

	fmt.Fprint(w, "# HELP opskit_evaluation_errors_total Diagnostic evaluations that failed to complete\n")
	fmt.Fprint(w, "# TYPE opskit_evaluation_errors_total counter\n")
	fmt.Fprintf(w, "opskit_evaluation_errors_total %d\n", scrapeErrors)
}

// writeFindingsTotal emits finding counts partitioned by target and severity.
// Series are emitted in sorted order so scrape output is byte-stable, which
// keeps diffs and golden tests meaningful.
func writeFindingsTotal(w io.Writer, rep *model.Report) {
	type key struct{ target, severity string }
	counts := make(map[key]int)

	for _, f := range rep.Findings {
		counts[key{string(f.TargetType), string(f.Severity)}]++
	}

	keys := make([]key, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].target != keys[j].target {
			return keys[i].target < keys[j].target
		}
		return keys[i].severity < keys[j].severity
	})

	fmt.Fprint(w, "# HELP opskit_findings_total Diagnostic findings partitioned by target and severity\n")
	fmt.Fprint(w, "# TYPE opskit_findings_total gauge\n")
	for _, k := range keys {
		fmt.Fprintf(w, "opskit_findings_total{target=%q,severity=%q} %d\n",
			escapeLabel(k.target), escapeLabel(k.severity), counts[k])
	}
	fmt.Fprint(w, "\n")
}

// writeSeveritySummary emits flat per-severity gauges, which are cheaper to
// alert on than summing a partitioned series.
func writeSeveritySummary(w io.Writer, rep *model.Report) {
	fmt.Fprint(w, "# HELP opskit_severity_count Findings at each severity across all targets\n")
	fmt.Fprint(w, "# TYPE opskit_severity_count gauge\n")
	fmt.Fprintf(w, "opskit_severity_count{severity=\"CRITICAL\"} %d\n", rep.Summary.Critical)
	fmt.Fprintf(w, "opskit_severity_count{severity=\"WARNING\"} %d\n", rep.Summary.Warning)
	fmt.Fprintf(w, "opskit_severity_count{severity=\"INFO\"} %d\n", rep.Summary.Info)
	fmt.Fprintf(w, "opskit_severity_count{severity=\"PASS\"} %d\n\n", rep.Summary.Pass)
}

// writeActiveFindings emits one series per actionable finding, so an alert can
// name the failing rule and resource instead of only a count. PASS findings are
// omitted: they would multiply cardinality for no alerting value.
func writeActiveFindings(w io.Writer, rep *model.Report) {
	fmt.Fprint(w, "# HELP opskit_finding_active An actionable finding currently detected\n")
	fmt.Fprint(w, "# TYPE opskit_finding_active gauge\n")

	seen := make(map[string]bool)
	for _, f := range rep.Findings {
		if f.Severity == model.SeverityPass {
			continue
		}

		line := fmt.Sprintf("opskit_finding_active{id=%q,severity=%q,target=%q,resource=%q,namespace=%q}",
			escapeLabel(f.ID), escapeLabel(string(f.Severity)), escapeLabel(string(f.TargetType)),
			escapeLabel(f.Resource), escapeLabel(f.Namespace))

		// Identical label sets would be a duplicate series and make the whole
		// scrape fail to parse, so collapse them.
		if seen[line] {
			continue
		}
		seen[line] = true
		fmt.Fprintf(w, "%s 1\n", line)
	}
	fmt.Fprint(w, "\n")
}

// HealthScore converts a severity summary into a 0-100 gauge. Criticals weigh
// three times a warning because a single crash-looping workload matters more
// than several approaching thresholds.
func HealthScore(s model.Summary) int {
	score := 100 - (s.Critical * 30) - (s.Warning * 10)
	if score < 0 {
		return 0
	}
	return score
}

// escapeLabel escapes a Prometheus label value. An unescaped backslash, quote,
// or newline inside a resource name (a container command, a mount path) would
// otherwise emit a malformed exposition that Prometheus rejects wholesale.
func escapeLabel(v string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return replacer.Replace(v)
}
