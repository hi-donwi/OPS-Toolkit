package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/exporter"
	"github.com/spf13/cobra"
)

var (
	metricsPort     int
	metricsInterval string
)

var metricsCmd = &cobra.Command{
	Use:   "export-metrics",
	Short: "Start Prometheus metrics HTTP exporter",
	Long: `export-metrics launches a lightweight HTTP server exposing live SRE diagnostic
telemetry on /metrics in standard Prometheus text format.

Can be scraped by Prometheus or VictoriaMetrics to populate Grafana dashboards
with cluster and host health metrics.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		interval, err := time.ParseDuration(metricsInterval)
		if err != nil {
			return fmt.Errorf("invalid interval '%s': %w", metricsInterval, err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Println("\nShutting down metrics server...")
			cancel()
		}()

		server := exporter.NewMetricsServer(metricsPort, interval)
		fmt.Printf("opskit Prometheus exporter listening on http://0.0.0.0:%d/metrics (refresh interval: %s)\n", metricsPort, interval)
		return server.Start(ctx)
	},
}

func init() {
	metricsCmd.Flags().IntVarP(&metricsPort, "port", "p", 9876, "Port to expose Prometheus /metrics endpoint")
	metricsCmd.Flags().StringVarP(&metricsInterval, "interval", "i", "30s", "Telemetry re-evaluation interval (e.g. 15s, 30s, 1m)")
	RootCmd.AddCommand(metricsCmd)
}
