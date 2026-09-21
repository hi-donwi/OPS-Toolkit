package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hi-donwi/OPS-Toolkit/pkg/daemon"
	"github.com/spf13/cobra"
)

var (
	daemonInterval   string
	daemonWebhookURL string
	daemonAlertOn    string
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run continuous background health watcher with webhook alerting",
	Long: `daemon runs opskit as an autonomous background monitoring service.
It continuously evaluates host, container, and cluster health at defined intervals
and sends instant alert notifications to Slack, Discord, Telegram, or custom webhooks
whenever a critical issue or crashloop is detected.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		interval, err := time.ParseDuration(daemonInterval)
		if err != nil {
			return fmt.Errorf("invalid interval '%s': %w", daemonInterval, err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Println("\nReceived termination signal. Exiting daemon...")
			cancel()
		}()

		d := daemon.NewDaemon(interval, daemonWebhookURL, daemonAlertOn)
		d.Start(ctx)
		return nil
	},
}

func init() {
	daemonCmd.Flags().StringVarP(&daemonInterval, "interval", "i", "60s", "Monitoring evaluation frequency (e.g. 30s, 1m, 5m)")
	daemonCmd.Flags().StringVar(&daemonWebhookURL, "webhook-url", "", "HTTP Webhook endpoint for alert dispatch (Slack, Discord, PagerDuty)")
	daemonCmd.Flags().StringVar(&daemonAlertOn, "alert-on", "critical", "Alert severity threshold: 'critical' or 'warning'")
	RootCmd.AddCommand(daemonCmd)
}
