package cmd

import (
	"net"
	"os"
	"time"

	"github.com/charmbracelet/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type Flags struct {
	Prefix      net.IPNet
	Gateway     net.IP
	Interval    time.Duration
	EMASpan     int
	LogLevel    string
	LogRawStats bool
	LogRawEMA   bool
	Debug       bool
}

var flags Flags

var rootCmd = &cobra.Command{
	Use:   "lb-proposal",
	Short: "[提案手法] 流量監視によるSRv6 Segment Listの変更ツール",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.SetOutput(os.Stdout)
		if flags.Debug {
			log.SetLevel(log.DebugLevel)
		} else {
			if logLevel, err := log.ParseLevel(flags.LogLevel); err != nil {
				return errors.Wrap(err, "Failed to parse log level")
			} else {
				log.SetLevel(logLevel)
			}
		}

		return runProposal()
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().IPNetVarP(&flags.Prefix, "prefix", "p", net.IPNet{}, "Prefix")
	rootCmd.MarkFlagRequired("prefix")
	rootCmd.Flags().IPVarP(&flags.Gateway, "gateway", "g", net.IP{}, "Gateway")
	rootCmd.MarkFlagRequired("gateway")
	rootCmd.Flags().DurationVarP(&flags.Interval, "interval", "i", time.Duration(0), "Interval")
	rootCmd.MarkFlagRequired("interval")
	rootCmd.Flags().IntVarP(&flags.EMASpan, "ema-span", "e", 100, "EMA span")

	// Debug mode
	rootCmd.Flags().BoolVarP(&flags.Debug, "debug", "d", false, "Debug mode")
	// log level
	rootCmd.Flags().StringVarP(&flags.LogLevel, "loglevel", "l", "info", "Log level (debug, info, warn, error, fatal)")
	// log raw statistics
	rootCmd.Flags().BoolVar(&flags.LogRawStats, "log-raw-stats", false, "Log raw statistics")
	// log statistics
	rootCmd.Flags().BoolVar(&flags.LogRawEMA, "log-raw-ema", false, "Log raw EMA")
}
