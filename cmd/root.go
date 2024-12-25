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
	Prefix   net.IPNet
	Gateway  net.IP
	Interval time.Duration
	LogLevel string
	Debug    bool
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

	// Debug mode
	rootCmd.Flags().BoolVarP(&flags.Debug, "debug", "d", false, "Debug mode")
	// log level
	rootCmd.Flags().StringVarP(&flags.LogLevel, "loglevel", "l", "info", "Log level (debug, info, warn, error, fatal)")
}
