package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(hashCmd)
	rootCmd.AddCommand(signCmd)
}

var rootCmd = &cobra.Command{
	Use:   "go-client-cli",
	Short: "Test-app for working with Crypto Broker",
}

func Execute() {
	rootCmd.Execute()
}
