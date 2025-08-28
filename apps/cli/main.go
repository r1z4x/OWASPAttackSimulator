package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/owaspattacksimulator/apps/cli/cmd"
	"github.com/owaspattacksimulator/internal/attack"
	"github.com/spf13/cobra"
)

func main() {
	// Setup aggressive signal handling for immediate termination
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	go func() {
		sig := <-sigChan
		fmt.Printf("\n🛑 Received signal %v, terminating immediately...\n", sig)
		os.Exit(0)
	}()

	rootCmd := &cobra.Command{
		Use:   "simulation",
		Short: "OWASP Security Testing Framework",
		Long: `OWASPAttackSimulator - Comprehensive security testing framework with infinite-step attack infrastructure.

Features:
• 🎯 Multiple attack types (XSS, SQLi, SSRF, XXE, CSRF, CORS, AuthZ)
• 🎬 Scenario-based testing with YAML DSL
• 🚀 CLI and GUI support
• 📊 Real-time monitoring and reporting`,
		Version:           "1.0.0",
		DisableAutoGenTag: true,
		SilenceUsage:      true, // Don't show usage on error
		SilenceErrors:     true, // Don't show error twice
		RunE: func(cmd *cobra.Command, args []string) error {
			// Show banner and help when no subcommand is provided
			ui := attack.NewUI(true, false, false) // Enable colors, no progress, no interactive
			ui.PrintBanner()
			return cmd.Help()
		},
	}

	// Add commands
	cmd.AddServerCommand(rootCmd)
	cmd.AddAttackCommand(rootCmd)
	cmd.AddScenarioCommand(rootCmd)
	cmd.AddReportCommand(rootCmd)

	// Remove completion and help commands
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:    "no-help",
		Hidden: true,
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}
}
