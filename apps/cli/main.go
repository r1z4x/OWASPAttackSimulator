package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/owaspattacksimulator/apps/cli/cmd"
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
		Long: `OWASPAttackSimulator is a scenario-based security testing framework that provides
infinite-step attack infrastructure with GUI/CLI support, gRPC broker,
and comprehensive OWASP vulnerability detection.

Features:
• 🚀 Enhanced CLI with colored output
• 🎯 Multiple attack types (XSS, SQLi, SSRF, etc.)
• 🎬 Scenario-based testing
• 📊 Real-time progress tracking
• 🛡️ Comprehensive vulnerability detection`,
		Version:           "1.0.0",
		DisableAutoGenTag: true,
		SilenceUsage:      true, // Don't show usage on error
		SilenceErrors:     true, // Don't show error twice
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no subcommand is provided, run the server by default
			fmt.Println("🚀 Starting gRPC server (default mode)...")
			// Find the server command
			for _, subCmd := range cmd.Commands() {
				if subCmd.Name() == "server" {
					return subCmd.RunE(subCmd, []string{})
				}
			}
			return fmt.Errorf("server command not found")
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
