package main

import (
	"fmt"
	"os"

	"github.com/owaspchecker/apps/cli/cmd"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "simulation",
		Short: "OWASP Security Testing Framework",
		Long: `OWASPAttackSimulator is a scenario-based security testing framework that provides
infinite-step attack infrastructure with GUI/CLI support, gRPC broker,
and comprehensive OWASP vulnerability detection.`,
		Version:           "1.0.0",
		DisableAutoGenTag: true,
		SilenceUsage:      true,  // Don't show usage on error
		SilenceErrors:     true,  // Don't show error twice
	}

	// Add direct commands (no parent run command)
	cmd.AddAttackCommand(rootCmd)
	cmd.AddScenarioCommand(rootCmd)

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
