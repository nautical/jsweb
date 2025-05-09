package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nautical/jsweb/pkg/config"
	"github.com/nautical/jsweb/pkg/scanner"

	"github.com/playwright-community/playwright-go"
)

func installPlaywrightBrowsers() error {
	err := playwright.Install()
	if err != nil {
		return fmt.Errorf("could not install playwright browsers: %v", err)
	}
	return nil
}

func main() {
	// Parse command line flags
	forceUpdate := flag.Bool("force-update", false, "Force update of gitleaks configuration")
	flag.Parse()

	// Get URL from command line arguments
	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: jsweb [--force-update] <url>\n")
		os.Exit(1)
	}
	url := args[0]

	if err := installPlaywrightBrowsers(); err != nil {
		fmt.Fprintf(os.Stderr, "Error installing Playwright browsers: %v\n", err)
		os.Exit(1)
	}

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	// Load configuration
	cfg, err := config.LoadConfig(*forceUpdate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Create scanner
	s := scanner.NewScanner(cfg)

	// Initialize Playwright
	pw, err := playwright.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing Playwright: %v\n", err)
		os.Exit(1)
	}
	defer pw.Stop()

	// Create browser
	browser, err := pw.Chromium.Launch()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error launching browser: %v\n", err)
		os.Exit(1)
	}
	defer browser.Close()

	// Create page
	page, err := browser.NewPage()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating page: %v\n", err)
		os.Exit(1)
	}

	// Navigate to URL
	if _, err := page.Goto(url); err != nil {
		fmt.Fprintf(os.Stderr, "Error navigating to URL: %v\n", err)
		os.Exit(1)
	}

	// Find JavaScript files
	jsFiles, err := s.FindJSFiles(page)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding JavaScript files: %v\n", err)
		os.Exit(1)
	}

	// Check each file for secrets
	for _, jsFile := range jsFiles {
		if err := s.CheckFileForSecrets(jsFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking file %s: %v\n", jsFile, err)
		}
	}

	// Print findings
	if err := s.PrintFindings(); err != nil {
		fmt.Fprintf(os.Stderr, "Error printing findings: %v\n", err)
		os.Exit(1)
	}
}
