package main

import (
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
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: jsweb <url>\n")
		os.Exit(1)
	}

	if err := installPlaywrightBrowsers(); err != nil {
		fmt.Fprintf(os.Stderr, "Error installing Playwright browsers: %v\n", err)
		os.Exit(1)
	}

	url := os.Args[1]
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	scanner := scanner.NewScanner(cfg)

	pw, err := playwright.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting Playwright: %v\n", err)
		os.Exit(1)
	}

	browser, err := pw.Chromium.Launch()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error launching browser: %v\n", err)
		os.Exit(1)
	}

	page, err := browser.NewPage()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating new page: %v\n", err)
		os.Exit(1)
	}

	if _, err := page.Goto(url); err != nil {
		fmt.Fprintf(os.Stderr, "Error navigating to URL: %v\n", err)
		os.Exit(1)
	}

	jsFiles, err := scanner.FindJSFiles(page)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding JS files: %v\n", err)
		os.Exit(1)
	}

	for _, jsFile := range jsFiles {
		if err := scanner.CheckFileForSecrets(jsFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking file %s: %v\n", jsFile, err)
		}
	}

	if err := browser.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Error closing browser: %v\n", err)
	}
	if err := pw.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping Playwright: %v\n", err)
	}

	// Print findings in JSON format
	if err := scanner.PrintFindings(); err != nil {
		fmt.Fprintf(os.Stderr, "Error printing findings: %v\n", err)
		os.Exit(1)
	}
}
