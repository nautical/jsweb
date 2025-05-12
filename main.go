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

// Custom flag type for headers
type headerFlag []string

func (h *headerFlag) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlag) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func main() {
	// Parse command line flags
	forceUpdate := flag.Bool("force-update", false, "Force update of gitleaks configuration")

	// Define custom flag for headers
	var headers headerFlag
	flag.Var(&headers, "header", "Custom header in format 'Name: Value'. Can be specified multiple times")

	cookies := flag.String("cookies", "", "Cookies in format 'name=value; name2=value2'")
	flag.Parse()

	// Get URL from command line arguments
	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: jsweb [--force-update] [--header 'Name: Value'] [--cookies 'name=value; name2=value2'] <url>\n")
		os.Exit(1)
	}
	url := args[0]

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	// Load configuration
	cfg, err := config.LoadConfig(*forceUpdate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Create scanner with headers and cookies
	s := scanner.NewScannerWithOptions(cfg, headers, *cookies)

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

	// Set headers if provided
	if len(headers) > 0 {
		playwrightHeaders := make(map[string]string)
		for _, header := range headers {
			headerParts := strings.SplitN(header, ": ", 2)
			if len(headerParts) == 2 {
				playwrightHeaders[headerParts[0]] = headerParts[1]
			}
		}

		if len(playwrightHeaders) > 0 {
			if err := page.SetExtraHTTPHeaders(playwrightHeaders); err != nil {
				fmt.Fprintf(os.Stderr, "Error setting headers: %v\n", err)
			}
		}
	}

	// Set cookies if provided
	if *cookies != "" {
		// Parse cookies string
		cookiesList := strings.Split(*cookies, ";")
		var playwrightCookies []playwright.OptionalCookie

		for _, cookie := range cookiesList {
			cookie = strings.TrimSpace(cookie)
			if cookie == "" {
				continue
			}

			parts := strings.SplitN(cookie, "=", 2)
			if len(parts) != 2 {
				continue
			}

			name := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			if name != "" && value != "" {
				playwrightCookies = append(playwrightCookies, playwright.OptionalCookie{
					Name:  name,
					Value: value,
					URL:   &url,
				})
			}
		}

		if len(playwrightCookies) > 0 {
			if err := page.Context().AddCookies(playwrightCookies); err != nil {
				fmt.Fprintf(os.Stderr, "Error setting cookies: %v\n", err)
			}
		}
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
