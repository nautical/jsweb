package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/nautical/jsweb/pkg/config"
	"github.com/nautical/jsweb/pkg/scanner"

	"github.com/playwright-community/playwright-go"
)

// Version information - these variables are set during build using ldflags
var (
	Version   = "dev"
	BuildDate = "unknown"
	GitCommit = "unknown"
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

// validateURL checks if the provided string is a valid URL
func validateURL(rawURL string) (string, error) {
	// Add https:// prefix if no scheme is provided
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	// Parse the URL to validate it
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %v", err)
	}

	// Check for required components
	if parsedURL.Hostname() == "" {
		return "", fmt.Errorf("URL must contain a hostname")
	}

	return rawURL, nil
}

// printUsage prints detailed usage information
func printUsage() {
	fmt.Fprintf(os.Stderr, "JSWeb - JavaScript Secret Scanner %s\n\n", Version)
	fmt.Fprintf(os.Stderr, "Usage: jsweb [options] <url>\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  jsweb example.com\n")
	fmt.Fprintf(os.Stderr, "  jsweb --force-update example.com\n")
	fmt.Fprintf(os.Stderr, "  jsweb --header 'Authorization: Bearer token123' example.com\n")
	fmt.Fprintf(os.Stderr, "  jsweb --cookies 'session=abc123; user=john' example.com\n")
}

func main() {
	// Parse command line flags
	forceUpdate := flag.Bool("force-update", false, "Force update of gitleaks configuration")
	showVersion := flag.Bool("version", false, "Show version information")

	// Define custom flag for headers
	var headers headerFlag
	flag.Var(&headers, "header", "Custom header in format 'Name: Value'. Can be specified multiple times")

	cookies := flag.String("cookies", "", "Cookies in format 'name=value; name2=value2'")

	// Set custom usage function
	flag.Usage = printUsage

	flag.Parse()

	// Show version if requested
	if *showVersion {
		fmt.Printf("JSWeb - JavaScript Secret Scanner\nVersion: %s\nBuild Date: %s\nGit Commit: %s\n", Version, BuildDate, GitCommit)
		os.Exit(0)
	}

	// Get URL from command line arguments
	args := flag.Args()
	if len(args) != 1 {
		printUsage()
		os.Exit(1)
	}

	// Validate the URL
	url, err := validateURL(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
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
