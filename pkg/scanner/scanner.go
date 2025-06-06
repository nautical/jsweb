package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/nautical/jsweb/pkg/config"
	"github.com/nautical/jsweb/pkg/utils"

	"github.com/playwright-community/playwright-go"
)

// Finding represents a detected secret
type Finding struct {
	Description string   `json:"description"`
	File        string   `json:"file"`
	RuleID      string   `json:"rule_id"`
	Tags        []string `json:"tags"`
	Secret      string   `json:"secret"`
	Context     string   `json:"context"`
	Line        string   `json:"line"`
	Entropy     float64  `json:"entropy,omitempty"`
	CodeSnippet string   `json:"code_snippet"`
}

// Scanner represents the secret scanning functionality
type Scanner struct {
	config   *config.Config
	findings []Finding
	headers  http.Header
	cookies  string
}

// getPlaywrightCacheDir returns the platform-specific Playwright cache directory
func getPlaywrightCacheDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	switch runtime.GOOS {
	case "windows":
		return filepath.Join(homeDir, "AppData", "Local", "ms-playwright"), nil
	case "darwin":
		return filepath.Join(homeDir, "Library", "Caches", "ms-playwright"), nil
	default: // linux and others
		return filepath.Join(homeDir, ".cache", "ms-playwright"), nil
	}
}

// areBrowsersInstalled checks if Playwright browsers are already installed
func areBrowsersInstalled() bool {
	cacheDir, err := getPlaywrightCacheDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get cache dir: %v\n", err)
		return false
	}

	// Check for the cache directory that Playwright uses
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Cache directory not found: %s\n", cacheDir)
		return false
	}

	// Check for at least one browser
	browsers := []string{"chromium", "firefox", "webkit"}
	for _, browser := range browsers {
		// List all directories in the cache directory
		entries, err := os.ReadDir(cacheDir)
		if err != nil {
			continue
		}

		// Check if any directory starts with the browser name
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), browser) {
				// Found a browser directory
				return true
			}
		}
	}
	return false
}

// NewScanner creates a new Scanner instance
func NewScanner(cfg *config.Config) *Scanner {
	return NewScannerWithOptions(cfg, nil, "")
}

// NewScannerWithOptions creates a new Scanner instance with custom headers and cookies
func NewScannerWithOptions(cfg *config.Config, headers []string, cookiesStr string) *Scanner {
	// Initialize scanner
	s := &Scanner{
		config:   cfg,
		findings: make([]Finding, 0),
		cookies:  cookiesStr,
	}

	// Parse headers
	s.headers = make(http.Header)
	for _, headerStr := range headers {
		if headerStr == "" {
			continue
		}

		headerParts := strings.SplitN(headerStr, ": ", 2)
		if len(headerParts) == 2 {
			s.headers.Add(headerParts[0], headerParts[1])
		}
	}

	// Only install browsers if they're not already present
	if !areBrowsersInstalled() {
		fmt.Println("Downloading browsers...")
		if err := playwright.Install(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to install browsers: %v\n", err)
		} else {
			fmt.Println("Downloaded browsers successfully")
		}
	}

	return s
}

// GetFindings returns all findings
func (s *Scanner) GetFindings() []Finding {
	return s.findings
}

// PrintFindings prints all findings in JSON format
func (s *Scanner) PrintFindings() error {
	// Sort findings by entropy in descending order
	sort.Slice(s.findings, func(i, j int) bool {
		return s.findings[i].Entropy > s.findings[j].Entropy
	})

	output := struct {
		Findings []Finding `json:"findings"`
	}{
		Findings: s.findings,
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %v", err)
	}

	// Ensure we write to stdout and add a newline
	if _, err := fmt.Println(string(jsonData)); err != nil {
		return fmt.Errorf("failed to write findings to stdout: %v", err)
	}

	return nil
}

// FindJSFiles finds all JavaScript files on a webpage
func (s *Scanner) FindJSFiles(page playwright.Page) ([]string, error) {
	scripts, err := page.Evaluate(`() => {
		const scripts = Array.from(document.getElementsByTagName('script'));
		return scripts.map(script => script.src).filter(src => src && src.endsWith('.js'));
	}`)
	if err != nil {
		return nil, err
	}

	var jsFiles []string
	for _, script := range scripts.([]interface{}) {
		if url, ok := script.(string); ok {
			jsFiles = append(jsFiles, url)
		}
	}

	return jsFiles, nil
}

// calculateEntropy calculates the Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}

	var entropy float64
	for _, count := range freq {
		probability := count / float64(len(s))
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// isAllowlisted checks if a match is in the allowlist
func (s *Scanner) isAllowlisted(match string, secret string, line string, rule config.Rule) bool {
	// Check global allowlists first (they have higher precedence)
	for _, allowlist := range s.config.Allowlists {
		// Skip if allowlist has target rules and this rule isn't one of them
		if len(allowlist.TargetRules) > 0 && !utils.Contains(allowlist.TargetRules, rule.ID) {
			continue
		}

		matchCount := 0
		totalChecks := 0

		// Check regexes
		if len(allowlist.Regexes) > 0 {
			totalChecks++
			for _, regex := range allowlist.Regexes {
				re, err := regexp.Compile(regex)
				if err != nil {
					continue
				}
				target := secret
				if allowlist.RegexTarget == "match" {
					target = match
				} else if allowlist.RegexTarget == "line" {
					target = line
				}
				if re.MatchString(target) {
					matchCount++
					break
				}
			}
		}

		// Check stopwords (targets the secret)
		if len(allowlist.Stopwords) > 0 {
			totalChecks++
			for _, stopword := range allowlist.Stopwords {
				if strings.Contains(secret, stopword) {
					matchCount++
					break
				}
			}
		}

		// If any allowlist matches, return true
		if matchCount > 0 {
			return true
		}
	}

	// Check rule-specific allowlists
	for _, allowlist := range rule.Allowlists {
		matchCount := 0
		totalChecks := 0

		// Check regexes
		if len(allowlist.Regexes) > 0 {
			totalChecks++
			for _, regex := range allowlist.Regexes {
				re, err := regexp.Compile(regex)
				if err != nil {
					continue
				}
				target := secret
				if allowlist.RegexTarget == "match" {
					target = match
				} else if allowlist.RegexTarget == "line" {
					target = line
				}
				if re.MatchString(target) {
					matchCount++
					break
				}
			}
		}

		// Check stopwords (targets the secret)
		if len(allowlist.Stopwords) > 0 {
			totalChecks++
			for _, stopword := range allowlist.Stopwords {
				if strings.Contains(secret, stopword) {
					matchCount++
					break
				}
			}
		}

		if allowlist.Condition == "AND" {
			if totalChecks > 0 && matchCount == totalChecks {
				return true
			}
		} else { // Default to OR
			if matchCount > 0 {
				return true
			}
		}
	}

	return false
}

// getCodeSnippet extracts a code snippet with context around the match
func getCodeSnippet(content string, match string, maxContext int) string {
	// Find the position of the match in the content
	pos := strings.Index(content, match)
	if pos == -1 {
		return match
	}

	// Calculate start and end positions for the snippet
	start := pos - maxContext
	if start < 0 {
		start = 0
	}

	end := pos + len(match) + maxContext
	if end > len(content) {
		end = len(content)
	}

	// Extract the snippet
	snippet := content[start:end]

	// Try to find complete lines
	lines := strings.Split(snippet, "\n")
	if len(lines) > 1 {
		// Remove partial first line if it exists
		if start > 0 && !strings.HasPrefix(snippet, "\n") {
			lines = lines[1:]
		}
		// Remove partial last line if it exists
		if end < len(content) && !strings.HasSuffix(snippet, "\n") {
			lines = lines[:len(lines)-1]
		}
		snippet = strings.Join(lines, "\n")
	}

	return strings.TrimSpace(snippet)
}

// CheckFileForSecrets scans a JavaScript file for potential secrets
func (s *Scanner) CheckFileForSecrets(url string) error {
	// Skip non-JavaScript files
	if !utils.IsJavaScriptFile(url) {
		return nil
	}

	// Skip third-party domains
	if utils.IsThirdPartyDomain(url) {
		return nil
	}

	// Add rate limiting
	time.Sleep(100 * time.Millisecond)

	// Create request with headers
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	for key, values := range s.headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Set cookies
	if s.cookies != "" {
		req.Header.Add("Cookie", s.cookies)
	}

	// Set common headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JS file: %v", err)
	}
	defer resp.Body.Close()

	// Skip non-JavaScript content types
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "javascript") && !strings.Contains(contentType, "text/plain") {
		return nil
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JS file content: %v", err)
	}

	contentStr := string(content)
	reportedMatches := make(map[string]bool) // Track reported matches to avoid duplicates

	for _, rule := range s.config.Rules {
		// Skip disabled rules
		if utils.Contains(s.config.Extend.DisabledRules, rule.ID) {
			continue
		}

		// Check keywords first if specified
		if len(rule.Keywords) > 0 {
			hasKeyword := false
			for _, keyword := range rule.Keywords {
				if strings.Contains(contentStr, keyword) {
					hasKeyword = true
					break
				}
			}
			if !hasKeyword {
				continue
			}
		}

		re, err := regexp.Compile(rule.Regex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Invalid regex in rule %s: %v\n", rule.ID, err)
			continue
		}

		matches := re.FindAllStringSubmatch(contentStr, -1)
		for _, match := range matches {
			if len(match) <= rule.SecretGroup {
				continue
			}

			secret := match[rule.SecretGroup]
			// Skip empty secrets
			if strings.TrimSpace(secret) == "" {
				continue
			}

			// Check entropy if specified
			var entropy float64
			if rule.Entropy > 0 {
				entropy = calculateEntropy(secret)
				if entropy < rule.Entropy {
					continue
				}
			}

			// Create a unique key for this match
			matchKey := fmt.Sprintf("%s:%s:%s", rule.ID, url, secret)
			if reportedMatches[matchKey] {
				continue
			}

			if s.isAllowlisted(match[0], secret, match[0], rule) {
				continue
			}

			// Get code snippet with context (300 characters before and after)
			codeSnippet := getCodeSnippet(contentStr, match[0], 300)

			// Add finding to the list
			finding := Finding{
				Description: rule.Description,
				File:        url,
				RuleID:      rule.ID,
				Tags:        rule.Tags,
				Secret:      secret,
				Context:     match[0],
				Line:        match[0],
				CodeSnippet: codeSnippet,
			}

			if rule.Entropy > 0 {
				finding.Entropy = entropy
			}

			s.findings = append(s.findings, finding)
			reportedMatches[matchKey] = true
		}
	}
	return nil
}
