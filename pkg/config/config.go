package config

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Rule represents a single detection rule
type Rule struct {
	ID          string   `toml:"id"`
	Description string   `toml:"description"`
	Regex       string   `toml:"regex"`
	SecretGroup int      `toml:"secretGroup"`
	Entropy     float64  `toml:"entropy"`
	Path        string   `toml:"path"`
	Keywords    []string `toml:"keywords"`
	Tags        []string `toml:"tags"`
	Allowlists  []struct {
		Description string   `toml:"description"`
		RegexTarget string   `toml:"regexTarget"`
		Regexes     []string `toml:"regexes"`
		Stopwords   []string `toml:"stopwords"`
		Condition   string   `toml:"condition"`
		Commits     []string `toml:"commits"`
		Paths       []string `toml:"paths"`
	} `toml:"allowlists"`
}

// Config represents the entire configuration
type Config struct {
	Title  string `toml:"title"`
	Extend struct {
		UseDefault    bool     `toml:"useDefault"`
		Path          string   `toml:"path"`
		DisabledRules []string `toml:"disabledRules"`
	} `toml:"extend"`
	Rules      []Rule `toml:"rules"`
	Allowlists []struct {
		Description string   `toml:"description"`
		RegexTarget string   `toml:"regexTarget"`
		Regexes     []string `toml:"regexes"`
		Stopwords   []string `toml:"stopwords"`
		Commits     []string `toml:"commits"`
		Paths       []string `toml:"paths"`
		TargetRules []string `toml:"targetRules"`
	} `toml:"allowlists"`
}

// LoadConfig loads the configuration from file or downloads it if not present
func LoadConfig() (*Config, error) {
	// Get user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %v", err)
	}

	// Create .jsweb directory if it doesn't exist
	jswebDir := filepath.Join(homeDir, ".jsweb")
	if err := os.MkdirAll(jswebDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create .jsweb directory: %v", err)
	}

	configPath := filepath.Join(jswebDir, "gitleaks.toml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := downloadGitleaksConfig(configPath); err != nil {
			return nil, err
		}
	}

	var config Config
	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		return nil, fmt.Errorf("failed to decode TOML: %v", err)
	}
	return &config, nil
}

// downloadGitleaksConfig downloads the official Gitleaks configuration
func downloadGitleaksConfig(configPath string) error {
	url := "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download TOML: %v", err)
	}
	defer resp.Body.Close()

	out, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
