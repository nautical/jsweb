package config

import (
	"fmt"
	"io"
	"net/http"
	"os"

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
	if _, err := os.Stat("gitleaks.toml"); os.IsNotExist(err) {
		if err := downloadGitleaksConfig(); err != nil {
			return nil, err
		}
	}

	var config Config
	if _, err := toml.DecodeFile("gitleaks.toml", &config); err != nil {
		return nil, fmt.Errorf("failed to decode TOML: %v", err)
	}
	return &config, nil
}

// downloadGitleaksConfig downloads the official Gitleaks configuration
func downloadGitleaksConfig() error {
	url := "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download TOML: %v", err)
	}
	defer resp.Body.Close()

	out, err := os.Create("gitleaks.toml")
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
