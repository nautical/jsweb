package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// UpdateInfo stores the last update check information
type UpdateInfo struct {
	LastCheck time.Time `json:"last_check"`
	LastHash  string    `json:"last_hash"`
}

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

// getRemoteFileHash gets the SHA-256 hash of the remote file
func getRemoteFileHash(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch remote file: %v", err)
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read remote file: %v", err)
	}

	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:]), nil
}

// getLocalFileHash gets the SHA-256 hash of the local file
func getLocalFileHash(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read local file: %v", err)
	}

	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:]), nil
}

// getConfigDir returns the platform-specific configuration directory
func getConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Use .jsweb in home directory for all platforms
	return filepath.Join(homeDir, ".jsweb"), nil
}

// getUpdateInfoPath returns the path to the update info file
func getUpdateInfoPath(configDir string) string {
	return filepath.Join(configDir, "update_info.json")
}

// loadUpdateInfo loads the last update check information
func loadUpdateInfo(configDir string) (*UpdateInfo, error) {
	infoPath := getUpdateInfoPath(configDir)
	if _, err := os.Stat(infoPath); os.IsNotExist(err) {
		return &UpdateInfo{}, nil
	}

	data, err := os.ReadFile(infoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read update info: %v", err)
	}

	var info UpdateInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to parse update info: %v", err)
	}

	return &info, nil
}

// saveUpdateInfo saves the update check information
func saveUpdateInfo(configDir string, info *UpdateInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal update info: %v", err)
	}

	infoPath := getUpdateInfoPath(configDir)
	if err := os.WriteFile(infoPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write update info: %v", err)
	}

	return nil
}

// shouldCheckForUpdates determines if we should check for updates
func shouldCheckForUpdates(info *UpdateInfo, forceUpdate bool) bool {
	if forceUpdate {
		return true
	}

	// If we've never checked before
	if info.LastCheck.IsZero() {
		return true
	}

	// Check if 24 hours have passed since last check
	return time.Since(info.LastCheck) >= 24*time.Hour
}

// LoadConfig loads the configuration from file or downloads it if not present
func LoadConfig(forceUpdate bool) (*Config, error) {
	// Get configuration directory
	configDir, err := getConfigDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get config directory: %v", err)
	}

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %v", err)
	}

	configPath := filepath.Join(configDir, "gitleaks.toml")
	url := "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"

	// Load update info
	updateInfo, err := loadUpdateInfo(configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load update info: %v", err)
	}

	// Check if file exists
	fileExists := false
	if _, err := os.Stat(configPath); err == nil {
		fileExists = true
	}

	// If file exists and we should check for updates
	if fileExists && shouldCheckForUpdates(updateInfo, forceUpdate) {
		localHash, err := getLocalFileHash(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to get local file hash: %v", err)
		}

		remoteHash, err := getRemoteFileHash(url)
		if err != nil {
			return nil, fmt.Errorf("failed to get remote file hash: %v", err)
		}

		// If hashes are different or force update is true, update the file
		if localHash != remoteHash || forceUpdate {
			fmt.Println("Updating gitleaks configuration...")
			if err := downloadGitleaksConfig(configPath); err != nil {
				return nil, fmt.Errorf("failed to update gitleaks config: %v", err)
			}
			fmt.Println("Gitleaks configuration updated successfully")
		}

		// Update the last check time and hash
		updateInfo.LastCheck = time.Now()
		updateInfo.LastHash = remoteHash
		if err := saveUpdateInfo(configDir, updateInfo); err != nil {
			return nil, fmt.Errorf("failed to save update info: %v", err)
		}
	} else if !fileExists {
		// Download if file doesn't exist
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
