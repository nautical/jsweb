# JSWeb - JavaScript Secret Scanner

JSWeb is a tool that scans web pages for JavaScript files and checks them for potential secrets and sensitive information. It uses the Gitleaks configuration format and Playwright for browser automation.

## Features

- Scans web pages for JavaScript files using Playwright
- Uses Gitleaks rules for secret detection
- Supports entropy-based detection with configurable thresholds
- Advanced allowlist functionality with regex and stopword support
- Provides code snippets with context around matches
- Outputs findings in JSON format
- Rate limiting to avoid overwhelming servers
- Skips third-party domains to reduce noise
- Automatic browser installation and management

## Prerequisites

- Go 1.16 or later
- Playwright browsers (automatically installed on first run)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/nautical/jsweb.git
cd jsweb
```

2. Install dependencies:
```bash
go mod download
```

The Playwright browsers will be automatically installed on first run.

## Usage

Basic usage:
```bash
go run main.go https://example.com
```

The tool will:
1. Install Playwright browsers if not already installed
2. Download the Gitleaks configuration if not present
3. Launch a headless browser
4. Navigate to the specified URL
5. Find all JavaScript files
6. Scan each file for potential secrets
7. Output findings in JSON format

## Output Format

The tool outputs findings in JSON format with the following structure:

```json
{
  "findings": [
    {
      "description": "Description of the finding",
      "file": "URL of the JavaScript file",
      "rule_id": "ID of the rule that matched",
      "tags": ["list", "of", "tags"],
      "secret": "The matched secret",
      "context": "The full match context",
      "line": "Line number where the secret was found",
      "entropy": 4.5,
      "code_snippet": "Code snippet with context around the match"
    }
  ]
}
```

## Configuration

The tool uses the Gitleaks configuration format. The configuration file (`gitleaks.toml`) will be downloaded automatically if not present. You can also provide your own configuration file.

### Rule Structure

```toml
[[rules]]
id = "rule-id"
description = "Description of the rule"
regex = "regex pattern"
secretGroup = 1
entropy = 3.5
path = "path pattern"
keywords = ["keyword1", "keyword2"]
tags = ["javascript", "api-key"]

[[rules.allowlists]]
description = "Allowlist description"
regexTarget = "match"  # Can be "match", "secret", or "line"
regexes = ["regex1", "regex2"]
stopwords = ["word1", "word2"]
condition = "OR"  # Can be "OR" or "AND"
```

### Allowlist Features

- Global and rule-specific allowlists
- Multiple allowlist conditions (AND/OR)
- Target-specific matching (match, secret, or line)
- Regex and stopword support
- Rule targeting for global allowlists

## Third-Party Domains

The tool automatically skips JavaScript files from common third-party domains to reduce noise. This includes:
- CDN services (Cloudflare, jsDelivr, etc.)
- Analytics services (Google Analytics, etc.)
- Social media services (Facebook, Twitter, etc.)
- Cloud services (AWS, Google Cloud, etc.)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details. 