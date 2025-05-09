package utils

import (
	"strings"
)

// Contains checks if a string slice contains a specific string
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// IsJavaScriptFile checks if a URL points to a JavaScript file
func IsJavaScriptFile(url string) bool {
	return strings.HasSuffix(url, ".js")
}

// IsThirdPartyDomain checks if a URL belongs to a third-party service
func IsThirdPartyDomain(url string) bool {
	thirdPartyDomains := []string{
		"facebook.net",
		"connect.facebook.net",
		"googleapis.com",
		"google-analytics.com",
		"googletagmanager.com",
		"doubleclick.net",
		"cloudflare.com",
		"cloudfront.net",
		"cdnjs.cloudflare.com",
		"ajax.googleapis.com",
		"maps.googleapis.com",
		"youtube.com",
		"youtu.be",
		"twitter.com",
		"twimg.com",
		"linkedin.com",
		"amazonaws.com",
		"cloudinary.com",
		"jsdelivr.net",
		"unpkg.com",
		"bootstrapcdn.com",
		"jquery.com",
		"microsoft.com",
		"microsoftonline.com",
		"bing.com",
		"bingapis.com",
	}

	for _, domain := range thirdPartyDomains {
		if strings.Contains(url, domain) {
			return true
		}
	}
	return false
}
