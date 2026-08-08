package siwe

import (
	"regexp"
	"strconv"
	"strings"
)

// ParsedMessage contains the ERC-4361 fields that the server independently
// validates before calling the application verifier.
type ParsedMessage struct {
	Scheme         string `json:"scheme,omitempty"`
	Domain         string `json:"domain,omitempty"`
	Address        string `json:"address,omitempty"`
	URI            string `json:"uri,omitempty"`
	Version        string `json:"version,omitempty"`
	ChainID        int64  `json:"chainId,omitempty"`
	HasChainID     bool   `json:"-"`
	Nonce          string `json:"nonce,omitempty"`
	IssuedAt       string `json:"issuedAt,omitempty"`
	ExpirationTime string `json:"expirationTime,omitempty"`
	NotBefore      string `json:"notBefore,omitempty"`
	RequestID      string `json:"requestId,omitempty"`
}

var (
	headerPattern  = regexp.MustCompile(`^(?:([a-zA-Z][a-zA-Z0-9+.-]*):\/\/)?(\S+) wants you to sign in with your Ethereum account:$`)
	addressPattern = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
	fieldPattern   = regexp.MustCompile(`^([A-Za-z ]+): (.*)$`)
)

// ParseMessage is the tolerant parser used by single-auth 1.6.26. Missing or
// malformed fields are left empty and are rejected by the binding step.
func ParseMessage(message string) ParsedMessage {
	result := ParsedMessage{}
	lines := strings.Split(strings.ReplaceAll(message, "\r\n", "\n"), "\n")
	if len(lines) != 0 {
		if match := headerPattern.FindStringSubmatch(lines[0]); match != nil {
			result.Scheme = match[1]
			result.Domain = match[2]
		}
	}
	if len(lines) > 1 {
		address := strings.TrimSpace(lines[1])
		if addressPattern.MatchString(address) {
			result.Address = address
		}
	}
	for _, line := range lines {
		match := fieldPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		value := match[2]
		switch match[1] {
		case "URI":
			result.URI = value
		case "Version":
			result.Version = value
		case "Chain ID":
			if parsed, ok := parseJavaScriptInteger(value); ok {
				result.ChainID = parsed
				result.HasChainID = true
			}
		case "Nonce":
			result.Nonce = value
		case "Issued At":
			result.IssuedAt = value
		case "Expiration Time":
			result.ExpirationTime = value
		case "Not Before":
			result.NotBefore = value
		case "Request ID":
			result.RequestID = value
		}
	}
	return result
}

func parseJavaScriptInteger(input string) (int64, bool) {
	value := strings.TrimSpace(input)
	if value == "" {
		return 0, true
	}
	for _, candidate := range []struct {
		prefix string
		base   int
	}{{"0x", 16}, {"0X", 16}, {"0b", 2}, {"0B", 2}, {"0o", 8}, {"0O", 8}} {
		if strings.HasPrefix(value, candidate.prefix) {
			parsed, err := strconv.ParseUint(value[len(candidate.prefix):], candidate.base, 63)
			if err != nil {
				return 0, false
			}
			return int64(parsed), true
		}
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed != float64(int64(parsed)) {
		return 0, false
	}
	return int64(parsed), true
}

// NormalizeDomain strips scheme and path and lowercases the RFC 3986
// authority, exactly like the frozen plugin.
func NormalizeDomain(domain string) string {
	value := strings.ToLower(strings.TrimSpace(domain))
	if scheme := regexp.MustCompile(`^[a-z][a-z0-9+.-]*:\/\/`).FindStringIndex(value); scheme != nil {
		value = value[scheme[1]:]
	}
	if slash := strings.IndexByte(value, '/'); slash >= 0 {
		value = value[:slash]
	}
	return value
}
