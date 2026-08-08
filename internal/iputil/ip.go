// Package iputil implements the reference implementation 1.6.26 IP normalization and trusted
// proxy selection without depending on a particular HTTP transport.
package iputil

import (
	"net/netip"
	"strconv"
	"strings"
)

// NormalizeOptions controls IPv6 prefix collapsing. A nil IPv6Subnet selects
// the reference implementation's /64 default; a pointer to zero deliberately masks all bits.
type NormalizeOptions struct {
	IPv6Subnet *int
}

// HeaderOptions controls normalization and trusted-proxy chain processing.
type HeaderOptions struct {
	IPv6Subnet     *int
	TrustedProxies []string
}

// IPv6Prefix returns a prefix pointer suitable for NormalizeOptions and
// HeaderOptions while preserving an explicit /0.
func IPv6Prefix(bits int) *int { return &bits }

// IsValidIP reports whether value is a syntactically valid IPv4 or IPv6
// address. Zone-qualified IPv6 addresses are rejected, matching the upstream
// Zod validators.
func IsValidIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Zone() == ""
}

// NormalizeIP canonicalizes an address for stable rate-limit keys. IPv4 is
// unchanged, IPv4-mapped IPv6 becomes IPv4, and ordinary IPv6 is expanded to
// eight lowercase groups and collapsed to /64 unless explicitly configured.
func NormalizeIP(value string, supplied ...NormalizeOptions) string {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return strings.ToLower(value)
	}
	address = address.Unmap()
	if address.Is4() {
		return address.String()
	}

	prefix := 64
	if len(supplied) > 0 && supplied[0].IPv6Subnet != nil {
		prefix = *supplied[0].IPv6Subnet
	}
	if prefix < 128 {
		if prefix < 0 {
			prefix = 0
		}
		address = netip.PrefixFrom(address, prefix).Masked().Addr()
	}
	return expandedIPv6(address)
}

// CreateRateLimitKey separates an IP and request path to prevent ambiguous
// concatenations from sharing a bucket.
func CreateRateLimitKey(ip, path string) string { return ip + "|" + path }

// GetIPFromHeader selects a trustworthy client IP from one forwarded header.
// Without at least one valid trusted proxy, only a single-value header is
// accepted. With trusted proxies, hops are stripped from right to left and a
// malformed hop fails closed. Nil means no trustworthy address was resolved.
func GetIPFromHeader(value string, supplied ...HeaderOptions) *string {
	options := HeaderOptions{}
	if len(supplied) > 0 {
		options = supplied[0]
	}

	parts := strings.Split(value, ",")
	forwarded := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			forwarded = append(forwarded, part)
		}
	}
	if len(forwarded) == 0 {
		return nil
	}

	trusted := make([]trustedNetwork, 0, len(options.TrustedProxies))
	for _, configured := range options.TrustedProxies {
		if network, valid := parseTrustedNetwork(configured); valid {
			trusted = append(trusted, network)
		}
	}
	if len(trusted) > 0 {
		for index := len(forwarded) - 1; index >= 0; index-- {
			address, err := netip.ParseAddr(forwarded[index])
			if err != nil || address.Zone() != "" {
				return nil
			}
			isTrusted := false
			for _, network := range trusted {
				if network.contains(address) {
					isTrusted = true
					break
				}
			}
			if isTrusted {
				continue
			}
			normalized := NormalizeIP(forwarded[index], NormalizeOptions{
				IPv6Subnet: options.IPv6Subnet,
			})
			return &normalized
		}
		return nil
	}

	if len(forwarded) != 1 || !IsValidIP(forwarded[0]) {
		return nil
	}
	normalized := NormalizeIP(forwarded[0], NormalizeOptions{
		IPv6Subnet: options.IPv6Subnet,
	})
	return &normalized
}

// FindInvalidTrustedProxies returns entries which are neither a valid bare IP
// nor a valid CIDR range, preserving their original order and spelling.
func FindInvalidTrustedProxies(entries []string) []string {
	invalid := make([]string, 0)
	for _, entry := range entries {
		if _, valid := parseTrustedNetwork(entry); !valid {
			invalid = append(invalid, entry)
		}
	}
	return invalid
}

func expandedIPv6(address netip.Addr) string {
	bytes := address.As16()
	var builder strings.Builder
	builder.Grow(39)
	const hexadecimal = "0123456789abcdef"
	for index, value := range bytes {
		if index > 0 && index%2 == 0 {
			builder.WriteByte(':')
		}
		builder.WriteByte(hexadecimal[value>>4])
		builder.WriteByte(hexadecimal[value&0x0f])
	}
	return builder.String()
}

type trustedNetwork struct {
	address netip.Addr
	prefix  int
}

func parseTrustedNetwork(value string) (trustedNetwork, bool) {
	addressPart := value
	prefix := -1
	if slash := strings.LastIndexByte(value, '/'); slash >= 0 {
		addressPart = value[:slash]
		prefixPart := value[slash+1:]
		if prefixPart == "" {
			return trustedNetwork{}, false
		}
		for _, character := range prefixPart {
			if character < '0' || character > '9' {
				return trustedNetwork{}, false
			}
		}
		parsed, err := strconv.Atoi(prefixPart)
		if err != nil {
			return trustedNetwork{}, false
		}
		prefix = parsed
	}

	address, err := netip.ParseAddr(addressPart)
	if err != nil || address.Zone() != "" {
		return trustedNetwork{}, false
	}
	address = address.Unmap()
	bits := 128
	if address.Is4() {
		bits = 32
	}
	if prefix < 0 {
		prefix = bits
	}
	if prefix > bits {
		return trustedNetwork{}, false
	}
	return trustedNetwork{address: address, prefix: prefix}, true
}

func (network trustedNetwork) contains(address netip.Addr) bool {
	address = address.Unmap()
	if network.address.Is4() != address.Is4() {
		return false
	}
	return netip.PrefixFrom(network.address, network.prefix).Contains(address)
}
