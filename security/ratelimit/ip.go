package ratelimit

import (
	"net/netip"
	"strconv"
	"strings"
)

var defaultIPHeaders = []string{"x-forwarded-for"}

// IsValidIP reports whether value is a syntactically valid IPv4 or IPv6
// address. Zone-qualified IPv6 addresses are intentionally rejected.
func IsValidIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Zone() == ""
}

// NormalizeIP applies reference implementation's address canonicalization. IPv4-mapped
// IPv6 addresses become IPv4. IPv6 addresses are expanded to eight lowercase
// groups and masked to /64 unless an explicit prefix is supplied.
func NormalizeIP(value string, ipv6Subnet *int) string {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return strings.ToLower(value)
	}
	address = address.Unmap()
	if address.Is4() {
		return address.String()
	}
	prefix := 64
	if ipv6Subnet != nil {
		prefix = *ipv6Subnet
	}
	if prefix < 128 {
		if prefix < 0 {
			prefix = 0
		}
		address = netip.PrefixFrom(address, prefix).Masked().Addr()
	}
	return expandedIPv6(address)
}

func expandedIPv6(address netip.Addr) string {
	bytes := address.As16()
	var builder strings.Builder
	builder.Grow(39)
	const hex = "0123456789abcdef"
	for index, value := range bytes {
		if index > 0 && index%2 == 0 {
			builder.WriteByte(':')
		}
		builder.WriteByte(hex[value>>4])
		builder.WriteByte(hex[value&0x0f])
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

// FindInvalidTrustedProxies returns configured proxy entries that are neither
// a valid bare IP nor a valid IP/prefix range, preserving input order.
func FindInvalidTrustedProxies(entries []string) []string {
	invalid := make([]string, 0)
	for _, entry := range entries {
		if _, valid := parseTrustedNetwork(entry); !valid {
			invalid = append(invalid, entry)
		}
	}
	return invalid
}

// GetIPFromHeader resolves a trustworthy client from one forwarded header.
// Without a valid trusted-proxy configuration only a single address is
// accepted. With one, proxy hops are stripped from right to left.
func GetIPFromHeader(value string, ipv6Subnet *int, trustedProxies []string) string {
	parts := strings.Split(value, ",")
	forwarded := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			forwarded = append(forwarded, part)
		}
	}
	if len(forwarded) == 0 {
		return ""
	}

	trusted := make([]trustedNetwork, 0, len(trustedProxies))
	for _, configured := range trustedProxies {
		if network, valid := parseTrustedNetwork(configured); valid {
			trusted = append(trusted, network)
		}
	}
	if len(trusted) > 0 {
		for index := len(forwarded) - 1; index >= 0; index-- {
			address, err := netip.ParseAddr(forwarded[index])
			if err != nil || address.Zone() != "" {
				return ""
			}
			isTrusted := false
			for _, network := range trusted {
				if network.contains(address) {
					isTrusted = true
					break
				}
			}
			if !isTrusted {
				return NormalizeIP(forwarded[index], ipv6Subnet)
			}
		}
		return ""
	}

	if len(forwarded) != 1 || !IsValidIP(forwarded[0]) {
		return ""
	}
	return NormalizeIP(forwarded[0], ipv6Subnet)
}

// GetIP resolves a client IP from configured headers. It returns an empty
// string when tracking is disabled or no trustworthy value exists.
func GetIP(headers HeaderGetter, options IPOptions) string {
	if options.DisableTracking {
		return ""
	}
	names := options.Headers
	if names == nil {
		names = defaultIPHeaders
	}
	if headers != nil {
		for _, name := range names {
			if value := headers.Get(name); value != "" {
				if ip := GetIPFromHeader(value, options.IPv6Subnet, options.TrustedProxies); ip != "" {
					return ip
				}
			}
		}
	}
	if options.Development || options.Test {
		return "127.0.0.1"
	}
	return ""
}

// CreateKey separates the IP and path so attacker-controlled concatenations
// cannot collide.
func CreateKey(ip, path string) string { return ip + "|" + path }
