// Package hostutil classifies hosts for loopback checks and SSRF gates.
//
// Its behavior follows the reference implementation 1.6.26's RFC 6890, RFC 6761, and RFC 8252
// host utilities, including IPv4-mapped IPv6 and tunnel/translation forms.
package hostutil

import (
	"net/netip"
	"strings"
)

// HostKind is the semantic classification of a host.
type HostKind string

const (
	KindLoopback           HostKind = "loopback"
	KindLocalhost          HostKind = "localhost"
	KindUnspecified        HostKind = "unspecified"
	KindPrivate            HostKind = "private"
	KindLinkLocal          HostKind = "linkLocal"
	KindSharedAddressSpace HostKind = "sharedAddressSpace"
	KindDocumentation      HostKind = "documentation"
	KindBenchmarking       HostKind = "benchmarking"
	KindMulticast          HostKind = "multicast"
	KindBroadcast          HostKind = "broadcast"
	KindReserved           HostKind = "reserved"
	KindCloudMetadata      HostKind = "cloudMetadata"
	KindPublic             HostKind = "public"
)

// HostLiteral identifies the normalized syntactic form of a host.
type HostLiteral string

const (
	LiteralIPv4 HostLiteral = "ipv4"
	LiteralIPv6 HostLiteral = "ipv6"
	LiteralFQDN HostLiteral = "fqdn"
)

// HostClassification is the normalized result returned by ClassifyHost.
type HostClassification struct {
	Kind      HostKind    `json:"kind"`
	Literal   HostLiteral `json:"literal"`
	Canonical string      `json:"canonical"`
}

var cloudMetadataHosts = map[string]struct{}{
	"metadata.google.internal":   {},
	"metadata.goog":              {},
	"metadata":                   {},
	"instance-data":              {},
	"instance-data.ec2.internal": {},
}

var (
	ipv4Loopback      = netip.MustParsePrefix("127.0.0.0/8")
	ipv4Private10     = netip.MustParsePrefix("10.0.0.0/8")
	ipv4Private172    = netip.MustParsePrefix("172.16.0.0/12")
	ipv4Private192    = netip.MustParsePrefix("192.168.0.0/16")
	ipv4LinkLocal     = netip.MustParsePrefix("169.254.0.0/16")
	ipv4Shared        = netip.MustParsePrefix("100.64.0.0/10")
	ipv4Documentation = [...]netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	ipv4Benchmarking = netip.MustParsePrefix("198.18.0.0/15")
	ipv4Multicast    = netip.MustParsePrefix("224.0.0.0/4")
	ipv4ReservedZero = netip.MustParsePrefix("0.0.0.0/8")
	ipv4ReservedIETF = netip.MustParsePrefix("192.0.0.0/24")
	ipv4ReservedHigh = netip.MustParsePrefix("240.0.0.0/4")

	ipv6Documentation  = netip.MustParsePrefix("2001:db8::/32")
	ipv6Benchmarking   = netip.MustParsePrefix("2001:2::/48")
	ipv6SixToFour      = netip.MustParsePrefix("2002::/16")
	ipv6NAT64          = netip.MustParsePrefix("64:ff9b::/96")
	ipv6LocalNAT64     = netip.MustParsePrefix("64:ff9b:1::/48")
	ipv6Teredo         = netip.MustParsePrefix("2001::/32")
	ipv6Discard        = netip.MustParsePrefix("100::/64")
	ipv6Documentation2 = netip.MustParsePrefix("3fff::/20")
	ipv6SRv6           = netip.MustParsePrefix("5f00::/16")
)

// ClassifyHost normalizes and classifies an IPv4 literal, IPv6 literal, or
// FQDN. Structurally invalid non-empty input follows the reference implementation and is treated
// as a public FQDN; callers that need syntax validation must do that separately.
func ClassifyHost(host string) HostClassification {
	normalized := strings.TrimSpace(host)
	normalized = stripPort(normalized)
	normalized = stripBrackets(normalized)
	normalized = stripZoneID(normalized)
	normalized = strings.TrimRight(normalized, ".")
	normalized = strings.ToLower(normalized)

	if normalized == "" {
		return HostClassification{Kind: KindReserved, Literal: LiteralFQDN, Canonical: ""}
	}

	address, err := netip.ParseAddr(normalized)
	if err != nil {
		if normalized == "localhost" || strings.HasSuffix(normalized, ".localhost") {
			return HostClassification{Kind: KindLocalhost, Literal: LiteralFQDN, Canonical: normalized}
		}
		if _, ok := cloudMetadataHosts[normalized]; ok {
			return HostClassification{Kind: KindCloudMetadata, Literal: LiteralFQDN, Canonical: normalized}
		}
		return HostClassification{Kind: KindPublic, Literal: LiteralFQDN, Canonical: normalized}
	}

	if address.Is4() || address.Is4In6() {
		address = address.Unmap()
		canonical := address.String()
		return HostClassification{
			Kind:      classifyIPv4(address),
			Literal:   LiteralIPv4,
			Canonical: canonical,
		}
	}

	return HostClassification{
		Kind:      classifyIPv6(address),
		Literal:   LiteralIPv6,
		Canonical: address.StringExpanded(),
	}
}

// IsLoopbackIP reports whether host is an IPv4 127/8 or IPv6 ::1 literal.
// Unlike IsLoopbackHost, DNS names such as localhost are rejected.
func IsLoopbackIP(host string) bool {
	return ClassifyHost(host).Kind == KindLoopback
}

// IsLoopbackHost accepts loopback IP literals, localhost, and .localhost
// subdomains.
func IsLoopbackHost(host string) bool {
	kind := ClassifyHost(host).Kind
	return kind == KindLoopback || kind == KindLocalhost
}

// IsPublicRoutableHost is a syntactic SSRF gate. It accepts only hosts whose
// classification is public; it does not perform DNS resolution.
func IsPublicRoutableHost(host string) bool {
	return ClassifyHost(host).Kind == KindPublic
}

func stripPort(host string) string {
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end == -1 {
			return host
		}
		return host[:end+1]
	}
	first := strings.IndexByte(host, ':')
	if first == -1 || strings.IndexByte(host[first+1:], ':') != -1 {
		return host
	}
	return host[:first]
}

func stripBrackets(host string) string {
	if len(host) >= 2 && strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}

func stripZoneID(host string) string {
	if index := strings.IndexByte(host, '%'); index != -1 {
		return host[:index]
	}
	return host
}

func classifyIPv4(address netip.Addr) HostKind {
	if address == netip.IPv4Unspecified() {
		return KindUnspecified
	}
	if address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return KindBroadcast
	}
	if ipv4Loopback.Contains(address) {
		return KindLoopback
	}
	if ipv4Private10.Contains(address) || ipv4Private172.Contains(address) || ipv4Private192.Contains(address) {
		return KindPrivate
	}
	if ipv4LinkLocal.Contains(address) {
		return KindLinkLocal
	}
	if ipv4Shared.Contains(address) {
		return KindSharedAddressSpace
	}
	for _, prefix := range ipv4Documentation {
		if prefix.Contains(address) {
			return KindDocumentation
		}
	}
	if ipv4Benchmarking.Contains(address) {
		return KindBenchmarking
	}
	if ipv4Multicast.Contains(address) {
		return KindMulticast
	}
	if ipv4ReservedZero.Contains(address) || ipv4ReservedIETF.Contains(address) || ipv4ReservedHigh.Contains(address) {
		return KindReserved
	}
	return KindPublic
}

func classifyIPv6(address netip.Addr) HostKind {
	if address.IsUnspecified() {
		return KindUnspecified
	}
	if address == netip.IPv6Loopback() {
		return KindLoopback
	}

	bytes := address.As16()
	if bytes[0] == 0xff {
		return KindMulticast
	}
	if bytes[0] == 0xfe && bytes[1]&0xc0 == 0x80 {
		return KindLinkLocal
	}
	if bytes[0]&0xfe == 0xfc {
		return KindPrivate
	}
	if ipv6Documentation.Contains(address) {
		return KindDocumentation
	}
	if ipv6Benchmarking.Contains(address) {
		return KindBenchmarking
	}
	if ipv6SixToFour.Contains(address) {
		embedded := netip.AddrFrom4([4]byte{bytes[2], bytes[3], bytes[4], bytes[5]})
		if classifyIPv4(embedded) != KindPublic {
			return KindReserved
		}
		return KindPublic
	}
	if ipv6NAT64.Contains(address) || ipv6LocalNAT64.Contains(address) || ipv6Teredo.Contains(address) || ipv6Discard.Contains(address) || ipv6SRv6.Contains(address) {
		return KindReserved
	}
	if ipv6Documentation2.Contains(address) {
		return KindDocumentation
	}
	return KindPublic
}
