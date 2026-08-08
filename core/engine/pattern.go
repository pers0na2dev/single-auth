package engine

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

type segmentKind uint8

const (
	segmentStatic segmentKind = iota
	segmentParameter
	segmentWildcard
)

type routeSegment struct {
	kind  segmentKind
	value string
}

type routePattern struct {
	raw      string
	shape    string
	segments []routeSegment
	rank     []uint8
}

func compileRoutePattern(path string) (routePattern, error) {
	if path == "" || path[0] != '/' {
		return routePattern{}, fmt.Errorf("path must start with '/'")
	}
	if strings.ContainsAny(path, "?#") {
		return routePattern{}, fmt.Errorf("path must not contain query or fragment data")
	}

	rawSegments := splitPath(path)
	segments := make([]routeSegment, 0, len(rawSegments))
	ranks := make([]uint8, 0, len(rawSegments))
	shapeParts := make([]string, 0, len(rawSegments))
	parameterNames := make(map[string]struct{})
	for index, raw := range rawSegments {
		if raw == "" && index != len(rawSegments)-1 {
			return routePattern{}, fmt.Errorf("path contains an empty segment")
		}

		switch {
		case raw == "*" || raw == "**" || strings.HasPrefix(raw, "*"):
			if index != len(rawSegments)-1 {
				return routePattern{}, fmt.Errorf("wildcard must be the final segment")
			}
			name := strings.TrimPrefix(raw, "*")
			name = strings.TrimPrefix(name, "*")
			if name == "" {
				name = "*"
			}
			if name != "*" && !validParameterName(name) {
				return routePattern{}, fmt.Errorf("invalid wildcard name %q", name)
			}
			segments = append(segments, routeSegment{kind: segmentWildcard, value: name})
			ranks = append(ranks, 1)
			shapeParts = append(shapeParts, "*")
		case strings.HasPrefix(raw, ":"):
			name := strings.TrimPrefix(raw, ":")
			if !validParameterName(name) {
				return routePattern{}, fmt.Errorf("invalid parameter name %q", name)
			}
			if _, duplicate := parameterNames[name]; duplicate {
				return routePattern{}, fmt.Errorf("duplicate parameter name %q", name)
			}
			parameterNames[name] = struct{}{}
			segments = append(segments, routeSegment{kind: segmentParameter, value: name})
			ranks = append(ranks, 2)
			shapeParts = append(shapeParts, ":")
		default:
			value, err := url.PathUnescape(raw)
			if err != nil {
				return routePattern{}, fmt.Errorf("invalid escaped static segment %q: %w", raw, err)
			}
			segments = append(segments, routeSegment{kind: segmentStatic, value: value})
			ranks = append(ranks, 3)
			shapeParts = append(shapeParts, "s:"+value)
		}
	}

	return routePattern{
		raw:      path,
		shape:    strings.Join(shapeParts, "\x00"),
		segments: segments,
		rank:     ranks,
	}, nil
}

func validParameterName(name string) bool {
	if name == "" {
		return false
	}
	for index, r := range name {
		if index == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && r != '-' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func splitPath(path string) []string {
	if path == "/" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(path, "/"), "/")
}

func decodeRequestPath(rawPath string) ([]string, error) {
	if queryIndex := strings.IndexByte(rawPath, '?'); queryIndex >= 0 {
		rawPath = rawPath[:queryIndex]
	}
	if rawPath == "" || rawPath[0] != '/' {
		return nil, fmt.Errorf("request path must start with '/'")
	}
	rawSegments := splitPath(rawPath)
	segments := make([]string, len(rawSegments))
	for index, raw := range rawSegments {
		decoded, err := url.PathUnescape(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid escaped path segment %q: %w", raw, err)
		}
		segments[index] = decoded
	}
	return segments, nil
}

func (pattern routePattern) match(segments []string) (map[string]string, bool) {
	return pattern.matchRequest(segments, false)
}

func (pattern routePattern) matchRequest(
	segments []string,
	skipTrailingSlashes bool,
) (map[string]string, bool) {
	patternSegments := pattern.segments
	if skipTrailingSlashes {
		if len(patternSegments) > 0 {
			last := patternSegments[len(patternSegments)-1]
			if last.kind == segmentStatic && last.value == "" {
				patternSegments = patternSegments[:len(patternSegments)-1]
			}
		}
		if len(segments) > 0 && segments[len(segments)-1] == "" {
			segments = segments[:len(segments)-1]
		}
	}

	params := make(map[string]string)
	for index, segment := range patternSegments {
		if segment.kind == segmentWildcard {
			if index > len(segments) {
				return nil, false
			}
			params[segment.value] = strings.Join(segments[index:], "/")
			return params, true
		}
		if index >= len(segments) {
			return nil, false
		}
		switch segment.kind {
		case segmentStatic:
			if segments[index] != segment.value {
				return nil, false
			}
		case segmentParameter:
			if segments[index] == "" {
				return nil, false
			}
			params[segment.value] = segments[index]
		}
	}
	if len(segments) != len(patternSegments) {
		return nil, false
	}
	return params, true
}

func comparePatternSpecificity(left, right routePattern) int {
	length := len(left.rank)
	if len(right.rank) < length {
		length = len(right.rank)
	}
	for index := 0; index < length; index++ {
		if left.rank[index] > right.rank[index] {
			return 1
		}
		if left.rank[index] < right.rank[index] {
			return -1
		}
	}
	if len(left.rank) > len(right.rank) {
		return 1
	}
	if len(left.rank) < len(right.rank) {
		return -1
	}
	return 0
}
