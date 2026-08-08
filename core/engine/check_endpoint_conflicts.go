package engine

import "strings"

// EndpointConflictLogger is the logging surface used by
// CheckEndpointConflicts. logger.Logger satisfies this interface.
type EndpointConflictLogger interface {
	Error(message string, args ...any)
}

// PluginEndpointConflict is the path-level conflict report emitted by Better
// Auth before its router is built. Unlike EndpointConflict, this value keeps
// the plugin-oriented shape and method ordering used by the upstream
// checkEndpointConflicts helper.
type PluginEndpointConflict struct {
	Path               string
	Plugins            []string
	ConflictingMethods []string
}

type pluginEndpointEntry struct {
	pluginID string
	methods  []string
}

// CheckEndpointConflicts detects exact-path overlaps between plugin endpoints
// with the reference implementation's method semantics. An endpoint without methods occupies the
// wildcard method. Pathless endpoints are direct-only declarations for this
// preflight and are ignored.
//
// When one or more conflicts are found, logger receives exactly one aggregate
// error message. The returned slice is a Go convenience; the reference implementation exposes
// the same information only through that log entry.
func CheckEndpointConflicts(plugins []Plugin, logger EndpointConflictLogger) []PluginEndpointConflict {
	registry := make(map[string][]pluginEndpointEntry)
	pathOrder := make([]string, 0)
	for _, plugin := range plugins {
		for _, endpoint := range plugin.Endpoints {
			if endpoint.Path == "" {
				continue
			}
			methods := append([]string(nil), endpoint.Methods...)
			if len(methods) == 0 {
				methods = []string{anyMethod}
			}
			if _, exists := registry[endpoint.Path]; !exists {
				pathOrder = append(pathOrder, endpoint.Path)
			}
			registry[endpoint.Path] = append(registry[endpoint.Path], pluginEndpointEntry{
				pluginID: plugin.ID,
				methods:  methods,
			})
		}
	}

	conflicts := make([]PluginEndpointConflict, 0)
	for _, path := range pathOrder {
		entries := registry[path]
		if len(entries) < 2 {
			continue
		}

		methodPlugins := make(map[string][]string)
		methodOrder := make([]string, 0)
		hasConflict := false
		for _, entry := range entries {
			for _, method := range entry.methods {
				if _, exists := methodPlugins[method]; !exists {
					methodOrder = append(methodOrder, method)
				}
				methodPlugins[method] = append(methodPlugins[method], entry.pluginID)
				if len(methodPlugins[method]) > 1 {
					hasConflict = true
				}
				if method == anyMethod && len(entries) > 1 {
					hasConflict = true
				} else if method != anyMethod {
					if _, wildcardSeen := methodPlugins[anyMethod]; wildcardSeen {
						hasConflict = true
					}
				}
			}
		}
		if !hasConflict {
			continue
		}

		pluginsForPath := make([]string, 0, len(entries))
		seenPlugins := make(map[string]struct{}, len(entries))
		for _, entry := range entries {
			if _, seen := seenPlugins[entry.pluginID]; seen {
				continue
			}
			seenPlugins[entry.pluginID] = struct{}{}
			pluginsForPath = append(pluginsForPath, entry.pluginID)
		}

		conflictingMethods := make([]string, 0, len(methodOrder))
		_, wildcardPresent := methodPlugins[anyMethod]
		for _, method := range methodOrder {
			if len(methodPlugins[method]) > 1 ||
				(method == anyMethod && len(entries) > 1) ||
				(method != anyMethod && wildcardPresent) {
				conflictingMethods = append(conflictingMethods, method)
			}
		}
		conflicts = append(conflicts, PluginEndpointConflict{
			Path:               path,
			Plugins:            pluginsForPath,
			ConflictingMethods: conflictingMethods,
		})
	}

	if len(conflicts) > 0 && logger != nil {
		logger.Error(formatPluginEndpointConflictMessage(conflicts))
	}
	return conflicts
}

func formatPluginEndpointConflictMessage(conflicts []PluginEndpointConflict) string {
	messages := make([]string, len(conflicts))
	for index, conflict := range conflicts {
		messages[index] = `  - "` + conflict.Path + `" [` +
			strings.Join(conflict.ConflictingMethods, ", ") +
			"] used by plugins: " + strings.Join(conflict.Plugins, ", ")
	}
	return "Endpoint path conflicts detected! Multiple plugins are trying to use the same endpoint paths with conflicting HTTP methods:\n" +
		strings.Join(messages, "\n") +
		"\n\nTo resolve this, you can:\n" +
		"\t1. Use only one of the conflicting plugins\n" +
		"\t2. Configure the plugins to use different paths (if supported)\n" +
		"\t3. Ensure plugins use different HTTP methods for the same path\n"
}
