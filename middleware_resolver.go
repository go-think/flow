package flow

import (
	"fmt"
	"strings"
)

// MiddlewareNameResolver resolves middleware aliases and groups into their
// concrete entries (Laravel: MiddlewareNameResolver).
type MiddlewareNameResolver struct {
	aliases map[string]any
	groups  map[string][]any
}

// NewMiddlewareNameResolver creates a resolver from the alias and group tables.
func NewMiddlewareNameResolver(aliases map[string]any, groups map[string][]any) *MiddlewareNameResolver {
	return &MiddlewareNameResolver{aliases: aliases, groups: groups}
}

// Resolve expands a middleware entry (alias, group name, or "alias:params")
// into its concrete list. Group references are recursively expanded with
// self-reference detection (Laravel: parseMiddlewareGroup).
func (r *MiddlewareNameResolver) Resolve(name string) ([]any, error) {
	// Group expansion
	if _, isGroup := r.groups[name]; isGroup {
		return r.resolveEntries(name, nil)
	}
	// Alias resolution with :params suffix preservation
	aliasName, aliasParams := splitAliasParams(name)
	if alias, ok := r.aliases[aliasName]; ok {
		if aliasParams != "" {
			return []any{fmt.Sprintf("%v:%s", alias, aliasParams)}, nil
		}
		return []any{alias}, nil
	}
	return nil, fmt.Errorf("flow: middleware [%s] not found as group or alias", name)
}

// splitAliasParams splits "alias:param1,param2" into alias and params.
func splitAliasParams(name string) (string, string) {
	if idx := strings.Index(name, ":"); idx != -1 {
		return name[:idx], name[idx+1:]
	}
	return name, ""
}

// resolveEntries is the internal recursive expansion.
func (r *MiddlewareNameResolver) resolveEntries(name string, seen []string) ([]any, error) {
	for _, s := range seen {
		if s == name {
			return nil, fmt.Errorf("flow: [%s] middleware group is referencing itself", name)
		}
	}

	entries, ok := r.groups[name]
	if !ok {
		return nil, fmt.Errorf("flow: middleware group [%s] not defined", name)
	}

	var out []any
	for _, entry := range entries {
		if entryName, isStr := entry.(string); isStr {
			if idx := strings.Index(entryName, ":"); idx != -1 {
				entryName = entryName[:idx]
			}
			for _, s := range seen {
				if s == entryName {
					return nil, fmt.Errorf("flow: [%s] middleware group is referencing itself", entryName)
				}
			}
			if _, isGroup := r.groups[entryName]; isGroup {
				sub, err := r.resolveEntries(entryName, append(seen, name))
				if err != nil {
					return nil, err
				}
				out = append(out, sub...)
				continue
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

// Resolve expands an alias or group recursively with self-reference detection
// (Laravel: MiddlewareNameResolver::resolve + parseMiddlewareGroup).
func (r *router) resolveMiddlewareName(name string) ([]any, error) {
	resolver := NewMiddlewareNameResolver(r.middlewareAliases, r.middlewareGroups)
	if _, isGroup := r.middlewareGroups[name]; isGroup {
		return resolver.resolveEntries(name, nil)
	}
	if alias, ok := r.middlewareAliases[name]; ok {
		return []any{alias}, nil
	}
	return nil, fmt.Errorf("flow: middleware [%s] not found", name)
}
