package flow

import (
	"fmt"
	"reflect"
	"strings"
)

// MiddlewareNameResolver resolves middleware aliases and groups into their
// concrete entries.
type MiddlewareNameResolver struct {
	aliases map[string]any
	groups  map[string][]any
}

// NewMiddlewareNameResolver creates a resolver from the alias and group tables.
func NewMiddlewareNameResolver(aliases map[string]any, groups map[string][]any) *MiddlewareNameResolver {
	return &MiddlewareNameResolver{aliases: aliases, groups: groups}
}

// Resolve expands a middleware entry (alias, group name, or "alias:params")
// into its concrete list. First the full name is checked against the alias map
// and honored only when the mapped value is a Closure; then an exact group name
// is expanded recursively with self-reference detection; finally the name is
// split on the first ":" and the alias head resolved with the ":params" suffix
// re-appended. Unknown names pass through unchanged so the pipeline can surface
// the problem.
func (r *MiddlewareNameResolver) Resolve(name string) ([]any, error) {
	// A full-string alias hit wins before the group lookup, but only when the
	// mapped value is a Closure; string aliases with parameters are resolved
	// through the split below.
	if alias, ok := r.aliases[name]; ok && isClosureValue(alias) {
		return []any{alias}, nil
	}
	// Group expansion is by exact name: "web:foo" is not
	// a group name and never expands group "web".
	if _, isGroup := r.groups[name]; isGroup {
		return r.resolveEntries(name, nil)
	}
	// Alias resolution preserving the ":params" suffix. A Closure alias is
	// returned as-is without parameter concatenation.
	aliasName, aliasParams := splitAliasParams(name)
	if alias, ok := r.aliases[aliasName]; ok {
		if aliasParams != "" {
			switch alias.(type) {
			case string:
				return []any{fmt.Sprintf("%v:%s", alias, aliasParams)}, nil
			default:
				return []any{alias}, nil
			}
		}
		return []any{alias}, nil
	}
	// Unknown middleware passes through with its parameters.
	if aliasParams != "" {
		return []any{fmt.Sprintf("%s:%s", aliasName, aliasParams)}, nil
	}
	return []any{name}, nil
}

// splitAliasParams splits "alias:param1,param2" into alias and params.
func splitAliasParams(name string) (string, string) {
	if idx := strings.Index(name, ":"); idx != -1 {
		return name[:idx], name[idx+1:]
	}
	return name, ""
}

// isClosureValue reports whether the middleware entry is a closure/func value.
func isClosureValue(v any) bool {
	return v != nil && reflect.ValueOf(v).Kind() == reflect.Func
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
			// Group membership uses the full entry string, so "web:foo" does not
			// expand group "web".
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
			// A group member that is an alias is replaced by its target with
			// the ":params" suffix re-appended.
			head, params := splitAliasParams(entryName)
			if alias, ok := r.aliases[head]; ok {
				if params != "" {
					if target, isTargetStr := alias.(string); isTargetStr {
						out = append(out, target+":"+params)
						continue
					}
				} else {
					out = append(out, alias)
					continue
				}
			}
		}
		out = append(out, entry)
	}
	return out, nil
}
