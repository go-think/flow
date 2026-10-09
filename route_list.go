package flow

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
)

// RouteSummary provides a structured description of a registered route.
type RouteSummary struct {
	Methods    []string `json:"methods"`
	URI        string   `json:"uri"`
	Name       string   `json:"name,omitempty"`
	Action     string   `json:"action"`
	Middleware []string `json:"middleware,omitempty"`
	Domain     string   `json:"domain,omitempty"`
}

// Summary returns a structured summary of the route.
func (r *Route) Summary() RouteSummary {
	if r == nil {
		return RouteSummary{}
	}
	return RouteSummary{
		Methods:    r.Methods(),
		URI:        r.URI(),
		Name:       r.GetName(),
		Action:     r.ActionName(),
		Middleware: formatMiddlewareList(r.GetMiddleware()),
		Domain:     r.GetDomain(),
	}
}

// RouteList returns structured summaries for all registered routes.
func (r *router) RouteList() []RouteSummary {
	if r == nil {
		return nil
	}
	root := r.root()
	root.flushPending()
	if root.collection == nil {
		return nil
	}
	routes := root.collection.GetRoutes()
	out := make([]RouteSummary, len(routes))
	for i, route := range routes {
		out[i] = route.Summary()
	}
	return out
}

// RouteList returns structured summaries for all registered routes.
func (c *routeChain) RouteList() []RouteSummary {
	if c == nil || c.router == nil {
		return nil
	}
	return c.router.RouteList()
}

// Summary returns structured summaries for all routes in the collection.
func (c *RouteCollection) Summary() []RouteSummary {
	if c == nil {
		return nil
	}
	routes := c.GetRoutes()
	out := make([]RouteSummary, len(routes))
	for i, route := range routes {
		out[i] = route.Summary()
	}
	return out
}

// FormatRouteList generates a clean human-readable table of all routes.
func (r *router) FormatRouteList() string {
	if r == nil {
		return ""
	}
	return FormatRouteSummaries(r.RouteList())
}

// FormatRouteList generates a clean human-readable table of all routes.
func (c *routeChain) FormatRouteList() string {
	if c == nil || c.router == nil {
		return ""
	}
	return c.router.FormatRouteList()
}

// FormatRouteSummaries formats a slice of RouteSummary into an aligned table string.
func FormatRouteSummaries(summaries []RouteSummary) string {
	if len(summaries) == 0 {
		return "No routes registered."
	}

	headers := []string{"METHOD", "URI", "NAME", "ACTION", "MIDDLEWARE"}
	colWidths := []int{len(headers[0]), len(headers[1]), len(headers[2]), len(headers[3]), len(headers[4])}

	rows := make([][5]string, len(summaries))
	for i, s := range summaries {
		methods := strings.Join(s.Methods, "|")
		name := s.Name
		if name == "" {
			name = "-"
		}
		mw := strings.Join(s.Middleware, ",")
		if mw == "" {
			mw = "-"
		}
		rows[i] = [5]string{methods, s.URI, name, s.Action, mw}

		for j := 0; j < 5; j++ {
			if len(rows[i][j]) > colWidths[j] {
				colWidths[j] = len(rows[i][j])
			}
		}
	}

	var sb strings.Builder
	// Header row
	headerLine := fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %-*s",
		colWidths[0], headers[0],
		colWidths[1], headers[1],
		colWidths[2], headers[2],
		colWidths[3], headers[3],
		colWidths[4], headers[4],
	)
	sb.WriteString(headerLine)
	sb.WriteString("\n")

	// Separator line
	sepLine := fmt.Sprintf("%s  %s  %s  %s  %s",
		strings.Repeat("-", colWidths[0]),
		strings.Repeat("-", colWidths[1]),
		strings.Repeat("-", colWidths[2]),
		strings.Repeat("-", colWidths[3]),
		strings.Repeat("-", colWidths[4]),
	)
	sb.WriteString(sepLine)
	sb.WriteString("\n")

	// Data rows
	for _, row := range rows {
		sb.WriteString(fmt.Sprintf("%-*s  %-*s  %-*s  %-*s  %-*s\n",
			colWidths[0], row[0],
			colWidths[1], row[1],
			colWidths[2], row[2],
			colWidths[3], row[3],
			colWidths[4], row[4],
		))
	}

	return strings.TrimRight(sb.String(), "\n")
}

func formatMiddlewareList(middlewares []any) []string {
	if len(middlewares) == 0 {
		return nil
	}
	out := make([]string, 0, len(middlewares))
	for _, m := range middlewares {
		if m == nil {
			continue
		}
		switch v := m.(type) {
		case string:
			out = append(out, v)
		case fmt.Stringer:
			out = append(out, v.String())
		default:
			val := reflect.ValueOf(m)
			if val.Kind() == reflect.Func {
				name := runtime.FuncForPC(val.Pointer()).Name()
				if idx := strings.LastIndex(name, "/"); idx != -1 {
					name = name[idx+1:]
				}
				out = append(out, name)
			} else {
				t := reflect.TypeOf(m)
				if t.Kind() == reflect.Ptr {
					t = t.Elem()
				}
				out = append(out, t.Name())
			}
		}
	}
	return out
}
