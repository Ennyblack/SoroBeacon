package auth

import (
	"net/http"
	"strings"
)

// Role defines the authorization level of a caller.
type Role string

const (
	// RoleViewer can read monitoring data, alert history, and statistics.
	RoleViewer Role = "viewer"

	// RoleEditor can create, update, and delete monitors, rules, channels, and templates.
	RoleEditor Role = "editor"

	// RoleAdmin can perform all editor actions as well as administrative functions.
	RoleAdmin Role = "admin"

	// RoleUnknown represents an unassigned or invalid role.
	RoleUnknown Role = ""
)

// ParseRole parses a string into a Role, failing closed (returning RoleUnknown) for unknown values.
func ParseRole(s string) Role {
	s = strings.TrimSpace(strings.ToLower(s))
	switch Role(s) {
	case RoleViewer:
		return RoleViewer
	case RoleEditor:
		return RoleEditor
	case RoleAdmin:
		return RoleAdmin
	default:
		return RoleUnknown
	}
}

// APIRouteRole is the default role assigned or required for API routes when not specifically overridden.
const APIRouteRole Role = RoleViewer

// WebRouteRole is the default role assigned or required for Web dashboard routes when not specifically overridden.
const WebRouteRole Role = RoleViewer

// RoleEnforcer handles role authorization checks.
type RoleEnforcer struct {
	a        *Authenticator
	routes   []RouteRoleConfig
}

// NewRoleEnforcer creates a RoleEnforcer.
func NewRoleEnforcer(a *Authenticator) *RoleEnforcer {
	return &RoleEnforcer{
		a: a,
		routes: []RouteRoleConfig{
			// Probes and public
			{Method: "GET", Path: "/api/v1/livez", Role: RoleViewer},
			{Method: "GET", Path: "/api/v1/readyz", Role: RoleViewer},
			{Method: "GET", Path: "/api/v1/health", Role: RoleViewer},
			{Method: "GET", Path: "/api/v1/version", Role: RoleViewer},
			// Viewer reads
			{Method: "GET", Path: "/api/v1/monitors", Role: RoleViewer},
			{Method: "GET", Path: "/api/v1/monitors/", Role: RoleViewer},
			{Method: "GET", Path: "/api/v1/channels", Role: RoleViewer},
			{Method: "GET", Path: "/api/v1/channels/", Role: RoleViewer},
			{Method: "GET", Path: "/api/v1/templates", Role: RoleViewer},
			{Method: "GET", Path: "/api/v1/templates/", Role: RoleViewer},
			{Method: "GET", Path: "/api/v1/alerts", Role: RoleViewer},
			{Method: "GET", Path: "/api/v1/alerts.csv", Role: RoleViewer},
			{Method: "GET", Path: "/api/v1/stats", Role: RoleViewer},
			{Method: "GET", Path: "/api/v1/stats/alerts-daily", Role: RoleViewer},
			// Editor mutations & rules/deliveries reads/writes
			{Method: "POST", Path: "/api/v1/monitors", Role: RoleEditor},
			{Method: "POST", Path: "/api/v1/monitors/bulk", Role: RoleEditor},
			{Method: "POST", Path: "/api/v1/monitors/import", Role: RoleEditor},
			{Method: "POST", Path: "/api/v1/channels", Role: RoleEditor},
			{Method: "POST", Path: "/api/v1/templates", Role: RoleEditor},
		},
	}
}

// RouteRoleConfig maps HTTP method and path patterns to required minimum roles.
type RouteRoleConfig struct {
	Method string
	Path   string
	Role   Role
}

// RoleMiddleware enforces role-based access control per route, failing closed if unauthorized.
func RoleMiddleware(re *RoleEnforcer, defaultRole Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if re == nil {
				next.ServeHTTP(w, r)
				return
			}
			path := r.URL.Path
			method := r.Method
			requiredRole, assigned := re.lookupRoute(method, path)
			if !assigned {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden","code":"Forbidden"}`))
				return
			}
			role, ok := re.auth.RoleForRequest(r)
			if !ok {
				role = RoleUnknown
			}
			if !role.AtLeast(requiredRole) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden","code":"Forbidden"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (re *RoleEnforcer) RegisterRoute(method, path string, role Role) {
	re.routes = append(re.routes, RouteRoleConfig{Method: method, Path: path, Role: role})
}

func (re *RoleEnforcer) lookupRoute(method, path string) (Role, bool) {
	// If auth is not enabled, allow everything
	if re.a != nil && !re.a.Enabled() {
		return RoleViewer, true
	}
	// Normalize prefix
	for _, rc := range re.routes {
		if rc.Method == method {
			if rc.Path == path || strings.HasPrefix(path, rc.Path) {
				return rc.Role, true
			}
		}
	}
	// Fail closed: unknown routes return false for assigned
	return RoleAdmin, false
}

func (r Role) AtLeast(required Role) bool {
	if r == required {
		return true
	}
	switch r {
	case RoleAdmin:
		return required == RoleEditor || required == RoleViewer
	case RoleEditor:
		return required == RoleViewer
	default:
		return false
	}
}
