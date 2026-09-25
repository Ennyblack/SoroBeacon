package auth

import (
	"net/http"
	"strings"
)

type Role string

const (
	RoleUnknown Role = ""
	RoleViewer  Role = "viewer"
	RoleEditor  Role = "editor"
	RoleAdmin   Role = "admin"
)

func ParseRole(s string) (Role, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	switch Role(s) {
	case RoleViewer:
		return RoleViewer, true
	case RoleEditor:
		return RoleEditor, true
	case RoleAdmin:
		return RoleAdmin, true
	default:
		return RoleUnknown, false
	}
}

func (r Role) AtLeast(required Role) bool {
	rank := func(rol Role) int {
		switch rol {
		case RoleViewer:
			return 1
		case RoleEditor:
			return 2
		case RoleAdmin:
			return 3
		default:
			return 0
		}
	}
	return rank(r) >= rank(required)
}

func (r Role) HasPermission(required Role) bool {
	return r.AtLeast(required)
}

type RouteRole string

const (
	APIRouteRole RouteRole = "api"
	WebRouteRole RouteRole = "web"
)

type RoleEnforcer struct {
	a      *Authenticator
	routes map[string]Role
}

func NewRoleEnforcer(a *Authenticator) *RoleEnforcer {
	return &RoleEnforcer{
		a:      a,
		routes: make(map[string]Role),
	}
}

func (re *RoleEnforcer) RegisterRoute(method, path string, role Role) {
	if re == nil {
		return
	}
	re.routes[method+" "+path] = role
}

func RoleMiddleware(re *RoleEnforcer, defaultRole Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if re == nil || re.a == nil || !re.a.Enabled() {
				next.ServeHTTP(w, r)
				return
			}
			// Fail closed: if a route is not registered, deny access unless defaultRole permits
			key := r.Method + " " + r.URL.Path
			required, ok := re.routes[key]
			if !ok {
				required = defaultRole
			}
			role, ok := re.a.RoleForRequest(r)
			if !ok || !role.HasPermission(required) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
