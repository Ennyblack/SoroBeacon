package auth

import (
	"net/http"
	"strings"
)

type Role string

const (
	RoleViewer  Role = "viewer"
	RoleEditor  Role = "editor"
	RoleAdmin   Role = "admin"
	RoleUnknown Role = ""
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
	}
	return RoleUnknown, false
}

func (r Role) HasPermission(required Role) bool {
	if r == RoleAdmin {
		return true
	}
	if r == RoleEditor && (required == RoleEditor || required == RoleViewer) {
		return true
	}
	if r == RoleViewer && required == RoleViewer {
		return true
	}
	return false
}

type RoleEnforcer struct {
	a      *Authenticator
	routes map[string]map[string]Role
}

func NewRoleEnforcer(a *Authenticator) *RoleEnforcer {
	return &RoleEnforcer{
		a:      a,
		routes: make(map[string]map[string]Role),
	}
}

func (re *RoleEnforcer) RegisterRoute(method, path string, role Role) {
	if re.routes[path] == nil {
		re.routes[path] = make(map[string]Role)
	}
	re.routes[path][strings.ToUpper(method)] = role
}

func RoleMiddleware(re *RoleEnforcer, defaultRole Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if re == nil || !re.a.Enabled() {
				next.ServeHTTP(w, r)
				return
			}
			required := defaultRole
			if re.routes != nil {
				if m, ok := re.routes[r.URL.Path]; ok {
					if role, ok := m[r.Method]; ok {
						required = role
					}
				}
			}
			role := re.a.RoleForRequest(r)
			if !role.HasPermission(required) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
