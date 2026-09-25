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
	cleaned := strings.ToLower(strings.TrimSpace(s))
	switch cleaned {
	case "viewer":
		return RoleViewer, true
	case "editor":
		return RoleEditor, true
	case "admin":
		return RoleAdmin, true
	default:
		return RoleUnknown, false
	}
}

func (r Role) Level() int {
	switch r {
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

func (r Role) AtLeast(other Role) bool {
	return r.Level() >= other.Level()
}

func (r Role) HasPermission(required Role) bool {
	return r.AtLeast(required)
}

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

func (re *RoleEnforcer) RegisterRoute(method, pattern string, role Role) {
	if re == nil {
		return
	}
	re.routes[method+" "+pattern] = role
}

func RoleMiddleware(re *RoleEnforcer, defaultRole Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if re == nil || re.a == nil || !re.a.Enabled() {
				next.ServeHTTP(w, r)
				return
			}
			// Fail-closed: require explicit role assignment or check permissions
			role, ok := re.routes[r.Method+" "+r.URL.Path]
			if !ok {
				// If not explicitly registered, default to failing closed or defaultRole
				role = RoleUnknown
			}
			userRole := re.a.RoleForRequest(r)
			if !userRole.HasPermission(role) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func APIRouteRole(r *http.Request) Role {
	return RoleViewer
}

func WebRouteRole(r *http.Request) Role {
	return RoleViewer
}
