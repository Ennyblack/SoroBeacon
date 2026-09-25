package auth

// Role represents a permission level in SoroBeacon's RBAC system.
type Role string

const (
	// RoleViewer can read monitoring status, alerts, and monitors without viewing channel secrets.
	RoleViewer Role = "viewer"
	// RoleEditor can manage monitors, rules, and channels, but cannot perform admin operations if any exist.
	RoleEditor Role = "editor"
	// RoleAdmin has full permissions across all endpoints.
	RoleAdmin Role = "admin"
)

// ParseRole validates and normalises a string into a Role, returning an error or default if invalid.
func ParseRole(s string) (Role, bool) {
	switch Role(s) {
	case RoleViewer, RoleEditor, RoleAdmin:
		return Role(s), true
	default:
		return "", false
	}
}

// HasPermission reports whether the given role satisfies the required minimum role.
// Hierarchy: admin > editor > viewer.
func (r Role) HasPermission(required Role) bool {
	if r == RoleAdmin {
		return true
	}
	if r == RoleEditor {
		return required == RoleEditor || required == RoleViewer
	}
	if r == RoleViewer {
		return required == RoleViewer
	}
	return false
}
