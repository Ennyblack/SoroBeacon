package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRole(t *testing.T) {
	r, ok := ParseRole("viewer")
	assert.True(t, ok)
	assert.Equal(t, RoleViewer, r)

	r, ok = ParseRole("editor")
	assert.True(t, ok)
	assert.Equal(t, RoleEditor, r)

	r, ok = ParseRole("admin")
	assert.True(t, ok)
	assert.Equal(t, RoleAdmin, r)

	_, ok = ParseRole("unknown")
	assert.False(t, ok)
}

func TestRolePermissions(t *testing.T) {
	assert.True(t, RoleAdmin.HasPermission(RoleAdmin))
	assert.True(t, RoleAdmin.HasPermission(RoleEditor))
	assert.True(t, RoleAdmin.HasPermission(RoleViewer))

	assert.False(t, RoleEditor.HasPermission(RoleAdmin))
	assert.True(t, RoleEditor.HasPermission(RoleEditor))
	assert.True(t, RoleEditor.HasPermission(RoleViewer))

	assert.False(t, RoleViewer.HasPermission(RoleAdmin))
	assert.False(t, RoleViewer.HasPermission(RoleEditor))
	assert.True(t, RoleViewer.HasPermission(RoleViewer))
}
