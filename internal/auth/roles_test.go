package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRole(t *testing.T) {
	tests := []struct {
		input    string
		expected Role
	}{
		{"viewer", RoleViewer},
		{"VIEWER", RoleViewer},
		{"  viewer  ", RoleViewer},
		{"editor", RoleEditor},
		{"ADMIN", RoleAdmin},
		{"unknown", RoleUnknown},
		{"", RoleUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, _ := ParseRole(tc.input)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestRoleHierarchy(t *testing.T) {
	assert.True(t, RoleViewer.AtLeast(RoleViewer))
	assert.False(t, RoleViewer.AtLeast(RoleEditor))
	assert.False(t, RoleViewer.AtLeast(RoleAdmin))

	assert.True(t, RoleEditor.AtLeast(RoleViewer))
	assert.True(t, RoleEditor.AtLeast(RoleEditor))
	assert.False(t, RoleEditor.AtLeast(RoleAdmin))

	assert.True(t, RoleAdmin.AtLeast(RoleViewer))
	assert.True(t, RoleAdmin.AtLeast(RoleEditor))
	assert.True(t, RoleAdmin.AtLeast(RoleAdmin))

	assert.False(t, RoleUnknown.AtLeast(RoleViewer))
}

func TestRoleMiddlewareFailClosedAndUnassigned(t *testing.T) {
	a := New(map[string]Role{"token-admin": RoleAdmin}, 0)
	re := NewRoleEnforcer(a)
	re.RegisterRoute("GET", "/api/v1/safe", RoleViewer)

	handler := RoleMiddleware(re, RoleViewer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Unassigned route should fail closed (403)
	reqUnassigned := httptest.NewRequest("GET", "/api/v1/unknown-route", nil)
	reqUnassigned.Header.Set("Authorization", "Bearer token-admin")
	recUnassigned := httptest.NewRecorder()
	handler.ServeHTTP(recUnassigned, reqUnassigned)
	assert.Equal(t, http.StatusForbidden, recUnassigned.Code)

	// Assigned route with proper role should succeed
	reqAssigned := httptest.NewRequest("GET", "/api/v1/safe", nil)
	reqAssigned.Header.Set("Authorization", "Bearer token-admin")
	recAssigned := httptest.NewRecorder()
	handler.ServeHTTP(recAssigned, reqAssigned)
	assert.Equal(t, http.StatusOK, recAssigned.Code)
}
