// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseJWTClaims(t *testing.T) {
	t.Parallel()

	// Helper to build a JWT from claims
	buildJWT := func(claims map[string]any) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
		payload, _ := json.Marshal(claims)
		payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
		sig := base64.RawURLEncoding.EncodeToString([]byte("signature"))
		return header + "." + payloadB64 + "." + sig
	}

	tests := []struct {
		name      string
		token     string
		wantErr   bool
		wantClaim func(*testing.T, *Claims)
	}{
		{
			name: "full user token",
			token: buildJWT(map[string]any{
				"iss":                "https://login.microsoftonline.com/tenant/v2.0",
				"sub":                "user-sub-123",
				"aud":                "client-id-456",
				"tid":                "tenant-id-789",
				"oid":                "object-id-abc",
				"email":              "user@example.com",
				"preferred_username": "user@example.com",
				"name":               "Test User",
				"iat":                1700000000,
				"exp":                1700003600,
			}),
			wantClaim: func(t *testing.T, c *Claims) {
				t.Helper()
				assert.Equal(t, "https://login.microsoftonline.com/tenant/v2.0", c.Issuer)
				assert.Equal(t, "user-sub-123", c.Subject)
				assert.Equal(t, "tenant-id-789", c.TenantID)
				assert.Equal(t, "object-id-abc", c.ObjectID)
				assert.Equal(t, "client-id-456", c.ClientID)
				assert.Equal(t, "user@example.com", c.Email)
				assert.Equal(t, "Test User", c.Name)
				assert.Equal(t, "user@example.com", c.Username)
				assert.False(t, c.IssuedAt.IsZero())
				assert.False(t, c.ExpiresAt.IsZero())
			},
		},
		{
			name: "email fallback to preferred_username",
			token: buildJWT(map[string]any{
				"preferred_username": "fallback@example.com",
				"name":               "Fallback",
			}),
			wantClaim: func(t *testing.T, c *Claims) {
				t.Helper()
				assert.Equal(t, "fallback@example.com", c.Email)
				assert.Equal(t, "fallback@example.com", c.Username)
			},
		},
		{
			name: "email fallback to upn",
			token: buildJWT(map[string]any{
				"upn":  "upn@example.com",
				"name": "UPN User",
			}),
			wantClaim: func(t *testing.T, c *Claims) {
				t.Helper()
				assert.Equal(t, "upn@example.com", c.Email)
				assert.Equal(t, "upn@example.com", c.Username)
			},
		},
		{
			name: "email fallback to unique_name",
			token: buildJWT(map[string]any{
				"unique_name": "unique@example.com",
			}),
			wantClaim: func(t *testing.T, c *Claims) {
				t.Helper()
				assert.Equal(t, "unique@example.com", c.Email)
				assert.Equal(t, "unique@example.com", c.Username)
			},
		},
		{
			name: "clientID fallback to azp",
			token: buildJWT(map[string]any{
				"azp": "azp-client",
			}),
			wantClaim: func(t *testing.T, c *Claims) {
				t.Helper()
				assert.Equal(t, "azp-client", c.ClientID)
			},
		},
		{
			name: "clientID fallback to appid",
			token: buildJWT(map[string]any{
				"appid": "appid-client",
			}),
			wantClaim: func(t *testing.T, c *Claims) {
				t.Helper()
				assert.Equal(t, "appid-client", c.ClientID)
			},
		},
		{
			name:    "not a JWT - single part",
			token:   "not-a-jwt",
			wantErr: true,
		},
		{
			name:    "not a JWT - two parts",
			token:   "part1.part2",
			wantErr: true,
		},
		{
			name:    "invalid base64 payload",
			token:   "header.!!!invalid!!!.sig",
			wantErr: true,
		},
		{
			name:    "invalid JSON payload",
			token:   "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sig",
			wantErr: true,
		},
		{
			name: "zero timestamps not set",
			token: buildJWT(map[string]any{
				"sub": "subject",
			}),
			wantClaim: func(t *testing.T, c *Claims) {
				t.Helper()
				assert.True(t, c.IssuedAt.IsZero())
				assert.True(t, c.ExpiresAt.IsZero())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims, err := ParseJWTClaims(tc.token)
			if tc.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrOpaqueToken))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, claims)
			if tc.wantClaim != nil {
				tc.wantClaim(t, claims)
			}
		})
	}
}

func TestClaims_DisplayIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims *Claims
		want   string
	}{
		{name: "nil claims", claims: nil, want: ""},
		{name: "name and email", claims: &Claims{Name: "John", Email: "john@example.com"}, want: "John <john@example.com>"},
		{name: "name only", claims: &Claims{Name: "John"}, want: "John"},
		{name: "email only", claims: &Claims{Email: "john@example.com"}, want: "john@example.com"},
		{name: "username only", claims: &Claims{Username: "johndoe"}, want: "johndoe"},
		{name: "subject only", claims: &Claims{Subject: "sub-123"}, want: "sub-123"},
		{name: "empty", claims: &Claims{}, want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.claims.DisplayIdentity())
		})
	}
}
