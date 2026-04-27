// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
)

func BenchmarkParseJWTClaims(b *testing.B) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
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
	})
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	jwt := header + "." + payloadB64 + "." + sig

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, _ = ParseJWTClaims(jwt)
	}
}

func BenchmarkProtoClaimsToMap(b *testing.B) {
	claims := &proto.Claims{
		Issuer:        "issuer",
		Subject:       "subject",
		TenantId:      "tenant",
		ObjectId:      "object",
		ClientId:      "client",
		Email:         "user@example.com",
		Name:          "Test User",
		Username:      "testuser",
		IssuedAtUnix:  1700000000,
		ExpiresAtUnix: 1700003600,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_ = protoClaimsToMap(claims)
	}
}

func BenchmarkLocalClaimsToMap(b *testing.B) {
	claims := &Claims{
		Issuer:   "issuer",
		Subject:  "subject",
		TenantID: "tenant",
		ObjectID: "object",
		ClientID: "client",
		Email:    "user@example.com",
		Name:     "Test User",
		Username: "testuser",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_ = localClaimsToMap(claims)
	}
}

func BenchmarkDisplayIdentity(b *testing.B) {
	claims := &Claims{
		Name:  "Test User",
		Email: "user@example.com",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_ = claims.DisplayIdentity()
	}
}

func BenchmarkIdentityTypeFromProtoClaims(b *testing.B) {
	claims := &proto.Claims{
		Name:     "Test User",
		ObjectId: "oid",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_ = identityTypeFromProtoClaims(claims)
	}
}

func BenchmarkNewPlugin(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		_ = NewPlugin()
	}
}
