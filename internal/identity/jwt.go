// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ErrOpaqueToken is returned when a token is not a decodable JWT.
var ErrOpaqueToken = fmt.Errorf("token is not a decodable JWT")

// Claims represents normalized identity claims parsed from a JWT.
type Claims struct {
	Issuer    string    `json:"issuer,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	TenantID  string    `json:"tenantId,omitempty"`
	ObjectID  string    `json:"objectId,omitempty"`
	ClientID  string    `json:"clientId,omitempty"`
	Email     string    `json:"email,omitempty"`
	Name      string    `json:"name,omitempty"`
	Username  string    `json:"username,omitempty"`
	IssuedAt  time.Time `json:"issuedAt,omitempty"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
}

// DisplayIdentity returns the best human-readable identity string.
func (c *Claims) DisplayIdentity() string {
	if c == nil {
		return ""
	}
	if c.Name != "" && c.Email != "" {
		return c.Name + " <" + c.Email + ">"
	}
	if c.Name != "" {
		return c.Name
	}
	if c.Email != "" {
		return c.Email
	}
	if c.Username != "" {
		return c.Username
	}
	if c.Subject != "" {
		return c.Subject
	}
	return ""
}

// jwtClaims is the raw claim names from JWT tokens.
type jwtClaims struct {
	Issuer            string `json:"iss"`
	Subject           string `json:"sub"`
	Audience          string `json:"aud"`
	TenantID          string `json:"tid"`
	ObjectID          string `json:"oid"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	IssuedAt          int64  `json:"iat"`
	ExpiresAt         int64  `json:"exp"`
	AppID             string `json:"appid"`
	AuthorizedParty   string `json:"azp"`
	UniqueName        string `json:"unique_name"`
	UPN               string `json:"upn"`
	ServicePrincipal  string `json:"app_displayname"`
}

// ParseJWTClaims decodes a JWT token string (without signature verification)
// and extracts normalized identity claims.
//
// Returns ErrOpaqueToken if the token is not a decodable JWT.
func ParseJWTClaims(rawJWT string) (*Claims, error) {
	parts := strings.SplitN(rawJWT, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 parts, got %d", ErrOpaqueToken, len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode payload: %w", ErrOpaqueToken, err)
	}

	var raw jwtClaims
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("%w: failed to parse claims: %w", ErrOpaqueToken, err)
	}

	// Resolve email: prefer email > preferred_username > upn > unique_name
	email := raw.Email
	if email == "" {
		email = raw.PreferredUsername
	}
	if email == "" {
		email = raw.UPN
	}
	if email == "" {
		email = raw.UniqueName
	}

	// Resolve username: prefer preferred_username > upn > unique_name
	username := raw.PreferredUsername
	if username == "" {
		username = raw.UPN
	}
	if username == "" {
		username = raw.UniqueName
	}

	// Resolve client ID: prefer aud > azp > appid
	clientID := raw.Audience
	if clientID == "" {
		clientID = raw.AuthorizedParty
	}
	if clientID == "" {
		clientID = raw.AppID
	}

	claims := &Claims{
		Issuer:   raw.Issuer,
		Subject:  raw.Subject,
		TenantID: raw.TenantID,
		ObjectID: raw.ObjectID,
		ClientID: clientID,
		Email:    email,
		Name:     raw.Name,
		Username: username,
	}

	if raw.IssuedAt != 0 {
		claims.IssuedAt = time.Unix(raw.IssuedAt, 0)
	}
	if raw.ExpiresAt != 0 {
		claims.ExpiresAt = time.Unix(raw.ExpiresAt, 0)
	}

	return claims, nil
}
