// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package identity implements the identity provider plugin for scafctl.
// It exposes authentication identity information (claims, status, groups)
// via the host's auth registry without revealing tokens or secrets.
package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/google/jsonschema-go/jsonschema"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
	sdkhelper "github.com/oakwood-commons/scafctl-plugin-sdk/provider/schemahelper"
)

const (
	// ProviderName is the unique identifier for this provider.
	ProviderName = "identity"
	// Version is the semantic version of this provider.
	Version = "1.0.0"

	maxHandlerLen = 50
	maxScopeLen   = 1024
	maxOpLen      = 10
)

// authClient abstracts the host auth operations for testability.
type authClient interface {
	GetAuthIdentity(ctx context.Context, handler, scope string) (*proto.Claims, error)
	ListAuthHandlers(ctx context.Context) (handlers []string, defaultHandler string, err error)
	GetAuthToken(ctx context.Context, handler, scope string, minValidFor int64, forceRefresh bool) (*proto.GetAuthTokenResponse, error)
	GetAuthGroups(ctx context.Context, handler string) ([]string, error)
}

// Plugin implements the sdkplugin.ProviderPlugin interface.
type Plugin struct {
	descriptor *sdkprovider.Descriptor
}

// NewPlugin creates a new identity provider plugin.
func NewPlugin() *Plugin {
	version, _ := semver.NewVersion(Version)

	return &Plugin{
		descriptor: &sdkprovider.Descriptor{
			Name:        ProviderName,
			DisplayName: "Identity",
			APIVersion:  "v1",
			Description: "Provides authentication identity information (claims, status, identity type) from auth handlers without exposing tokens or secrets",
			Version:     version,
			Category:    "security",
			Capabilities: []sdkprovider.Capability{
				sdkprovider.CapabilityFrom,
			},
			Tags: []string{"auth", "identity", "claims", "security"},
			Schema: sdkhelper.ObjectSchema([]string{"operation"}, map[string]*jsonschema.Schema{
				"operation": sdkhelper.StringProp("Operation to perform: 'status' to get auth status, 'claims' to get identity claims, 'groups' to get group memberships (Entra only), 'list' to list available handlers",
					sdkhelper.WithEnum("status", "claims", "groups", "list"),
					sdkhelper.WithExample("claims"),
					sdkhelper.WithMaxLength(maxOpLen)),
				"handler": sdkhelper.StringProp("Name of the auth handler to query (e.g., 'entra'). If not specified, uses the first available authenticated handler.",
					sdkhelper.WithMaxLength(maxHandlerLen),
					sdkhelper.WithPattern(`^[a-z][a-z0-9-]*$`),
					sdkhelper.WithExample("entra")),
				"scope": sdkhelper.StringProp("OAuth scope for scoped token operations. When set, 'claims' and 'status' operations mint a token with this scope and return its details instead of stored metadata. Not supported for 'groups' or 'list' operations.",
					sdkhelper.WithMaxLength(maxScopeLen),
					sdkhelper.WithExample("api://my-app/.default")),
			}),
			OutputSchemas: map[sdkprovider.Capability]*jsonschema.Schema{
				sdkprovider.CapabilityFrom: sdkhelper.ObjectSchema(nil, map[string]*jsonschema.Schema{
					"operation":     sdkhelper.StringProp("Operation that was performed", sdkhelper.WithExample("claims")),
					"handler":       sdkhelper.StringProp("Name of the auth handler queried", sdkhelper.WithExample("entra")),
					"authenticated": sdkhelper.BoolProp("Whether the user is authenticated", sdkhelper.WithExample(true)),
					"identityType":  sdkhelper.StringProp("Type of identity: 'user' or 'service-principal'", sdkhelper.WithExample("user")),
					"claims":        sdkhelper.AnyProp("Identity claims (name, email, subject, etc.)"),
					"groups":        sdkhelper.ArrayProp("List of group names the user belongs to (groups operation only)"),
					"count":         sdkhelper.AnyProp("Number of items returned"),
					"tenantId":      sdkhelper.StringProp("Tenant ID for the authenticated identity"),
					"expiresAt":     sdkhelper.StringProp("Token expiration time in RFC3339 format"),
					"expiresIn":     sdkhelper.StringProp("Human-readable duration until token expires"),
					"handlers":      sdkhelper.ArrayProp("List of available auth handler names (for 'list' operation)"),
					"scopedToken":   sdkhelper.BoolProp("Whether the response was derived from a scoped access token"),
					"tokenScope":    sdkhelper.StringProp("The OAuth scope the token was minted for"),
					"tokenType":     sdkhelper.StringProp("Token type, typically Bearer"),
				}),
			},
			Examples: []sdkprovider.Example{
				{
					Name:        "Get identity claims",
					Description: "Retrieve claims (name, email, etc.) from the authenticated user",
					YAML: `name: get-claims
provider: identity
inputs:
  operation: claims`,
				},
				{
					Name:        "Check authentication status",
					Description: "Check if user is authenticated and get status details",
					YAML: `name: check-auth
provider: identity
inputs:
  operation: status
  handler: entra`,
				},
				{
					Name:        "Get group memberships",
					Description: "Retrieve group names the authenticated user belongs to",
					YAML: `name: user-groups
provider: identity
inputs:
  operation: groups
  handler: entra`,
				},
				{
					Name:        "List available handlers",
					Description: "List all registered auth handlers",
					YAML: `name: list-handlers
provider: identity
inputs:
  operation: list`,
				},
				{
					Name:        "Get claims from a scoped token",
					Description: "Mint a token for a specific OAuth scope and return the claims parsed from the access token JWT",
					YAML: `name: scoped-claims
provider: identity
inputs:
  operation: claims
  scope: api://my-app/.default`,
				},
			},
		},
	}
}

// GetProviders returns the list of provider names this plugin offers.
func (p *Plugin) GetProviders(_ context.Context) ([]string, error) {
	return []string{ProviderName}, nil
}

// GetProviderDescriptor returns the descriptor for the named provider.
func (p *Plugin) GetProviderDescriptor(_ context.Context, name string) (*sdkprovider.Descriptor, error) {
	if name != ProviderName {
		return nil, fmt.Errorf("unknown provider %q", name)
	}
	return p.descriptor, nil
}

// ConfigureProvider configures the plugin with the given settings.
func (p *Plugin) ConfigureProvider(_ context.Context, _ string, _ sdkplugin.ProviderConfig) error {
	return nil
}

// ExecuteProvider runs the identity provider logic.
func (p *Plugin) ExecuteProvider(ctx context.Context, _ string, inputs map[string]any) (*sdkprovider.Output, error) {
	operation, ok := inputs["operation"].(string)
	if !ok {
		return nil, fmt.Errorf("%s: operation is required and must be a string", ProviderName)
	}

	handlerName, _ := inputs["handler"].(string)
	scope, _ := inputs["scope"].(string)

	// Validate scope is only used with supported operations
	if scope != "" && (operation == "groups" || operation == "list") {
		return nil, fmt.Errorf("%s: scope is not supported for the %q operation; it can only be used with 'claims' or 'status'", ProviderName, operation)
	}

	hostClient := sdkplugin.HostClientFromContext(ctx)
	if hostClient == nil {
		return nil, fmt.Errorf("%s: host client not available; auth operations require the host to provide authentication services", ProviderName)
	}

	return p.execute(ctx, hostClient, operation, handlerName, scope)
}

// ExecuteProviderStream is not supported; identity operations are not streaming.
func (p *Plugin) ExecuteProviderStream(_ context.Context, _ string, _ map[string]any, _ func(sdkplugin.StreamChunk)) error {
	return sdkplugin.ErrStreamingNotSupported
}

// DescribeWhatIf returns a dry-run description for the operation.
func (p *Plugin) DescribeWhatIf(_ context.Context, _ string, inputs map[string]any) (string, error) {
	operation, _ := inputs["operation"].(string)
	handlerName, _ := inputs["handler"].(string)
	scope, _ := inputs["scope"].(string)

	switch operation {
	case "status":
		if scope != "" {
			return fmt.Sprintf("Would mint a scoped token (scope=%q) via handler %q and return token status", scope, handlerName), nil
		}
		return fmt.Sprintf("Would check authentication status for handler %q", handlerName), nil
	case "claims":
		if scope != "" {
			return fmt.Sprintf("Would mint a scoped token (scope=%q) via handler %q and parse JWT claims", scope, handlerName), nil
		}
		return fmt.Sprintf("Would retrieve identity claims from handler %q", handlerName), nil
	case "groups":
		return fmt.Sprintf("Would retrieve group memberships from handler %q", handlerName), nil
	case "list":
		return "Would list all available auth handlers", nil
	default:
		return fmt.Sprintf("Unknown operation %q", operation), nil
	}
}

// ExtractDependencies returns dependencies for the operation.
func (p *Plugin) ExtractDependencies(_ context.Context, _ string, _ map[string]any) ([]string, error) {
	return nil, nil
}

// StopProvider is a no-op for this stateless provider.
func (p *Plugin) StopProvider(_ context.Context, _ string) error {
	return nil
}

// execute dispatches to the appropriate operation handler.
func (p *Plugin) execute(ctx context.Context, client authClient, operation, handlerName, scope string) (*sdkprovider.Output, error) {
	switch operation {
	case "status":
		if scope != "" {
			return p.executeScopedStatus(ctx, client, handlerName, scope)
		}
		return p.executeStatus(ctx, client, handlerName)
	case "claims":
		if scope != "" {
			return p.executeScopedClaims(ctx, client, handlerName, scope)
		}
		return p.executeClaims(ctx, client, handlerName)
	case "groups":
		return p.executeGroups(ctx, client, handlerName)
	case "list":
		return p.executeList(ctx, client)
	default:
		return nil, fmt.Errorf("%s: unsupported operation: %s", ProviderName, operation)
	}
}

// executeStatus retrieves authentication status via GetAuthIdentity.
func (p *Plugin) executeStatus(ctx context.Context, client authClient, handlerName string) (*sdkprovider.Output, error) {
	claims, err := client.GetAuthIdentity(ctx, handlerName, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get identity from handler %q: %w", handlerName, err)
	}

	result := map[string]any{
		"operation":     "status",
		"handler":       handlerName,
		"authenticated": claims != nil,
	}

	if claims != nil {
		populateStatusFromProtoClaims(result, claims)
	}

	return &sdkprovider.Output{Data: result}, nil
}

// executeClaims retrieves identity claims via GetAuthIdentity.
func (p *Plugin) executeClaims(ctx context.Context, client authClient, handlerName string) (*sdkprovider.Output, error) {
	protoClaims, err := client.GetAuthIdentity(ctx, handlerName, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get identity from handler %q: %w", handlerName, err)
	}

	result := map[string]any{
		"operation":     "claims",
		"handler":       handlerName,
		"authenticated": protoClaims != nil,
	}

	if protoClaims == nil {
		result["claims"] = nil
		return &sdkprovider.Output{
			Data:     result,
			Warnings: []string{"not authenticated - no claims available"},
		}, nil
	}

	claims := protoClaimsToMap(protoClaims)
	result["claims"] = claims
	result["identityType"] = identityTypeFromProtoClaims(protoClaims)

	return &sdkprovider.Output{Data: result}, nil
}

// executeScopedStatus mints a scoped token and returns status from the token metadata.
func (p *Plugin) executeScopedStatus(ctx context.Context, client authClient, handlerName, scope string) (*sdkprovider.Output, error) {
	tokenResp, err := client.GetAuthToken(ctx, handlerName, scope, 0, false)
	if err != nil {
		return nil, fmt.Errorf("failed to mint scoped token from handler %q for scope %q: %w", handlerName, scope, err)
	}

	result := map[string]any{
		"operation":     "status",
		"handler":       handlerName,
		"authenticated": true,
		"scopedToken":   true,
		"tokenScope":    scope,
	}

	if tokenResp.TokenType != "" {
		result["tokenType"] = tokenResp.TokenType
	}

	if tokenResp.ExpiresAtUnix != 0 {
		expiresAt := time.Unix(tokenResp.ExpiresAtUnix, 0)
		result["expiresAt"] = expiresAt.Format(time.RFC3339)
		remaining := time.Until(expiresAt)
		if remaining > 0 {
			result["expiresIn"] = remaining.Truncate(time.Second).String()
		} else {
			result["expiresIn"] = "expired"
		}
	}

	// Try to extract identity info from the access token JWT
	var warnings []string
	parsed, parseErr := ParseJWTClaims(tokenResp.AccessToken)
	if parseErr != nil {
		if errors.Is(parseErr, ErrOpaqueToken) {
			warnings = append(warnings, fmt.Sprintf("access token is not a decodable JWT -- identity details unavailable: %v", parseErr))
		} else {
			warnings = append(warnings, fmt.Sprintf("failed to parse access token claims: %v", parseErr))
		}
	} else {
		if parsed.TenantID != "" {
			result["tenantId"] = parsed.TenantID
		}
		result["identityType"] = identityTypeFromLocalClaims(parsed)
	}

	output := &sdkprovider.Output{Data: result}
	if len(warnings) > 0 {
		output.Warnings = warnings
	}
	return output, nil
}

// executeScopedClaims mints a scoped token and parses JWT claims from the access token.
func (p *Plugin) executeScopedClaims(ctx context.Context, client authClient, handlerName, scope string) (*sdkprovider.Output, error) {
	tokenResp, err := client.GetAuthToken(ctx, handlerName, scope, 0, false)
	if err != nil {
		return nil, fmt.Errorf("failed to mint scoped token from handler %q for scope %q: %w", handlerName, scope, err)
	}

	result := map[string]any{
		"operation":     "claims",
		"handler":       handlerName,
		"authenticated": true,
		"scopedToken":   true,
		"tokenScope":    scope,
	}

	var warnings []string
	parsed, parseErr := ParseJWTClaims(tokenResp.AccessToken)
	if parseErr != nil {
		if errors.Is(parseErr, ErrOpaqueToken) {
			warnings = append(warnings, fmt.Sprintf("access token is not a decodable JWT -- claims unavailable: %v", parseErr))
		} else {
			warnings = append(warnings, fmt.Sprintf("failed to parse access token claims: %v", parseErr))
		}
		result["claims"] = nil
		if tokenResp.ExpiresAtUnix != 0 {
			result["expiresAt"] = time.Unix(tokenResp.ExpiresAtUnix, 0).Format(time.RFC3339)
		}
	} else {
		result["claims"] = localClaimsToMap(parsed)
		result["identityType"] = identityTypeFromLocalClaims(parsed)
	}

	output := &sdkprovider.Output{Data: result}
	if len(warnings) > 0 {
		output.Warnings = warnings
	}
	return output, nil
}

// executeGroups retrieves group memberships via GetAuthGroups.
func (p *Plugin) executeGroups(ctx context.Context, client authClient, handlerName string) (*sdkprovider.Output, error) {
	groups, err := client.GetAuthGroups(ctx, handlerName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve group memberships from handler %q: %w", handlerName, err)
	}

	if groups == nil {
		groups = []string{}
	}

	return &sdkprovider.Output{
		Data: map[string]any{
			"operation": "groups",
			"handler":   handlerName,
			"groups":    groups,
			"count":     len(groups),
		},
	}, nil
}

// executeList retrieves available auth handlers via ListAuthHandlers.
func (p *Plugin) executeList(ctx context.Context, client authClient) (*sdkprovider.Output, error) {
	handlers, defaultHandler, err := client.ListAuthHandlers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list auth handlers: %w", err)
	}

	handlerInfo := make([]map[string]any, 0, len(handlers))
	for _, name := range handlers {
		info := map[string]any{
			"name":    name,
			"default": name == defaultHandler,
		}
		handlerInfo = append(handlerInfo, info)
	}

	return &sdkprovider.Output{
		Data: map[string]any{
			"operation": "list",
			"handlers":  handlerInfo,
			"count":     len(handlerInfo),
		},
	}, nil
}

// protoClaimsToMap converts proto.Claims to a map, omitting zero-value fields.
func protoClaimsToMap(c *proto.Claims) map[string]any {
	if c == nil {
		return nil
	}
	m := make(map[string]any)
	if c.Issuer != "" {
		m["issuer"] = c.Issuer
	}
	if c.Subject != "" {
		m["subject"] = c.Subject
	}
	if c.TenantId != "" {
		m["tenantId"] = c.TenantId
	}
	if c.ObjectId != "" {
		m["objectId"] = c.ObjectId
	}
	if c.ClientId != "" {
		m["clientId"] = c.ClientId
	}
	if c.Email != "" {
		m["email"] = c.Email
	}
	if c.Name != "" {
		m["name"] = c.Name
	}
	if c.Username != "" {
		m["username"] = c.Username
	}
	if c.IssuedAtUnix != 0 {
		m["issuedAt"] = time.Unix(c.IssuedAtUnix, 0).Format(time.RFC3339)
	}
	if c.ExpiresAtUnix != 0 {
		m["expiresAt"] = time.Unix(c.ExpiresAtUnix, 0).Format(time.RFC3339)
	}
	// Compute display identity
	m["displayIdentity"] = protoDisplayIdentity(c)
	return m
}

// protoDisplayIdentity returns the best human-readable identity string from proto claims.
func protoDisplayIdentity(c *proto.Claims) string {
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

// identityTypeFromProtoClaims infers identity type from proto claims.
func identityTypeFromProtoClaims(c *proto.Claims) string {
	if c == nil {
		return "user"
	}
	if c.Name == "" && c.Email == "" && c.Username == "" && c.ObjectId != "" {
		return "service-principal"
	}
	return "user"
}

// localClaimsToMap converts locally parsed JWT Claims to a map.
func localClaimsToMap(c *Claims) map[string]any {
	if c == nil {
		return nil
	}
	m := make(map[string]any)
	if c.Issuer != "" {
		m["issuer"] = c.Issuer
	}
	if c.Subject != "" {
		m["subject"] = c.Subject
	}
	if c.TenantID != "" {
		m["tenantId"] = c.TenantID
	}
	if c.ObjectID != "" {
		m["objectId"] = c.ObjectID
	}
	if c.ClientID != "" {
		m["clientId"] = c.ClientID
	}
	if c.Email != "" {
		m["email"] = c.Email
	}
	if c.Name != "" {
		m["name"] = c.Name
	}
	if c.Username != "" {
		m["username"] = c.Username
	}
	if !c.IssuedAt.IsZero() {
		m["issuedAt"] = c.IssuedAt.Format(time.RFC3339)
	}
	if !c.ExpiresAt.IsZero() {
		m["expiresAt"] = c.ExpiresAt.Format(time.RFC3339)
	}
	m["displayIdentity"] = c.DisplayIdentity()
	return m
}

// identityTypeFromLocalClaims infers identity type from locally parsed JWT claims.
func identityTypeFromLocalClaims(c *Claims) string {
	if c == nil {
		return "user"
	}
	if c.Name == "" && c.Email == "" && c.Username == "" && c.ObjectID != "" {
		return "service-principal"
	}
	return "user"
}

// populateStatusFromProtoClaims adds identity fields to a status result map.
func populateStatusFromProtoClaims(result map[string]any, c *proto.Claims) {
	if c == nil {
		return
	}
	result["identityType"] = identityTypeFromProtoClaims(c)
	if c.TenantId != "" {
		result["tenantId"] = c.TenantId
	}
	if c.ExpiresAtUnix != 0 {
		expiresAt := time.Unix(c.ExpiresAtUnix, 0)
		result["expiresAt"] = expiresAt.Format(time.RFC3339)
		remaining := time.Until(expiresAt)
		if remaining > 0 {
			result["expiresIn"] = remaining.Truncate(time.Second).String()
		} else {
			result["expiresIn"] = "expired"
		}
	}
}
