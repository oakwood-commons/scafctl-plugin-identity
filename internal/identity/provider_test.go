// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAuthClient implements authClient for testing.
type mockAuthClient struct {
	getAuthIdentityFn  func(ctx context.Context, handler, scope string) (*proto.Claims, error)
	listAuthHandlersFn func(ctx context.Context) ([]string, string, error)
	getAuthTokenFn     func(ctx context.Context, handler, scope string, minValidFor int64, forceRefresh bool) (*proto.GetAuthTokenResponse, error)
	getAuthGroupsFn    func(ctx context.Context, handler string) ([]string, error)
}

func (m *mockAuthClient) GetAuthIdentity(ctx context.Context, handler, scope string) (*proto.Claims, error) {
	if m.getAuthIdentityFn != nil {
		return m.getAuthIdentityFn(ctx, handler, scope)
	}
	return nil, nil
}

func (m *mockAuthClient) ListAuthHandlers(ctx context.Context) ([]string, string, error) {
	if m.listAuthHandlersFn != nil {
		return m.listAuthHandlersFn(ctx)
	}
	return nil, "", nil
}

func (m *mockAuthClient) GetAuthToken(ctx context.Context, handler, scope string, minValidFor int64, forceRefresh bool) (*proto.GetAuthTokenResponse, error) {
	if m.getAuthTokenFn != nil {
		return m.getAuthTokenFn(ctx, handler, scope, minValidFor, forceRefresh)
	}
	return &proto.GetAuthTokenResponse{}, nil
}

func (m *mockAuthClient) GetAuthGroups(ctx context.Context, handler string) ([]string, error) {
	if m.getAuthGroupsFn != nil {
		return m.getAuthGroupsFn(ctx, handler)
	}
	return nil, nil
}

var _ authClient = (*mockAuthClient)(nil)

// buildTestJWT creates a test JWT with the given claims.
func buildTestJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
	return header + "." + payloadB64 + "." + sig
}

func TestNewPlugin(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	require.NotNil(t, p)

	providers, err := p.GetProviders(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{ProviderName}, providers)

	desc, err := p.GetProviderDescriptor(context.Background(), ProviderName)
	require.NoError(t, err)
	assert.Equal(t, "identity", desc.Name)
	assert.Equal(t, "Identity", desc.DisplayName)
	assert.Equal(t, "v1", desc.APIVersion)
	assert.Equal(t, "security", desc.Category)
	assert.NotNil(t, desc.Version)
	assert.NotNil(t, desc.Schema)
}

func TestGetProviderDescriptor_Unknown(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	_, err := p.GetProviderDescriptor(context.Background(), "unknown")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestConfigureProvider(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	err := p.ConfigureProvider(context.Background(), ProviderName, sdkplugin.ProviderConfig{})
	require.NoError(t, err)
}

func TestExecuteProvider_MissingOperation(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	ctx := context.Background()

	_, err := p.ExecuteProvider(ctx, ProviderName, map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "operation is required")
}

func TestExecuteProvider_NoHostClient(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	ctx := context.Background()

	_, err := p.ExecuteProvider(ctx, ProviderName, map[string]any{
		"operation": "status",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "host client not available")
}

func TestExecuteProvider_UnsupportedOperation(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	ctx := sdkplugin.WithHostClient(context.Background(), sdkplugin.NewHostServiceClient(nil))

	_, err := p.ExecuteProvider(ctx, ProviderName, map[string]any{
		"operation": "invalid",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported operation")
}

func TestExecuteProvider_ScopeWithGroups(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	ctx := sdkplugin.WithHostClient(context.Background(), sdkplugin.NewHostServiceClient(nil))

	_, err := p.ExecuteProvider(ctx, ProviderName, map[string]any{
		"operation": "groups",
		"scope":     "api://test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope is not supported")
}

func TestExecuteProvider_ScopeWithList(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	ctx := sdkplugin.WithHostClient(context.Background(), sdkplugin.NewHostServiceClient(nil))

	_, err := p.ExecuteProvider(ctx, ProviderName, map[string]any{
		"operation": "list",
		"scope":     "api://test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope is not supported")
}

func TestExecuteProviderStream(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	err := p.ExecuteProviderStream(context.Background(), ProviderName, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, sdkplugin.ErrStreamingNotSupported)
}

func TestStopProvider(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	err := p.StopProvider(context.Background(), ProviderName)
	require.NoError(t, err)
}

func TestExtractDependencies(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	deps, err := p.ExtractDependencies(context.Background(), ProviderName, nil)
	require.NoError(t, err)
	assert.Nil(t, deps)
}

func TestDescribeWhatIf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		inputs   map[string]any
		contains string
	}{
		{
			name:     "status",
			inputs:   map[string]any{"operation": "status", "handler": "entra"},
			contains: "authentication status",
		},
		{
			name:     "status with scope",
			inputs:   map[string]any{"operation": "status", "handler": "entra", "scope": "api://test"},
			contains: "scoped token",
		},
		{
			name:     "claims",
			inputs:   map[string]any{"operation": "claims", "handler": "entra"},
			contains: "identity claims",
		},
		{
			name:     "claims with scope",
			inputs:   map[string]any{"operation": "claims", "handler": "entra", "scope": "api://test"},
			contains: "parse JWT",
		},
		{
			name:     "groups",
			inputs:   map[string]any{"operation": "groups", "handler": "entra"},
			contains: "group memberships",
		},
		{
			name:     "list",
			inputs:   map[string]any{"operation": "list"},
			contains: "auth handlers",
		},
		{
			name:     "unknown",
			inputs:   map[string]any{"operation": "unknown"},
			contains: "Unknown operation",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewPlugin()
			desc, err := p.DescribeWhatIf(context.Background(), ProviderName, tc.inputs)
			require.NoError(t, err)
			assert.Contains(t, desc, tc.contains)
		})
	}
}

func TestProtoClaimsToMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims *proto.Claims
		want   map[string]any
	}{
		{name: "nil claims", claims: nil, want: nil},
		{
			name: "full claims",
			claims: &proto.Claims{
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
			},
			want: map[string]any{
				"issuer":          "issuer",
				"subject":         "subject",
				"tenantId":        "tenant",
				"objectId":        "object",
				"clientId":        "client",
				"email":           "user@example.com",
				"name":            "Test User",
				"username":        "testuser",
				"displayIdentity": "Test User <user@example.com>",
			},
		},
		{
			name: "sparse claims",
			claims: &proto.Claims{
				Email: "only@example.com",
			},
			want: map[string]any{
				"email":           "only@example.com",
				"displayIdentity": "only@example.com",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := protoClaimsToMap(tc.claims)
			if tc.want == nil {
				assert.Nil(t, result)
				return
			}
			for k, v := range tc.want {
				assert.Equal(t, v, result[k], "key %s", k)
			}
		})
	}
}

func TestIdentityTypeFromProtoClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims *proto.Claims
		want   string
	}{
		{name: "nil", claims: nil, want: "user"},
		{name: "user with name", claims: &proto.Claims{Name: "User", ObjectId: "oid"}, want: "user"},
		{name: "service principal", claims: &proto.Claims{ObjectId: "oid"}, want: "service-principal"},
		{name: "user with email", claims: &proto.Claims{Email: "a@b.com"}, want: "user"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, identityTypeFromProtoClaims(tc.claims))
		})
	}
}

func TestIdentityTypeFromLocalClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims *Claims
		want   string
	}{
		{name: "nil", claims: nil, want: "user"},
		{name: "user with name", claims: &Claims{Name: "User", ObjectID: "oid"}, want: "user"},
		{name: "service principal", claims: &Claims{ObjectID: "oid"}, want: "service-principal"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, identityTypeFromLocalClaims(tc.claims))
		})
	}
}

func TestProtoDisplayIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims *proto.Claims
		want   string
	}{
		{name: "nil", claims: nil, want: ""},
		{name: "name and email", claims: &proto.Claims{Name: "John", Email: "john@example.com"}, want: "John <john@example.com>"},
		{name: "name only", claims: &proto.Claims{Name: "John"}, want: "John"},
		{name: "email only", claims: &proto.Claims{Email: "john@example.com"}, want: "john@example.com"},
		{name: "username only", claims: &proto.Claims{Username: "johndoe"}, want: "johndoe"},
		{name: "subject only", claims: &proto.Claims{Subject: "sub-123"}, want: "sub-123"},
		{name: "empty", claims: &proto.Claims{}, want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, protoDisplayIdentity(tc.claims))
		})
	}
}

func TestLocalClaimsToMap(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, localClaimsToMap(nil))
	})

	t.Run("full claims", func(t *testing.T) {
		t.Parallel()
		c := &Claims{
			Issuer:   "iss",
			Subject:  "sub",
			TenantID: "tid",
			ObjectID: "oid",
			ClientID: "cid",
			Email:    "e@x.com",
			Name:     "Name",
			Username: "user",
		}
		m := localClaimsToMap(c)
		assert.Equal(t, "iss", m["issuer"])
		assert.Equal(t, "Name <e@x.com>", m["displayIdentity"])
	})
}

func TestPopulateStatusFromProtoClaims(t *testing.T) {
	t.Parallel()

	t.Run("nil claims", func(t *testing.T) {
		t.Parallel()
		result := map[string]any{}
		populateStatusFromProtoClaims(result, nil)
		assert.Empty(t, result)
	})

	t.Run("with claims and expiry", func(t *testing.T) {
		t.Parallel()
		result := map[string]any{}
		populateStatusFromProtoClaims(result, &proto.Claims{
			TenantId:      "tid",
			ExpiresAtUnix: 9999999999, // far future
		})
		assert.Equal(t, "tid", result["tenantId"])
		assert.Equal(t, "user", result["identityType"])
		assert.Contains(t, result, "expiresAt")
		assert.Contains(t, result, "expiresIn")
	})

	t.Run("expired token", func(t *testing.T) {
		t.Parallel()
		result := map[string]any{}
		populateStatusFromProtoClaims(result, &proto.Claims{
			ExpiresAtUnix: 1000000000, // long past
		})
		assert.Equal(t, "expired", result["expiresIn"])
	})
}

func TestDescribeWhatIf_EmptyOperation(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	desc, err := p.DescribeWhatIf(context.Background(), ProviderName, map[string]any{})
	require.NoError(t, err)
	assert.Contains(t, desc, "Unknown operation")
}

func TestBuildTestJWT(t *testing.T) {
	t.Parallel()

	jwt := buildTestJWT(map[string]any{
		"iss":  "test-issuer",
		"sub":  "test-subject",
		"name": "Test",
	})

	claims, err := ParseJWTClaims(jwt)
	require.NoError(t, err)
	assert.Equal(t, "test-issuer", claims.Issuer)
	assert.Equal(t, "test-subject", claims.Subject)
	assert.Equal(t, "Test", claims.Name)
}

func TestGetProviders(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	providers, err := p.GetProviders(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"identity"}, providers)
}

func TestSchema(t *testing.T) {
	t.Parallel()

	p := NewPlugin()
	desc, err := p.GetProviderDescriptor(context.Background(), ProviderName)
	require.NoError(t, err)
	require.NotNil(t, desc.Schema)
	assert.NotNil(t, desc.OutputSchemas)
	assert.GreaterOrEqual(t, len(desc.Examples), 4)
}

func TestOperationValidation(t *testing.T) {
	t.Parallel()

	p := NewPlugin()

	t.Run("operation must be string", func(t *testing.T) {
		t.Parallel()
		ctx := sdkplugin.WithHostClient(context.Background(), sdkplugin.NewHostServiceClient(nil))
		_, err := p.ExecuteProvider(ctx, ProviderName, map[string]any{
			"operation": 42,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "operation is required")
	})
}

// --- Execute method tests via authClient mock ---

func TestExecute_Status_Authenticated(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthIdentityFn: func(_ context.Context, _, _ string) (*proto.Claims, error) {
			return &proto.Claims{
				Name:          "Test User",
				Email:         "test@example.com",
				TenantId:      "tid-123",
				ExpiresAtUnix: 9999999999,
			}, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "status", "entra", "")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, "status", data["operation"])
	assert.Equal(t, "entra", data["handler"])
	assert.True(t, data["authenticated"].(bool))
	assert.Equal(t, "tid-123", data["tenantId"])
	assert.Equal(t, "user", data["identityType"])
	assert.Contains(t, data, "expiresAt")
	assert.Contains(t, data, "expiresIn")
}

func TestExecute_Status_NotAuthenticated(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthIdentityFn: func(_ context.Context, _, _ string) (*proto.Claims, error) {
			return nil, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "status", "entra", "")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.False(t, data["authenticated"].(bool))
}

func TestExecute_Status_Error(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthIdentityFn: func(_ context.Context, _, _ string) (*proto.Claims, error) {
			return nil, fmt.Errorf("auth failed")
		},
	}

	p := NewPlugin()
	_, err := p.execute(context.Background(), mock, "status", "entra", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth failed")
}

func TestExecute_Claims_Authenticated(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthIdentityFn: func(_ context.Context, _, _ string) (*proto.Claims, error) {
			return &proto.Claims{
				Name:     "Test User",
				Email:    "test@example.com",
				ObjectId: "oid-123",
			}, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "claims", "entra", "")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, "claims", data["operation"])
	assert.True(t, data["authenticated"].(bool))
	assert.Equal(t, "user", data["identityType"])

	claims := data["claims"].(map[string]any)
	assert.Equal(t, "Test User", claims["name"])
	assert.Equal(t, "test@example.com", claims["email"])
}

func TestExecute_Claims_NotAuthenticated(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthIdentityFn: func(_ context.Context, _, _ string) (*proto.Claims, error) {
			return nil, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "claims", "entra", "")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.False(t, data["authenticated"].(bool))
	assert.Nil(t, data["claims"])
	assert.NotEmpty(t, out.Warnings)
}

func TestExecute_Claims_Error(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthIdentityFn: func(_ context.Context, _, _ string) (*proto.Claims, error) {
			return nil, fmt.Errorf("claims failed")
		},
	}

	p := NewPlugin()
	_, err := p.execute(context.Background(), mock, "claims", "entra", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "claims failed")
}

func TestExecute_ScopedStatus_WithJWT(t *testing.T) {
	t.Parallel()

	jwt := buildTestJWT(map[string]any{
		"sub":  "user-sub",
		"name": "Scoped User",
		"tid":  "scoped-tid",
		"oid":  "scoped-oid",
	})

	mock := &mockAuthClient{
		getAuthTokenFn: func(_ context.Context, _, _ string, _ int64, _ bool) (*proto.GetAuthTokenResponse, error) {
			return &proto.GetAuthTokenResponse{
				AccessToken:   jwt,
				TokenType:     "Bearer",
				ExpiresAtUnix: 9999999999,
			}, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "status", "entra", "api://test")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, true, data["scopedToken"])
	assert.Equal(t, "api://test", data["tokenScope"])
	assert.Equal(t, "Bearer", data["tokenType"])
	assert.Equal(t, "scoped-tid", data["tenantId"])
	assert.Equal(t, "user", data["identityType"])
	assert.Contains(t, data, "expiresAt")
	assert.Contains(t, data, "expiresIn")
	assert.Empty(t, out.Warnings)
}

func TestExecute_ScopedStatus_OpaqueToken(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthTokenFn: func(_ context.Context, _, _ string, _ int64, _ bool) (*proto.GetAuthTokenResponse, error) {
			return &proto.GetAuthTokenResponse{ //nolint:gosec // test fixture
				AccessToken:   "opaque-token-not-jwt",
				TokenType:     "Bearer",
				ExpiresAtUnix: 9999999999,
			}, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "status", "entra", "api://test")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.True(t, data["scopedToken"].(bool))
	assert.NotEmpty(t, out.Warnings)
	assert.Contains(t, out.Warnings[0], "not a decodable JWT")
}

func TestExecute_ScopedStatus_Error(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthTokenFn: func(_ context.Context, _, _ string, _ int64, _ bool) (*proto.GetAuthTokenResponse, error) {
			return nil, fmt.Errorf("token mint failed")
		},
	}

	p := NewPlugin()
	_, err := p.execute(context.Background(), mock, "status", "entra", "api://test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token mint failed")
}

func TestExecute_ScopedClaims_WithJWT(t *testing.T) {
	t.Parallel()

	jwt := buildTestJWT(map[string]any{
		"sub":   "user-sub",
		"name":  "Scoped User",
		"email": "scoped@example.com",
		"tid":   "scoped-tid",
	})

	mock := &mockAuthClient{
		getAuthTokenFn: func(_ context.Context, _, _ string, _ int64, _ bool) (*proto.GetAuthTokenResponse, error) {
			return &proto.GetAuthTokenResponse{
				AccessToken:   jwt,
				ExpiresAtUnix: 9999999999,
			}, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "claims", "entra", "api://test")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.True(t, data["scopedToken"].(bool))
	assert.Equal(t, "api://test", data["tokenScope"])
	assert.Equal(t, "user", data["identityType"])

	claims := data["claims"].(map[string]any)
	assert.Equal(t, "Scoped User", claims["name"])
	assert.Equal(t, "scoped@example.com", claims["email"])
}

func TestExecute_ScopedClaims_OpaqueToken(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthTokenFn: func(_ context.Context, _, _ string, _ int64, _ bool) (*proto.GetAuthTokenResponse, error) {
			return &proto.GetAuthTokenResponse{ //nolint:gosec // test fixture
				AccessToken:   "opaque-token",
				ExpiresAtUnix: 1700003600,
			}, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "claims", "entra", "api://test")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Nil(t, data["claims"])
	assert.Contains(t, data, "expiresAt")
	assert.NotEmpty(t, out.Warnings)
}

func TestExecute_ScopedClaims_Error(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthTokenFn: func(_ context.Context, _, _ string, _ int64, _ bool) (*proto.GetAuthTokenResponse, error) {
			return nil, fmt.Errorf("scoped claims error")
		},
	}

	p := NewPlugin()
	_, err := p.execute(context.Background(), mock, "claims", "entra", "api://test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scoped claims error")
}

func TestExecute_Groups_Success(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthGroupsFn: func(_ context.Context, _ string) ([]string, error) {
			return []string{"group-a", "group-b", "group-c"}, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "groups", "entra", "")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, "groups", data["operation"])
	assert.Equal(t, "entra", data["handler"])
	assert.Equal(t, []string{"group-a", "group-b", "group-c"}, data["groups"])
	assert.Equal(t, 3, data["count"])
}

func TestExecute_Groups_Empty(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthGroupsFn: func(_ context.Context, _ string) ([]string, error) {
			return nil, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "groups", "entra", "")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, []string{}, data["groups"])
	assert.Equal(t, 0, data["count"])
}

func TestExecute_Groups_Error(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthGroupsFn: func(_ context.Context, _ string) ([]string, error) {
			return nil, fmt.Errorf("groups failed")
		},
	}

	p := NewPlugin()
	_, err := p.execute(context.Background(), mock, "groups", "entra", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "groups failed")
}

func TestExecute_List_WithHandlers(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		listAuthHandlersFn: func(_ context.Context) ([]string, string, error) {
			return []string{"entra", "github"}, "entra", nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "list", "", "")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, "list", data["operation"])
	assert.Equal(t, 2, data["count"])

	handlers := data["handlers"].([]map[string]any)
	assert.Equal(t, "entra", handlers[0]["name"])
	assert.True(t, handlers[0]["default"].(bool))
	assert.Equal(t, "github", handlers[1]["name"])
	assert.False(t, handlers[1]["default"].(bool))
}

func TestExecute_List_Empty(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		listAuthHandlersFn: func(_ context.Context) ([]string, string, error) {
			return []string{}, "", nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "list", "", "")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, 0, data["count"])
}

func TestExecute_List_Error(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		listAuthHandlersFn: func(_ context.Context) ([]string, string, error) {
			return nil, "", fmt.Errorf("list failed")
		},
	}

	p := NewPlugin()
	_, err := p.execute(context.Background(), mock, "list", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list failed")
}

func TestExecute_UnsupportedOperation(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{}
	p := NewPlugin()
	_, err := p.execute(context.Background(), mock, "invalid", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported operation")
}

func TestExecute_ScopedStatus_ExpiredToken(t *testing.T) {
	t.Parallel()

	jwt := buildTestJWT(map[string]any{
		"sub": "user-sub",
		"tid": "tid",
	})

	mock := &mockAuthClient{
		getAuthTokenFn: func(_ context.Context, _, _ string, _ int64, _ bool) (*proto.GetAuthTokenResponse, error) {
			return &proto.GetAuthTokenResponse{
				AccessToken:   jwt,
				ExpiresAtUnix: 1000000000, // long past
			}, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "status", "entra", "api://test")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, "expired", data["expiresIn"])
}

func TestExecute_ScopedStatus_ServicePrincipal(t *testing.T) {
	t.Parallel()

	jwt := buildTestJWT(map[string]any{
		"oid": "sp-oid",
	})

	mock := &mockAuthClient{
		getAuthTokenFn: func(_ context.Context, _, _ string, _ int64, _ bool) (*proto.GetAuthTokenResponse, error) {
			return &proto.GetAuthTokenResponse{
				AccessToken: jwt,
			}, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "status", "entra", "api://test")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, "service-principal", data["identityType"])
}

func TestExecute_Claims_ServicePrincipal(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{
		getAuthIdentityFn: func(_ context.Context, _, _ string) (*proto.Claims, error) {
			return &proto.Claims{
				ObjectId: "sp-oid",
			}, nil
		},
	}

	p := NewPlugin()
	out, err := p.execute(context.Background(), mock, "claims", "entra", "")
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, "service-principal", data["identityType"])
}

func TestMockAuthClient_Defaults(t *testing.T) {
	t.Parallel()

	mock := &mockAuthClient{}
	ctx := context.Background()

	claims, err := mock.GetAuthIdentity(ctx, "", "")
	require.NoError(t, err)
	assert.Nil(t, claims)

	handlers, def, err := mock.ListAuthHandlers(ctx)
	require.NoError(t, err)
	assert.Nil(t, handlers)
	assert.Empty(t, def)

	tokenResp, err := mock.GetAuthToken(ctx, "", "", 0, false)
	require.NoError(t, err)
	assert.NotNil(t, tokenResp)

	groups, err := mock.GetAuthGroups(ctx, "")
	require.NoError(t, err)
	assert.Nil(t, groups)
}
