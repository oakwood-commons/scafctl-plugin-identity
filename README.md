# scafctl-plugin-identity

Retrieves authentication identity, claims, and group membership from
configured auth handlers without exposing tokens or secrets.

## Installation

```bash
# Build from source
task build

# Or install from the scafctl catalog
scafctl plugins install identity
```

## Usage

Register this plugin in your scafctl solution, then reference
the **identity** provider in your resolvers:

```yaml
resolvers:
  # Check authentication status
  auth-status:
    resolve:
      with:
        - provider: identity
          inputs:
            operation: status

  # Get JWT claims for the current identity
  auth-claims:
    resolve:
      with:
        - provider: identity
          inputs:
            operation: claims

  # Get claims from a specific handler with a custom scope
  scoped-claims:
    resolve:
      with:
        - provider: identity
          inputs:
            operation: claims
            handler: azure
            scope: "api://my-app/.default"

  # List group memberships
  groups:
    resolve:
      with:
        - provider: identity
          inputs:
            operation: groups

  # List available auth handlers
  handlers:
    resolve:
      with:
        - provider: identity
          inputs:
            operation: list
```

### Operations

| Operation | Description |
|-----------|-------------|
| `status` | Returns authentication status, identity type, and display name |
| `claims` | Returns parsed JWT claims (issuer, subject, email, etc.) |
| `groups` | Returns group memberships for the current identity |
| `list` | Lists available auth handlers and the default handler |

> **Device-code sessions require a `scope`.** When the host has no cached ID
> token (common with the Entra device-code flow), `claims` and `status` cannot
> derive an identity on their own and return the unauthenticated fallback with a
> warning. Supply a `scope` (e.g., `api://<app-id>/.default`) so the provider
> mints a scoped token and parses identity from it. Without a scope, downstream
> auth-gated resolvers are disabled.

### Inputs

| Input | Required | Description |
|-------|----------|-------------|
| `operation` | Yes | One of: `status`, `claims`, `groups`, `list` |
| `handler` | No | Auth handler name (uses default if omitted) |
| `scope` | No | OAuth scope for token requests (triggers scoped token flow). Required for device-code/token-only sessions where no ID token is cached; without it, `claims`/`status` return the unauthenticated fallback. |

## Development

```bash
# Run tests
task test

# Run linter
task lint

# Run benchmarks
task bench

# Build
task build

# Full CI pipeline
task ci
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.
