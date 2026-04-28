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

### Inputs

| Input | Required | Description |
|-------|----------|-------------|
| `operation` | Yes | One of: `status`, `claims`, `groups`, `list` |
| `handler` | No | Auth handler name (uses default if omitted) |
| `scope` | No | OAuth scope for token requests (triggers scoped token flow) |

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
