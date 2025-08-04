# Keycloak Domain Integration Tests

This directory contains integration tests for the Keycloak domain layer using testcontainers-rs.

## Test Files

- `integration_test.rs` - Unit tests for domain entities and services (fast)
- `testcontainers_keycloak.rs` - Testcontainers setup and utilities for Keycloak
- `integration_tests_with_keycloak.rs` - Integration tests with real Keycloak instance (slower)

## Running Tests

### Unit Tests Only (Fast)
```bash
cargo test integration_test
```

### Integration Tests with Keycloak (Slower - requires Docker)
```bash
cargo test integration_tests_with_keycloak
```

### All Tests
```bash
cargo test
```

## Test Features

### Shared Container Performance
The integration tests use a shared Keycloak container across all tests to minimize startup time:
- ✅ First test: ~10 seconds (container startup)
- ✅ Subsequent tests: ~100ms (reuse existing container)

### Test Scenarios Covered

1. **Authentication Flow Testing**
   - Admin token acquisition
   - Token endpoint validation
   - User authentication flows

2. **Realm Management**
   - Realm creation and configuration
   - Realm accessibility verification

3. **Client Management**
   - Public and confidential client creation
   - Client property validation

4. **User Management**
   - User creation with/without email
   - User property verification

5. **Configuration Testing**
   - Environment-based configuration
   - Live Keycloak connection validation

6. **Performance Testing**
   - Shared container efficiency
   - Multiple test execution timing

## Container Configuration

The tests use:
- **Image**: `quay.io/keycloak/keycloak:25.0`
- **Admin User**: `admin` / `admin`
- **Memory**: Optimized for testing (1-5% of available RAM)
- **Mode**: Development mode with HTTP

## Test Utilities

The `testcontainers_keycloak.rs` module provides:

### Container Management
- `get_keycloak_container()` - Get shared container instance
- `get_keycloak_with_test_realm(name)` - Get container with pre-configured realm

### Helper Methods
- `get_admin_token()` - Obtain admin access token
- `create_test_realm(name)` - Create a test realm
- `create_test_client(realm, id, public)` - Create test client
- `create_test_user(realm, username, password, email)` - Create test user

### URL Helpers
- `admin_console_url()` - Admin console URL
- `realm_url(realm)` - Realm-specific URL
- `token_endpoint_url(realm)` - Token endpoint URL

## Requirements

- Docker or Podman must be available
- Sufficient memory for Keycloak container (~500MB)
- Network access for pulling Keycloak image

## Troubleshooting

### Container Startup Issues
If tests fail with container startup errors:
1. Ensure Docker/Podman is running
2. Check available memory
3. Verify network connectivity

### Port Conflicts
If you get port binding errors:
- Tests use dynamic port allocation
- Ensure no other Keycloak instances are running

### Slow Test Execution
- First test run downloads Keycloak image (~10 seconds)
- Subsequent runs should be faster with image caching
- Container is shared across tests in same run

## Example Test Output

```
✅ Keycloak authentication flow test passed
   Base URL: http://localhost:32768
   Admin Console: http://localhost:32768/admin

✅ Realm management test passed
   Realm: integration-test-realm
   Realm URL: http://localhost:32768/realms/integration-test-realm

✅ Shared container test 1 completed in: 15.2s
✅ Shared container test 2 completed in: 150ms
✅ Shared container test 3 completed in: 98ms
```