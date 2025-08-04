# Keycloak Management API

A RESTful API built with Axum that provides a simplified interface for managing Keycloak resources.

## Features

- **Realm Management**: Create, read, update, and delete realms
- **User Management**: CRUD operations for users with search capabilities
- **Client Management**: Manage OAuth2/OIDC clients
- **Group Management**: Organize users into groups
- **Role Management**: Define and manage roles
- **Session Management**: Logout users, manage sessions
- **Credential Management**: Reset passwords, manage user credentials
- **Event Management**: Track and configure audit events
- **Identity Provider Management**: Configure external identity providers (SAML, OIDC, etc.)
- **Client Scope Management**: Define and manage client scopes
- **User Federation**: Link users to external identity providers
- **User Attributes**: Manage custom user attributes and fields
- **User Groups**: Add/remove users from groups
- **Client Secret Management**: Rotate and manage client secrets
- **Protocol Mappers**: Configure how user data is mapped to tokens
- **Client Roles**: Create and manage client-specific roles
- **Role Mappings**: Assign realm and client roles to users and groups
- **API Key Authentication**: Optional API key protection
- **Automatic Token Refresh**: Handles Keycloak authentication tokens

## Prerequisites

- Rust 1.84+
- Running Keycloak instance
- Admin credentials for Keycloak

## Configuration

Set the following environment variables:

```bash
# Required
KEYCLOAK_PASSWORD=your-admin-password

# Optional (with defaults)
KEYCLOAK_URL=http://localhost:8080       # Keycloak server URL
KEYCLOAK_USERNAME=admin                  # Admin username
KEYCLOAK_REALM=master                    # Realm for authentication
KEYCLOAK_CLIENT_ID=admin-cli            # Client ID for authentication
PORT=3000                               # API server port
API_KEY=your-api-key                    # Optional API key for protection
```

## Running the API

```bash
cargo run
```

## API Endpoints

### Health Check
- `GET /health` - Check API health status

### Realms
- `GET /api/realms` - List all realms
- `POST /api/realms` - Create a new realm
- `GET /api/realms/:realm` - Get realm details
- `PUT /api/realms/:realm` - Update realm
- `DELETE /api/realms/:realm` - Delete realm

### Users
- `GET /api/realms/:realm/users` - List users (with query filters)
- `POST /api/realms/:realm/users` - Create user
- `GET /api/realms/:realm/users/:user_id` - Get user details
- `PUT /api/realms/:realm/users/:user_id` - Update user
- `DELETE /api/realms/:realm/users/:user_id` - Delete user

### Clients
- `GET /api/realms/:realm/clients` - List clients
- `POST /api/realms/:realm/clients` - Create client
- `GET /api/realms/:realm/clients/:client_id` - Get client details
- `PUT /api/realms/:realm/clients/:client_id` - Update client
- `DELETE /api/realms/:realm/clients/:client_id` - Delete client

### Groups
- `GET /api/realms/:realm/groups` - List groups
- `POST /api/realms/:realm/groups` - Create group
- `GET /api/realms/:realm/groups/:group_id` - Get group details
- `PUT /api/realms/:realm/groups/:group_id` - Update group
- `DELETE /api/realms/:realm/groups/:group_id` - Delete group

### Roles
- `GET /api/realms/:realm/roles` - List roles
- `POST /api/realms/:realm/roles` - Create role
- `GET /api/realms/:realm/roles/:role_name` - Get role details
- `PUT /api/realms/:realm/roles/:role_name` - Update role
- `DELETE /api/realms/:realm/roles/:role_name` - Delete role

### Sessions
- `POST /api/realms/:realm/logout-all` - Logout all sessions in realm
- `DELETE /api/realms/:realm/sessions/:session_id` - Delete specific session
- `GET /api/realms/:realm/users/:user_id/sessions` - Get user sessions
- `POST /api/realms/:realm/users/:user_id/logout` - Logout specific user

### Credentials
- `GET /api/realms/:realm/users/:user_id/credentials` - List user credentials
- `DELETE /api/realms/:realm/users/:user_id/credentials/:credential_id` - Delete credential
- `PUT /api/realms/:realm/users/:user_id/reset-password` - Reset user password
- `PUT /api/realms/:realm/users/:user_id/reset-password-email` - Send password reset email

### Events
- `GET /api/realms/:realm/events` - List events (with query filters)
- `DELETE /api/realms/:realm/events` - Clear all events
- `GET /api/realms/:realm/events/config` - Get events configuration
- `PUT /api/realms/:realm/events/config` - Update events configuration

### Identity Providers
- `GET /api/realms/:realm/identity-providers` - List identity providers
- `POST /api/realms/:realm/identity-providers` - Create identity provider
- `GET /api/realms/:realm/identity-providers/:alias` - Get identity provider details
- `PUT /api/realms/:realm/identity-providers/:alias` - Update identity provider
- `DELETE /api/realms/:realm/identity-providers/:alias` - Delete identity provider

### Client Scopes
- `GET /api/realms/:realm/client-scopes` - List client scopes
- `POST /api/realms/:realm/client-scopes` - Create client scope
- `GET /api/realms/:realm/client-scopes/:scope_id` - Get client scope details
- `PUT /api/realms/:realm/client-scopes/:scope_id` - Update client scope
- `DELETE /api/realms/:realm/client-scopes/:scope_id` - Delete client scope

### User Federation
- `GET /api/realms/:realm/users/:user_id/federated-identity` - List federated identities
- `POST /api/realms/:realm/users/:user_id/federated-identity/:provider` - Add federated identity
- `DELETE /api/realms/:realm/users/:user_id/federated-identity/:provider` - Remove federated identity

### User Attributes and Groups
- `GET /api/realms/:realm/users/:user_id/attributes` - Get user custom attributes
- `PUT /api/realms/:realm/users/:user_id/attributes` - Update user custom attributes
- `GET /api/realms/:realm/users/:user_id/groups` - Get user's groups
- `POST /api/realms/:realm/users/:user_id/groups` - Add user to groups
- `DELETE /api/realms/:realm/users/:user_id/groups/:group_id` - Remove user from group
- `PUT /api/realms/:realm/users/:user_id/required-actions` - Update user required actions

### Client Advanced Management
- `GET /api/realms/:realm/clients/:client_id/secret` - Get client secret
- `POST /api/realms/:realm/clients/:client_id/secret` - Regenerate client secret
- `GET /api/realms/:realm/clients/:client_id/secret-rotated` - Get rotated secret
- `DELETE /api/realms/:realm/clients/:client_id/secret-rotated` - Delete rotated secret
- `GET /api/realms/:realm/clients/:client_id/default-scopes` - List default scopes
- `PUT /api/realms/:realm/clients/:client_id/default-scopes/:scope_id` - Add default scope
- `DELETE /api/realms/:realm/clients/:client_id/default-scopes/:scope_id` - Remove default scope
- `GET /api/realms/:realm/clients/:client_id/optional-scopes` - List optional scopes
- `PUT /api/realms/:realm/clients/:client_id/optional-scopes/:scope_id` - Add optional scope
- `DELETE /api/realms/:realm/clients/:client_id/optional-scopes/:scope_id` - Remove optional scope

### Client Protocol Mappers
- `GET /api/realms/:realm/clients/:client_id/protocol-mappers` - List protocol mappers
- `POST /api/realms/:realm/clients/:client_id/protocol-mappers` - Create protocol mapper
- `GET /api/realms/:realm/clients/:client_id/protocol-mappers/:mapper_id` - Get protocol mapper
- `PUT /api/realms/:realm/clients/:client_id/protocol-mappers/:mapper_id` - Update protocol mapper
- `DELETE /api/realms/:realm/clients/:client_id/protocol-mappers/:mapper_id` - Delete protocol mapper

### Client Roles
- `GET /api/realms/:realm/clients/:client_id/roles` - List client roles
- `POST /api/realms/:realm/clients/:client_id/roles` - Create client role
- `GET /api/realms/:realm/clients/:client_id/roles/:role_name` - Get client role
- `PUT /api/realms/:realm/clients/:client_id/roles/:role_name` - Update client role
- `DELETE /api/realms/:realm/clients/:client_id/roles/:role_name` - Delete client role
- `GET /api/realms/:realm/clients/:client_id/roles/:role_name/composites` - Get composite roles
- `POST /api/realms/:realm/clients/:client_id/roles/:role_name/composites` - Add composite roles

### Role Mappings
- `GET /api/realms/:realm/users/:user_id/role-mappings` - Get all user role mappings
- `GET /api/realms/:realm/users/:user_id/role-mappings/realm` - Get realm role mappings
- `POST /api/realms/:realm/users/:user_id/role-mappings/realm` - Add realm roles to user
- `DELETE /api/realms/:realm/users/:user_id/role-mappings/realm` - Remove realm roles from user
- `GET /api/realms/:realm/users/:user_id/role-mappings/realm/available` - Get available realm roles
- `GET /api/realms/:realm/users/:user_id/role-mappings/clients/:client_id` - Get client role mappings
- `POST /api/realms/:realm/users/:user_id/role-mappings/clients/:client_id` - Add client roles to user
- `DELETE /api/realms/:realm/users/:user_id/role-mappings/clients/:client_id` - Remove client roles from user
- `GET /api/realms/:realm/users/:user_id/role-mappings/clients/:client_id/available` - Get available client roles
- `GET /api/realms/:realm/groups/:group_id/role-mappings` - Get group role mappings
- `GET /api/realms/:realm/groups/:group_id/role-mappings/clients/:client_id` - Get group client role mappings
- `POST /api/realms/:realm/groups/:group_id/role-mappings/clients/:client_id` - Add client roles to group
- `DELETE /api/realms/:realm/groups/:group_id/role-mappings/clients/:client_id` - Remove client roles from group

## Authentication

If `API_KEY` environment variable is set, all requests (except health check) must include the API key in the `x-api-key` header.

## Example Usage

### Create a User
```bash
curl -X POST http://localhost:3000/api/realms/master/users \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "enabled": true,
    "firstName": "Test",
    "lastName": "User"
  }'
```

### List Users with Search
```bash
curl "http://localhost:3000/api/realms/master/users?search=test" \
  -H "x-api-key: your-api-key"
```

### Reset User Password
```bash
curl -X PUT http://localhost:3000/api/realms/master/users/{user-id}/reset-password \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key" \
  -d '{
    "temporary": false,
    "value": "newPassword123!"
  }'
```

### Create Identity Provider (SAML)
```bash
curl -X POST http://localhost:3000/api/realms/master/identity-providers \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key" \
  -d '{
    "alias": "saml-provider",
    "providerId": "saml",
    "enabled": true,
    "config": {
      "singleSignOnServiceUrl": "https://idp.example.com/sso",
      "singleLogoutServiceUrl": "https://idp.example.com/logout",
      "nameIDPolicyFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    }
  }'
```

### List Events with Filters
```bash
curl "http://localhost:3000/api/realms/master/events?type=LOGIN&user=admin&dateFrom=2024-01-01" \
  -H "x-api-key: your-api-key"
```

### Update User Attributes
```bash
curl -X PUT http://localhost:3000/api/realms/master/users/{user-id}/attributes \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key" \
  -d '{
    "attributes": {
      "department": ["Engineering"],
      "location": ["San Francisco", "Remote"],
      "employee_id": ["12345"]
    }
  }'
```

### Create Client Protocol Mapper
```bash
curl -X POST http://localhost:3000/api/realms/master/clients/{client-id}/protocol-mappers \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key" \
  -d '{
    "name": "department-mapper",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "consentRequired": false,
    "config": {
      "userinfo.token.claim": "true",
      "user.attribute": "department",
      "id.token.claim": "true",
      "access.token.claim": "true",
      "claim.name": "department",
      "jsonType.label": "String"
    }
  }'
```

### Assign Client Roles to User
```bash
curl -X POST http://localhost:3000/api/realms/master/users/{user-id}/role-mappings/clients/{client-id} \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key" \
  -d '{
    "roles": [
      {
        "id": "role-id-1",
        "name": "admin"
      },
      {
        "id": "role-id-2", 
        "name": "viewer"
      }
    ]
  }'
```

### Regenerate Client Secret
```bash
curl -X POST http://localhost:3000/api/realms/master/clients/{client-id}/secret \
  -H "x-api-key: your-api-key"
```

## Error Handling

The API returns appropriate HTTP status codes and JSON error messages:

- `400` - Bad Request
- `401` - Unauthorized
- `404` - Not Found
- `409` - Conflict
- `500` - Internal Server Error

Error response format:
```json
{
  "error": "Error message here"
}
```