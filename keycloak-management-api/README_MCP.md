# Keycloak Management MCP Server

This project provides a Model Context Protocol (MCP) server that exposes Keycloak management functionality through standardized tools. The MCP server runs alongside the existing REST API and provides an MCP-compatible interface for managing Keycloak resources.

## Architecture

- **REST API Server** (`keycloak-api-server`): The original HTTP REST API server
- **MCP Server** (`keycloak-mcp-server`): The new MCP server that provides the same functionality through MCP tools
- **Shared Library**: Both servers use the same underlying Keycloak client and business logic

## MCP Server Features

The MCP server exposes the following tools:

### User Management
- `list_users` - List users in a realm with optional search filters
- `create_user` - Create a new user in the specified realm
- `get_user` - Get user details by user ID
- `reset_password` - Reset user password

### Realm Management
- `list_realms` - List all realms
- `create_realm` - Create a new realm

### Client Management
- `list_clients` - List clients in a realm
- `create_client` - Create a new client in the specified realm

### Group Management
- `list_groups` - List groups in a realm
- `create_group` - Create a new group in the specified realm

### Role Management
- `list_roles` - List roles in a realm
- `create_role` - Create a new role in the specified realm

## Configuration

Set the same environment variables as the REST API:

```bash
# Required
KEYCLOAK_PASSWORD=your-admin-password

# Optional (with defaults)
KEYCLOAK_URL=http://localhost:8080       # Keycloak server URL
KEYCLOAK_USERNAME=admin                  # Admin username
KEYCLOAK_REALM=master                    # Realm for authentication
KEYCLOAK_CLIENT_ID=admin-cli            # Client ID for authentication
```

## Running the MCP Server

### Start the MCP Server
```bash
cargo run --bin keycloak-mcp-server
```

The MCP server will start on `http://127.0.0.1:8001/mcp` by default.

### Test with Example Client
```bash
cargo run --bin mcp-client-example
```

## Using the MCP Server

### With MCP-Compatible Tools

The server implements the Model Context Protocol and can be used with any MCP-compatible client or tool. Connect to the server at:

```
http://127.0.0.1:8001/mcp
```

### Example Tool Calls

#### List Users
```json
{
  "name": "list_users",
  "arguments": {
    "realm": "master",
    "search": "john",
    "first": 0,
    "max": 10
  }
}
```

#### Create User
```json
{
  "name": "create_user",
  "arguments": {
    "realm": "master",
    "username": "newuser",
    "email": "newuser@example.com",
    "first_name": "New",
    "last_name": "User",
    "enabled": true,
    "temporary_password": "temp123"
  }
}
```

#### Create Realm
```json
{
  "name": "create_realm",
  "arguments": {
    "realm": "my-new-realm",
    "enabled": true,
    "display_name": "My New Realm"
  }
}
```

#### Reset Password
```json
{
  "name": "reset_password",
  "arguments": {
    "realm": "master",
    "user_id": "user-uuid-here",
    "password": "newpassword123",
    "temporary": false
  }
}
```

## Transport Protocol

The MCP server uses HTTP streaming transport, which allows for:
- Real-time bidirectional communication
- Efficient resource usage
- Standard HTTP infrastructure compatibility
- Easy integration with existing systems

## Development

### Building
```bash
cargo build
```

### Running Tests
```bash
cargo test
```

### Adding New Tools

To add new MCP tools:

1. Add the parameter struct in `src/mcp/mod.rs`
2. Implement the tool method with the `#[tool]` attribute
3. The tool will automatically be registered and available through the MCP interface

Example:
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct NewToolParams {
    pub realm: String,
    pub some_param: String,
}

#[tool(description = "Description of what this tool does")]
async fn new_tool(&self, params: NewToolParams) -> Result<CallToolResult, McpError> {
    // Implementation here
    Ok(CallToolResult::success(vec![Content::text("Success")]))
}
```

## Integration

The MCP server can be integrated into larger systems that support the Model Context Protocol, enabling Keycloak management capabilities within AI assistants, automation tools, and other MCP-compatible applications.

## Comparison with REST API

| Feature | REST API | MCP Server |
|---------|----------|------------|
| Protocol | HTTP REST | Model Context Protocol |
| Transport | HTTP | HTTP Streaming |
| Interface | Endpoints | Tools |
| Discovery | Documentation | Built-in tool listing |
| Typing | JSON Schema | Serde + JSON Schema |
| Auth | API Key | Inherited from Keycloak client |

Both servers provide the same underlying functionality but through different protocols suitable for different use cases.