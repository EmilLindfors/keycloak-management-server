use rmcp::{
    model::*,
    tool, tool_router, tool_handler,
    handler::server::router::tool::ToolRouter,
    ErrorData as McpError,
    ServerHandler, RoleServer,
    service::RequestContext,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::{Config, AppState};

#[derive(Clone)]
pub struct KeycloakMcpServer {
    state: Arc<AppState>,
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListUsersParams {
    pub realm: String,
    pub search: Option<String>,
    pub first: Option<i32>,
    pub max: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserParams {
    pub realm: String,
    pub username: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: Option<bool>,
    pub temporary_password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUserParams {
    pub realm: String,
    pub user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListRealmsParams {}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRealmParams {
    pub realm: String,
    pub enabled: Option<bool>,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListClientsParams {
    pub realm: String,
    pub client_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateClientParams {
    pub realm: String,
    pub client_id: String,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub client_protocol: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListGroupsParams {
    pub realm: String,
    pub search: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupParams {
    pub realm: String,
    pub name: String,
    pub path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListRolesParams {
    pub realm: String,
    pub search: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRoleParams {
    pub realm: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResetPasswordParams {
    pub realm: String,
    pub user_id: String,
    pub password: String,
    pub temporary: Option<bool>,
}

#[tool_router]
impl KeycloakMcpServer {
    pub async fn new(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let state = Arc::new(AppState::new(config).await?);
        Ok(Self {
            state,
            tool_router: Self::tool_router(),
        })
    }

    #[tool(description = "List users in a realm with optional search filters")]
    async fn list_users(&self, params: ListUsersParams) -> Result<CallToolResult, McpError> {
        let keycloak_client = &self.state.keycloak_client;
        
        let mut query_params = Vec::new();
        if let Some(search) = &params.search {
            query_params.push(("search", search.as_str()));
        }
        if let Some(first) = params.first {
            query_params.push(("first", &first.to_string()));
        }
        if let Some(max) = params.max {
            query_params.push(("max", &max.to_string()));
        }

        match keycloak_client
            .realm_users_get(&params.realm, Some(query_params))
            .await
        {
            Ok(users) => {
                let content = serde_json::to_string_pretty(&users)
                    .map_err(|e| McpError::new(-1, format!("Serialization error: {}", e)))?;
                Ok(CallToolResult::success(vec![Content::text(content)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to list users: {}", e))),
        }
    }

    #[tool(description = "Create a new user in the specified realm")]
    async fn create_user(&self, params: CreateUserParams) -> Result<CallToolResult, McpError> {
        let keycloak_client = &self.state.keycloak_client;
        
        let mut user_rep = keycloak::types::UserRepresentation::default();
        user_rep.username = Some(params.username);
        user_rep.email = params.email;
        user_rep.first_name = params.first_name;
        user_rep.last_name = params.last_name;
        user_rep.enabled = params.enabled;

        match keycloak_client
            .realm_users_post(&params.realm, user_rep)
            .await
        {
            Ok(_) => {
                let result = format!("User created successfully in realm '{}'", params.realm);
                Ok(CallToolResult::success(vec![Content::text(result)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to create user: {}", e))),
        }
    }

    #[tool(description = "Get user details by user ID")]
    async fn get_user(&self, params: GetUserParams) -> Result<CallToolResult, McpError> {
        let keycloak_client = &self.state.keycloak_client;

        match keycloak_client
            .realm_users_with_id_get(&params.realm, &params.user_id)
            .await
        {
            Ok(user) => {
                let content = serde_json::to_string_pretty(&user)
                    .map_err(|e| McpError::new(-1, format!("Serialization error: {}", e)))?;
                Ok(CallToolResult::success(vec![Content::text(content)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to get user: {}", e))),
        }
    }

    #[tool(description = "List all realms")]
    async fn list_realms(&self, _params: ListRealmsParams) -> Result<CallToolResult, McpError> {
        let keycloak_client = &self.state.keycloak_client;

        match keycloak_client.admin_realms_get().await {
            Ok(realms) => {
                let content = serde_json::to_string_pretty(&realms)
                    .map_err(|e| McpError::new(-1, format!("Serialization error: {}", e)))?;
                Ok(CallToolResult::success(vec![Content::text(content)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to list realms: {}", e))),
        }
    }

    #[tool(description = "Create a new realm")]
    async fn create_realm(&self, params: CreateRealmParams) -> Result<CallToolResult, McpError> {
        let keycloak_client = &self.state.keycloak_client;
        
        let mut realm_rep = keycloak::types::RealmRepresentation::default();
        realm_rep.realm = Some(params.realm.clone());
        realm_rep.enabled = params.enabled;
        realm_rep.display_name = params.display_name;

        match keycloak_client.admin_realms_post(realm_rep).await {
            Ok(_) => {
                let result = format!("Realm '{}' created successfully", params.realm);
                Ok(CallToolResult::success(vec![Content::text(result)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to create realm: {}", e))),
        }
    }

    #[tool(description = "List clients in a realm")]
    async fn list_clients(&self, params: ListClientsParams) -> Result<CallToolResult, McpError> {
        let keycloak_client = &self.state.keycloak_client;
        
        let query_params = if let Some(client_id) = &params.client_id {
            Some(vec![("clientId", client_id.as_str())])
        } else {
            None
        };

        match keycloak_client
            .realm_clients_get(&params.realm, query_params)
            .await
        {
            Ok(clients) => {
                let content = serde_json::to_string_pretty(&clients)
                    .map_err(|e| McpError::new(-1, format!("Serialization error: {}", e)))?;
                Ok(CallToolResult::success(vec![Content::text(content)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to list clients: {}", e))),
        }
    }

    #[tool(description = "Create a new client in the specified realm")]
    async fn create_client(&self, params: CreateClientParams) -> Result<CallToolResult, McpError> {
        let keycloak_client = &self.state.keycloak_client;
        
        let mut client_rep = keycloak::types::ClientRepresentation::default();
        client_rep.client_id = Some(params.client_id);
        client_rep.name = params.name;
        client_rep.enabled = params.enabled;
        client_rep.protocol = params.client_protocol;

        match keycloak_client
            .realm_clients_post(&params.realm, client_rep)
            .await
        {
            Ok(_) => {
                let result = format!("Client created successfully in realm '{}'", params.realm);
                Ok(CallToolResult::success(vec![Content::text(result)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to create client: {}", e))),
        }
    }

    #[tool(description = "List groups in a realm")]
    async fn list_groups(&self, params: ListGroupsParams) -> Result<CallToolResult, McpError> {
        let keycloak_client = &self.state.keycloak_client;
        
        let query_params = if let Some(search) = &params.search {
            Some(vec![("search", search.as_str())])
        } else {
            None
        };

        match keycloak_client
            .realm_groups_get(&params.realm, query_params)
            .await
        {
            Ok(groups) => {
                let content = serde_json::to_string_pretty(&groups)
                    .map_err(|e| McpError::new(-1, format!("Serialization error: {}", e)))?;
                Ok(CallToolResult::success(vec![Content::text(content)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to list groups: {}", e))),
        }
    }

    #[tool(description = "Create a new group in the specified realm")]
    async fn create_group(&self, params: CreateGroupParams) -> Result<CallToolResult, McpError> {
        let keycloak_client = &self.state.keycloak_client;
        
        let mut group_rep = keycloak::types::GroupRepresentation::default();
        group_rep.name = Some(params.name);
        group_rep.path = params.path;

        match keycloak_client
            .realm_groups_post(&params.realm, group_rep)
            .await
        {
            Ok(_) => {
                let result = format!("Group created successfully in realm '{}'", params.realm);
                Ok(CallToolResult::success(vec![Content::text(result)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to create group: {}", e))),
        }
    }

    #[tool(description = "List roles in a realm")]
    async fn list_roles(&self, params: ListRolesParams) -> Result<CallToolResult, McpError> {
        let keycloak_client = &self.state.keycloak_client;
        
        let query_params = if let Some(search) = &params.search {
            Some(vec![("search", search.as_str())])
        } else {
            None
        };

        match keycloak_client
            .realm_roles_get(&params.realm, query_params)
            .await
        {
            Ok(roles) => {
                let content = serde_json::to_string_pretty(&roles)
                    .map_err(|e| McpError::new(-1, format!("Serialization error: {}", e)))?;
                Ok(CallToolResult::success(vec![Content::text(content)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to list roles: {}", e))),
        }
    }

    #[tool(description = "Create a new role in the specified realm")]
    async fn create_role(&self, params: CreateRoleParams) -> Result<CallToolResult, McpError> {
        let keycloak_client = &self.state.keycloak_client;
        
        let mut role_rep = keycloak::types::RoleRepresentation::default();
        role_rep.name = Some(params.name);
        role_rep.description = params.description;

        match keycloak_client
            .realm_roles_post(&params.realm, role_rep)
            .await
        {
            Ok(_) => {
                let result = format!("Role created successfully in realm '{}'", params.realm);
                Ok(CallToolResult::success(vec![Content::text(result)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to create role: {}", e))),
        }
    }

    #[tool(description = "Reset user password")]
    async fn reset_password(&self, params: ResetPasswordParams) -> Result<CallToolResult, McpError> {
        let keycloak_client = &self.state.keycloak_client;
        
        let mut credential_rep = keycloak::types::CredentialRepresentation::default();
        credential_rep.type_ = Some("password".to_string());
        credential_rep.value = Some(params.password);
        credential_rep.temporary = params.temporary;

        match keycloak_client
            .realm_users_with_id_reset_password_put(&params.realm, &params.user_id, credential_rep)
            .await
        {
            Ok(_) => {
                let result = format!("Password reset successfully for user {} in realm '{}'", params.user_id, params.realm);
                Ok(CallToolResult::success(vec![Content::text(result)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to reset password: {}", e))),
        }
    }
}

#[tool_handler]
impl ServerHandler for KeycloakMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("Keycloak Management MCP Server - manage Keycloak realms, users, clients, groups, and roles through MCP tools".to_string()),
        }
    }

    async fn initialize(
        &self,
        _request: InitializeRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        Ok(self.get_info())
    }
}