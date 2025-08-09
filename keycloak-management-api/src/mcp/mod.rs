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
use keycloak_domain::{
    application::ports::auth::AuthorizationContext,
    domain::entities::{UserFilter, RealmFilter, ClientFilter, GroupFilter, RoleFilter},
};

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

    /// Create an authorization context for MCP operations
    /// For now, using a basic admin context - should be enhanced with proper auth
    fn create_auth_context(&self, realm: &str) -> AuthorizationContext {
        AuthorizationContext::new(realm.to_string())
            .with_user("mcp-admin".to_string())
            .with_roles(vec!["admin".to_string(), "realm-admin".to_string()])
    }

    #[tool(description = "List users in a realm with optional search filters")]
    async fn list_users(&self, params: ListUsersParams) -> Result<CallToolResult, McpError> {
        let auth_context = self.create_auth_context(&params.realm);
        
        let filter = UserFilter {
            search: params.search,
            first: params.first,
            max: params.max,
            ..Default::default()
        };

        match self.state.user_service.list_users(&params.realm, &filter, &auth_context).await {
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
        let auth_context = self.create_auth_context(&params.realm);
        
        let request = keycloak_domain::domain::entities::CreateUserRequest {
            username: params.username.clone(),
            email: params.email,
            first_name: params.first_name,
            last_name: params.last_name,
            enabled: params.enabled,
            temporary_password: params.temporary_password,
            attributes: Default::default(),
        };

        match self.state.user_service.create_user(&params.realm, &request, &auth_context).await {
            Ok(user_id) => {
                let result = format!(
                    "User '{}' created successfully in realm '{}' with ID: {}", 
                    params.username, params.realm, user_id
                );
                Ok(CallToolResult::success(vec![Content::text(result)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to create user: {}", e))),
        }
    }

    #[tool(description = "Get user details by user ID")]
    async fn get_user(&self, params: GetUserParams) -> Result<CallToolResult, McpError> {
        let auth_context = self.create_auth_context(&params.realm);

        match self.state.user_service.get_user(&params.realm, &params.user_id, &auth_context).await {
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
        let auth_context = self.create_auth_context("master");
        let filter = RealmFilter::default();

        match self.state.realm_service.list_realms_with_filter(&filter, &auth_context).await {
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
        let auth_context = self.create_auth_context("master");
        
        let request = keycloak_domain::domain::entities::CreateRealmRequest {
            realm: params.realm.clone(),
            enabled: params.enabled,
            display_name: params.display_name,
            ..Default::default()
        };

        match self.state.realm_service.create_realm(&request, &auth_context).await {
            Ok(realm_id) => {
                let result = format!("Realm '{}' created successfully with ID: {}", params.realm, realm_id);
                Ok(CallToolResult::success(vec![Content::text(result)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to create realm: {}", e))),
        }
    }

    #[tool(description = "List clients in a realm")]
    async fn list_clients(&self, params: ListClientsParams) -> Result<CallToolResult, McpError> {
        let auth_context = self.create_auth_context(&params.realm);
        
        let filter = ClientFilter {
            client_id: params.client_id,
            ..Default::default()
        };

        match self.state.client_service.list_clients(&params.realm, &filter, &auth_context).await {
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
        let auth_context = self.create_auth_context(&params.realm);
        
        let request = keycloak_domain::domain::entities::CreateClientRequest {
            client_id: params.client_id.clone(),
            name: params.name,
            enabled: params.enabled,
            protocol: params.client_protocol,
            ..Default::default()
        };

        match self.state.client_service.create_client(&params.realm, &request, &auth_context).await {
            Ok(client_uuid) => {
                let result = format!("Client '{}' created successfully in realm '{}' with ID: {}", params.client_id, params.realm, client_uuid);
                Ok(CallToolResult::success(vec![Content::text(result)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to create client: {}", e))),
        }
    }

    #[tool(description = "List groups in a realm")]
    async fn list_groups(&self, params: ListGroupsParams) -> Result<CallToolResult, McpError> {
        let auth_context = self.create_auth_context(&params.realm);
        
        let filter = GroupFilter {
            search: params.search,
            ..Default::default()
        };

        match self.state.group_service.list_groups(&params.realm, &filter, &auth_context).await {
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
        let auth_context = self.create_auth_context(&params.realm);
        
        let request = keycloak_domain::domain::entities::CreateGroupRequest {
            name: params.name.clone(),
            path: params.path,
            parent_id: None,
            attributes: Default::default(),
        };

        match self.state.group_service.create_group(&params.realm, &request, &auth_context).await {
            Ok(group_id) => {
                let result = format!("Group '{}' created successfully in realm '{}' with ID: {}", params.name, params.realm, group_id);
                Ok(CallToolResult::success(vec![Content::text(result)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to create group: {}", e))),
        }
    }

    #[tool(description = "List roles in a realm")]
    async fn list_roles(&self, params: ListRolesParams) -> Result<CallToolResult, McpError> {
        let auth_context = self.create_auth_context(&params.realm);
        
        let filter = RoleFilter {
            search: params.search,
            ..Default::default()
        };

        match self.state.role_service.list_roles(&params.realm, &filter, &auth_context).await {
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
        let auth_context = self.create_auth_context(&params.realm);
        
        let request = keycloak_domain::domain::entities::CreateRoleRequest {
            name: params.name.clone(),
            description: params.description,
            composite: Some(false),
            client_role: Some(false),
            container_id: params.realm.clone(),
            attributes: Default::default(),
        };

        match self.state.role_service.create_role(&params.realm, &request, &auth_context).await {
            Ok(role_id) => {
                let result = format!("Role '{}' created successfully in realm '{}' with ID: {}", params.name, params.realm, role_id);
                Ok(CallToolResult::success(vec![Content::text(result)]))
            }
            Err(e) => Err(McpError::new(-1, format!("Failed to create role: {}", e))),
        }
    }

    #[tool(description = "Reset user password")]
    async fn reset_password(&self, params: ResetPasswordParams) -> Result<CallToolResult, McpError> {
        let auth_context = self.create_auth_context(&params.realm);

        match self.state.user_service.reset_password(
            &params.realm, 
            &params.user_id, 
            &params.password, 
            params.temporary.unwrap_or(false),
            &auth_context
        ).await {
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