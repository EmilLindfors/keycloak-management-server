use keycloak_management_api::{Config, mcp::KeycloakMcpServer};
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const BIND_ADDRESS: &str = "127.0.0.1:8001";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keycloak_mcp_server=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    println!("Starting Keycloak MCP Server on {}", BIND_ADDRESS);

    // Load configuration from environment
    let config = Config::from_env();
    
    // Create the streamable HTTP service with the Keycloak MCP server
    let service = StreamableHttpService::new(
        move || {
            let config = config.clone();
            async move { KeycloakMcpServer::new(&config).await }
        },
        LocalSessionManager::default().into(),
        Default::default(),
    );

    // Create axum router with the MCP service
    let router = axum::Router::new().nest_service("/mcp", service);
    
    // Start the HTTP server
    let tcp_listener = tokio::net::TcpListener::bind(BIND_ADDRESS).await?;
    
    println!("Keycloak MCP Server running on http://{}/mcp", BIND_ADDRESS);
    println!("Available tools:");
    println!("  - list_users: List users in a realm");
    println!("  - create_user: Create a new user");
    println!("  - get_user: Get user details");
    println!("  - list_realms: List all realms");
    println!("  - create_realm: Create a new realm");
    println!("  - list_clients: List clients in a realm");
    println!("  - create_client: Create a new client");
    println!("  - list_groups: List groups in a realm");
    println!("  - create_group: Create a new group");
    println!("  - list_roles: List roles in a realm");
    println!("  - create_role: Create a new role");
    println!("  - reset_password: Reset user password");
    
    axum::serve(tcp_listener, router)
        .with_graceful_shutdown(async { 
            tokio::signal::ctrl_c().await.unwrap();
            println!("\nShutting down Keycloak MCP Server...");
        })
        .await?;

    Ok(())
}