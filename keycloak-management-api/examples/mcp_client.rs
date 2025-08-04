use rmcp::{
    model::CallToolRequestParam,
    service::ServiceExt,
    transport::streamable_http_client::StreamableHttpClientTransport,
};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the Keycloak MCP server
    let transport = StreamableHttpClientTransport::new("http://127.0.0.1:8001/mcp").await?;
    let service = ().serve(transport).await?;

    println!("Connected to Keycloak MCP Server");

    // Get server information
    let server_info = service.peer_info();
    println!("Server info: {:#?}", server_info);

    // List available tools
    let tools = service.list_tools(Default::default()).await?;
    println!("Available tools: {:#?}", tools);

    // Example: List all realms
    println!("\n--- Listing all realms ---");
    let result = service
        .call_tool(CallToolRequestParam {
            name: "list_realms".into(),
            arguments: Some(json!({})),
        })
        .await?;
    println!("List realms result: {:#?}", result);

    // Example: List users in master realm
    println!("\n--- Listing users in master realm ---");
    let result = service
        .call_tool(CallToolRequestParam {
            name: "list_users".into(),
            arguments: Some(json!({
                "realm": "master",
                "first": 0,
                "max": 10
            })),
        })
        .await?;
    println!("List users result: {:#?}", result);

    // Gracefully close the connection
    service.cancel().await?;
    
    Ok(())
}