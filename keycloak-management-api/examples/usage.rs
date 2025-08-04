use reqwest::Client;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let api_url = "http://localhost:3000";
    let api_key = std::env::var("API_KEY").ok();

    // Build request with optional API key
    let mut request = client.get(format!("{}/health", api_url));
    if let Some(key) = &api_key {
        request = request.header("x-api-key", key);
    }

    // Health check
    let response = request.send().await?;
    println!("Health check: {}", response.text().await?);

    // Create a test realm
    let mut request = client.post(format!("{}/api/realms", api_url))
        .json(&json!({
            "realm": "test-realm",
            "enabled": true
        }));
    if let Some(key) = &api_key {
        request = request.header("x-api-key", key);
    }

    let response = request.send().await?;
    if response.status().is_success() {
        println!("Realm created: {}", response.text().await?);
    } else {
        println!("Failed to create realm: {}", response.text().await?);
    }

    // Create a user in the test realm
    let mut request = client.post(format!("{}/api/realms/test-realm/users", api_url))
        .json(&json!({
            "username": "testuser",
            "email": "test@example.com",
            "enabled": true,
            "firstName": "Test",
            "lastName": "User",
            "emailVerified": true
        }));
    if let Some(key) = &api_key {
        request = request.header("x-api-key", key);
    }

    let response = request.send().await?;
    if response.status().is_success() {
        println!("User created: {}", response.text().await?);
    } else {
        println!("Failed to create user: {}", response.text().await?);
    }

    // List users
    let mut request = client.get(format!("{}/api/realms/test-realm/users", api_url));
    if let Some(key) = &api_key {
        request = request.header("x-api-key", key);
    }

    let response = request.send().await?;
    if response.status().is_success() {
        let users: Vec<serde_json::Value> = response.json().await?;
        println!("Found {} users", users.len());
        for user in users {
            println!("  - {} ({})", 
                user["username"].as_str().unwrap_or(""),
                user["email"].as_str().unwrap_or("")
            );
        }
    }

    Ok(())
}