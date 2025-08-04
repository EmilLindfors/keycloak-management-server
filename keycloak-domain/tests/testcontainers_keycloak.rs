use std::sync::Arc;
use once_cell::sync::Lazy;
use testcontainers::{
    core::IntoContainerPort,
    runners::AsyncRunner,
    GenericImage,
    ImageExt,
    ContainerAsync,
};
use tokio::sync::Mutex;

/// Shared Keycloak container for integration tests
/// Using Lazy + Arc + Mutex to ensure single container across all tests
static KEYCLOAK_CONTAINER: Lazy<Arc<Mutex<Option<Arc<KeycloakTestContainer>>>>> = 
    Lazy::new(|| Arc::new(Mutex::new(None)));

/// Container wrapper with connection details
pub struct KeycloakTestContainer {
    _container: ContainerAsync<GenericImage>,
    pub host: String,
    pub port: u16,
    pub base_url: String,
    pub admin_username: String,
    pub admin_password: String,
}

impl KeycloakTestContainer {
    /// Get admin console URL
    pub fn admin_console_url(&self) -> String {
        format!("{}/admin", self.base_url)
    }

    /// Get realm URL
    pub fn realm_url(&self, realm: &str) -> String {
        format!("{}/realms/{}", self.base_url, realm)
    }

    /// Get token endpoint URL
    pub fn token_endpoint_url(&self, realm: &str) -> String {
        format!("{}/realms/{}/protocol/openid-connect/token", self.base_url, realm)
    }

    /// Get admin token for Keycloak API access
    pub async fn get_admin_token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();
        
        let response = client
            .post(&self.token_endpoint_url("master"))
            .form(&[
                ("username", &self.admin_username),
                ("password", &self.admin_password),
                ("grant_type", &"password".to_string()),
                ("client_id", &"admin-cli".to_string()),
            ])
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to get admin token: {}", response.status()).into());
        }

        let token_response: serde_json::Value = response.json().await?;
        
        token_response
            .get("access_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "No access_token in response".into())
    }

    /// Create a test realm
    pub async fn create_test_realm(&self, realm_name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let token = self.get_admin_token().await?;
        let client = reqwest::Client::new();
        
        let realm_config = serde_json::json!({
            "realm": realm_name,
            "enabled": true,
            "displayName": format!("Test Realm: {}", realm_name),
            "registrationAllowed": true,
            "loginWithEmailAllowed": true,
            "duplicateEmailsAllowed": false
        });

        let response = client
            .post(&format!("{}/admin/realms", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&realm_config)
            .send()
            .await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::CONFLICT {
            Ok(())
        } else {
            Err(format!("Failed to create realm: {}", response.status()).into())
        }
    }

    /// Create a test client in a realm
    pub async fn create_test_client(&self, realm_name: &str, client_id: &str, is_public: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let token = self.get_admin_token().await?;
        let client = reqwest::Client::new();
        
        let client_config = serde_json::json!({
            "clientId": client_id,
            "enabled": true,
            "publicClient": is_public,
            "standardFlowEnabled": true,
            "directAccessGrantsEnabled": true,
            "serviceAccountsEnabled": !is_public,
            "redirectUris": ["http://localhost:*"],
            "webOrigins": ["*"]
        });

        let response = client
            .post(&format!("{}/admin/realms/{}/clients", self.base_url, realm_name))
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&client_config)
            .send()
            .await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::CONFLICT {
            Ok(())
        } else {
            Err(format!("Failed to create client: {}", response.status()).into())
        }
    }

    /// Create a test user in a realm
    pub async fn create_test_user(&self, realm_name: &str, username: &str, password: &str, email: Option<&str>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let token = self.get_admin_token().await?;
        let client = reqwest::Client::new();
        
        let mut user_config = serde_json::json!({
            "username": username,
            "enabled": true,
            "credentials": [{
                "type": "password",
                "value": password,
                "temporary": false
            }]
        });

        if let Some(email) = email {
            user_config["email"] = serde_json::Value::String(email.to_string());
            user_config["emailVerified"] = serde_json::Value::Bool(true);
        }

        let response = client
            .post(&format!("{}/admin/realms/{}/users", self.base_url, realm_name))
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&user_config)
            .send()
            .await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::CONFLICT {
            Ok(())
        } else {
            Err(format!("Failed to create user: {}", response.status()).into())
        }
    }
}

/// Get or create the shared Keycloak container
pub async fn get_keycloak_container() -> Arc<KeycloakTestContainer> {
    let mut container_guard = KEYCLOAK_CONTAINER.lock().await;
    
    if container_guard.is_none() {
        println!("Starting Keycloak container (this may take ~10 seconds)...");
        
        let container = GenericImage::new("quay.io/keycloak/keycloak", "25.0")
            .with_exposed_port(8080.tcp())
            .with_env_var("KEYCLOAK_ADMIN", "admin")
            .with_env_var("KEYCLOAK_ADMIN_PASSWORD", "admin")
            .with_env_var("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .with_env_var("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            // Reduce memory usage for testing
            .with_env_var("JAVA_OPTS_KC_HEAP", "-XX:InitialRAMPercentage=1 -XX:MaxRAMPercentage=5")
            .with_cmd(vec!["start-dev", "--http-relative-path=/"])
            .start()
            .await
            .expect("Failed to start Keycloak container");
            
        // Wait for Keycloak to be ready manually instead of using with_wait_for
        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
        
        let host_port = container.get_host_port_ipv4(8080).await.unwrap();
        let host = "localhost".to_string();
        let base_url = format!("http://{}:{}", host, host_port);
        
        println!("Keycloak started at: {}", base_url);
        
        let keycloak_container = KeycloakTestContainer {
            _container: container,
            host: host.clone(),
            port: host_port,
            base_url,
            admin_username: "admin".to_string(),
            admin_password: "admin".to_string(),
        };
        
        // Wait a bit more for Keycloak to be fully ready
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        
        *container_guard = Some(Arc::new(keycloak_container));
    }
    
    container_guard.as_ref().unwrap().clone()
}

/// Get or create Keycloak container with a pre-configured test realm
pub async fn get_keycloak_with_test_realm(realm_name: &str) -> Arc<KeycloakTestContainer> {
    let container = get_keycloak_container().await;
    
    // Create test realm if it doesn't exist
    if let Err(e) = container.create_test_realm(realm_name).await {
        println!("Warning: Could not create test realm {}: {}", realm_name, e);
    }
    
    container
}

/// Utility function to wait for Keycloak health check
pub async fn wait_for_keycloak_health(base_url: &str, max_attempts: u32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    
    for attempt in 1..=max_attempts {
        match client.get(&format!("{}/health", base_url)).send().await {
            Ok(response) if response.status().is_success() => {
                println!("Keycloak health check passed on attempt {}", attempt);
                return Ok(());
            }
            Ok(response) => {
                println!("Keycloak health check failed with status: {} (attempt {})", response.status(), attempt);
            }
            Err(e) => {
                println!("Keycloak health check error: {} (attempt {})", e, attempt);
            }
        }
        
        if attempt < max_attempts {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    }
    
    Err(format!("Keycloak not ready after {} attempts", max_attempts).into())
}

// Note: KeycloakTestContainer doesn't implement Clone because ContainerAsync doesn't implement Clone
// We work around this by using Arc<Mutex<Option<KeycloakTestContainer>>> for sharing