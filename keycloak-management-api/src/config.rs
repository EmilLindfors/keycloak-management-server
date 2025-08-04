use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub keycloak_url: String,
    pub keycloak_username: String,
    pub keycloak_password: String,
    pub keycloak_realm: String,
    pub keycloak_client_id: String,
    pub port: u16,
    pub api_key: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            keycloak_url: env::var("KEYCLOAK_URL")
                .unwrap_or_else(|_| "http://localhost:8080".into()),
            keycloak_username: env::var("KEYCLOAK_USERNAME")
                .unwrap_or_else(|_| "admin".into()),
            keycloak_password: env::var("KEYCLOAK_PASSWORD")
                .expect("KEYCLOAK_PASSWORD must be set"),
            keycloak_realm: env::var("KEYCLOAK_REALM").unwrap_or_else(|_| "master".into()),
            keycloak_client_id: env::var("KEYCLOAK_CLIENT_ID")
                .unwrap_or_else(|_| "admin-cli".into()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "3000".into())
                .parse()
                .expect("Invalid PORT"),
            api_key: env::var("API_KEY").ok(),
        }
    }
}