use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::application::ports::auth::*;
use crate::domain::errors::*;

/// Raw token response from Keycloak
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawTokenResponse {
    access_token: String,
    expires_in: i64,
    #[serde(rename = "not-before-policy")]
    not_before_policy: Option<i64>,
    refresh_expires_in: Option<i64>,
    refresh_token: Option<String>,
    scope: String,
    session_state: Option<String>,
    token_type: String,
}

/// Keycloak token manager implementation
pub struct KeycloakTokenManager {
    keycloak_url: String,
    client: reqwest::Client,
}

impl KeycloakTokenManager {
    pub fn new(keycloak_url: String) -> Self {
        Self {
            keycloak_url,
            client: reqwest::Client::new(),
        }
    }

    pub fn new_with_client(keycloak_url: String, client: reqwest::Client) -> Self {
        Self {
            keycloak_url,
            client,
        }
    }

    /// Convert raw token response to our domain AuthToken
    fn convert_raw_token(&self, raw_token: RawTokenResponse) -> AuthToken {
        AuthToken::new(
            raw_token.access_token,
            raw_token.expires_in,
            raw_token.refresh_token,
            Some(raw_token.token_type),
        )
    }
}

#[async_trait]
impl TokenManager for KeycloakTokenManager {
    async fn acquire_token(&self, credentials: &AdminCredentials) -> Result<AuthToken, AuthError> {
        let token_url = format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.keycloak_url, credentials.realm
        );

        let form_data = match credentials.grant_type.as_str() {
            "client_credentials" => {
                vec![
                    ("client_id", credentials.client_id.as_str()),
                    ("client_secret", credentials.password.as_str()),
                    ("grant_type", "client_credentials"),
                ]
            }
            "password" => {
                vec![
                    ("client_id", credentials.client_id.as_str()),
                    ("username", credentials.username.as_str()),
                    ("password", credentials.password.as_str()),
                    ("grant_type", "password"),
                ]
            }
            _ => {
                return Err(AuthError::TokenAcquisitionFailed {
                    reason: format!("Unsupported grant type: {}", credentials.grant_type),
                });
            }
        };

        let response = self
            .client
            .post(&token_url)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| AuthError::TokenAcquisitionFailed {
                reason: format!("HTTP request failed: {}", e),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::TokenAcquisitionFailed {
                reason: format!("HTTP error {}: {}", status, error_text),
            });
        }

        let raw_token: RawTokenResponse = response
            .json()
            .await
            .map_err(|e| AuthError::TokenAcquisitionFailed {
                reason: format!("Failed to parse token response: {}", e),
            })?;

        Ok(self.convert_raw_token(raw_token))
    }

    async fn refresh_token(&self, token: &AuthToken) -> Result<AuthToken, AuthError> {
        let refresh_token = token.refresh_token.as_ref().ok_or_else(|| {
            AuthError::TokenRefreshFailed {
                reason: "No refresh token available".to_string(),
            }
        })?;

        // Use the refresh token to get a new access token - assume master realm for now
        let response = self
            .client
            .post(format!("{}/realms/master/protocol/openid-connect/token", self.keycloak_url))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await
            .map_err(|e| AuthError::TokenRefreshFailed {
                reason: format!("HTTP request failed: {}", e),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::TokenRefreshFailed {
                reason: format!("HTTP error {}: {}", status, error_text),
            });
        }

        let raw_token: RawTokenResponse = response
            .json()
            .await
            .map_err(|e| AuthError::TokenRefreshFailed {
                reason: format!("Failed to parse response: {}", e),
            })?;

        Ok(self.convert_raw_token(raw_token))
    }

    async fn validate_token(&self, token: &AuthToken) -> Result<bool, AuthError> {
        // First check if token is expired locally
        if token.is_expired() {
            return Ok(false);
        }

        // Validate with Keycloak introspection endpoint
        let response = self
            .client
            .post(format!("{}/realms/master/protocol/openid-connect/token/introspect", self.keycloak_url))
            .form(&[
                ("token", &token.access_token),
                ("token_type_hint", &"access_token".to_string()),
            ])
            .send()
            .await
            .map_err(|e| AuthError::TokenValidationFailed {
                reason: format!("HTTP request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(AuthError::TokenValidationFailed {
                reason: format!("HTTP error: {}", response.status()),
            });
        }

        let introspection: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AuthError::TokenValidationFailed {
                reason: format!("Failed to parse response: {}", e),
            })?;

        Ok(introspection
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }

    async fn revoke_token(&self, token: &AuthToken) -> Result<(), AuthError> {
        let response = self
            .client
            .post(format!("{}/realms/master/protocol/openid-connect/logout", self.keycloak_url))
            .form(&[
                ("refresh_token", token.refresh_token.as_deref().unwrap_or(&token.access_token)),
            ])
            .send()
            .await
            .map_err(|e| AuthError::TokenValidationFailed {
                reason: format!("HTTP request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(AuthError::TokenValidationFailed {
                reason: format!("HTTP error: {}", response.status()),
            });
        }

        Ok(())
    }

    async fn introspect_token(&self, token: &str) -> Result<TokenInfo, AuthError> {
        let response = self
            .client
            .post(format!("{}/realms/master/protocol/openid-connect/token/introspect", self.keycloak_url))
            .form(&[
                ("token", token),
                ("token_type_hint", &"access_token".to_string()),
            ])
            .send()
            .await
            .map_err(|e| AuthError::TokenValidationFailed {
                reason: format!("HTTP request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(AuthError::TokenValidationFailed {
                reason: format!("HTTP error: {}", response.status()),
            });
        }

        let introspection: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AuthError::TokenValidationFailed {
                reason: format!("Failed to parse response: {}", e),
            })?;

        Ok(TokenInfo {
            active: introspection
                .get("active")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            scope: introspection
                .get("scope")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            client_id: introspection
                .get("client_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            username: introspection
                .get("username")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            token_type: introspection
                .get("token_type")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            exp: introspection
                .get("exp")
                .and_then(|v| v.as_i64()),
            iat: introspection
                .get("iat")
                .and_then(|v| v.as_i64()),
            sub: introspection
                .get("sub")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            aud: introspection
                .get("aud")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            iss: introspection
                .get("iss")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            jti: introspection
                .get("jti")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        })
    }
}