use crate::{error::AppResult, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use keycloak::types::{CredentialRepresentation, TypeString};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct PasswordReset {
    pub temporary: bool,
    pub value: String,
}

pub async fn list_user_credentials(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<CredentialRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let credentials = admin
        .realm_users_with_user_id_credentials_get(&realm, &user_id)
        .await?;
    Ok(Json(credentials))
}

pub async fn delete_user_credential(
    State(state): State<AppState>,
    Path((realm, user_id, credential_id)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_users_with_user_id_credentials_with_credential_id_delete(&realm, &user_id, &credential_id)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Credential deleted successfully"
    })))
}

pub async fn reset_user_password(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
    Json(password): Json<PasswordReset>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    
    let credential = CredentialRepresentation {
        temporary: Some(password.temporary),
        type_: Some(TypeString::from("password".to_string())),
        value: Some(TypeString::from(password.value)),
        ..Default::default()
    };
    
    admin
        .realm_users_with_user_id_reset_password_put(&realm, &user_id, credential)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Password reset successfully"
    })))
}

pub async fn send_reset_password_email(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_users_with_user_id_reset_password_email_put(&realm, &user_id, None, None, None)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Password reset email sent successfully"
    })))
}