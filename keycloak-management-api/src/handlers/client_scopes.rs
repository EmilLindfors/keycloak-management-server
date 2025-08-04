use crate::{error::{AppResult, AppError}, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use keycloak::types::ClientScopeRepresentation;

pub async fn list_client_scopes(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> AppResult<Json<Vec<ClientScopeRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let scopes = admin.realm_client_scopes_get(&realm).await?;
    Ok(Json(scopes))
}

pub async fn create_client_scope(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Json(scope): Json<ClientScopeRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    let response = admin.realm_client_scopes_post(&realm, scope).await?;
    
    let scope_id = response
        .to_id()
        .ok_or_else(|| AppError::InternalError("Failed to get client scope ID from response".into()))?;
    
    Ok(Json(serde_json::json!({
        "id": scope_id,
        "message": "Client scope created successfully"
    })))
}

pub async fn get_client_scope(
    State(state): State<AppState>,
    Path((realm, scope_id)): Path<(String, String)>,
) -> AppResult<Json<ClientScopeRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let scope = admin
        .realm_client_scopes_with_client_scope_id_get(&realm, &scope_id)
        .await?;
    Ok(Json(scope))
}

pub async fn update_client_scope(
    State(state): State<AppState>,
    Path((realm, scope_id)): Path<(String, String)>,
    Json(scope): Json<ClientScopeRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_client_scopes_with_client_scope_id_put(&realm, &scope_id, scope)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Client scope updated successfully"
    })))
}

pub async fn delete_client_scope(
    State(state): State<AppState>,
    Path((realm, scope_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_client_scopes_with_client_scope_id_delete(&realm, &scope_id)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Client scope deleted successfully"
    })))
}