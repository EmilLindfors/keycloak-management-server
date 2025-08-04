use crate::{error::{AppResult, AppError}, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use keycloak::types::{CredentialRepresentation, ProtocolMapperRepresentation, ClientScopeRepresentation};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ClientSecretRotation {
    pub rotate: bool,
}

// Client Secret Management
pub async fn get_client_secret(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
) -> AppResult<Json<CredentialRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let secret = admin.realm_clients_with_client_uuid_client_secret_get(&realm, &client_id).await?;
    Ok(Json(secret))
}

pub async fn regenerate_client_secret(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
) -> AppResult<Json<CredentialRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let new_secret = admin.realm_clients_with_client_uuid_client_secret_post(&realm, &client_id).await?;
    Ok(Json(new_secret))
}

pub async fn get_client_secret_rotated(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
) -> AppResult<Json<CredentialRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let secret = admin.realm_clients_with_client_uuid_client_secret_rotated_get(&realm, &client_id).await?;
    Ok(Json(secret))
}

pub async fn delete_client_secret_rotated(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_clients_with_client_uuid_client_secret_rotated_delete(&realm, &client_id).await?;
    Ok(Json(serde_json::json!({
        "message": "Rotated client secret deleted successfully"
    })))
}

// Client Scope Management
pub async fn get_client_default_scopes(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<ClientScopeRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let scopes = admin.realm_clients_with_client_uuid_default_client_scopes_get(&realm, &client_id).await?;
    Ok(Json(scopes))
}

pub async fn add_client_default_scope(
    State(state): State<AppState>,
    Path((realm, client_id, scope_id)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_clients_with_client_uuid_default_client_scopes_with_client_scope_id_put(&realm, &client_id, &scope_id).await?;
    Ok(Json(serde_json::json!({
        "message": "Default client scope added successfully"
    })))
}

pub async fn remove_client_default_scope(
    State(state): State<AppState>,
    Path((realm, client_id, scope_id)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_clients_with_client_uuid_default_client_scopes_with_client_scope_id_delete(&realm, &client_id, &scope_id).await?;
    Ok(Json(serde_json::json!({
        "message": "Default client scope removed successfully"
    })))
}

pub async fn get_client_optional_scopes(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<ClientScopeRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let scopes = admin.realm_clients_with_client_uuid_optional_client_scopes_get(&realm, &client_id).await?;
    Ok(Json(scopes))
}

pub async fn add_client_optional_scope(
    State(state): State<AppState>,
    Path((realm, client_id, scope_id)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_clients_with_client_uuid_optional_client_scopes_with_client_scope_id_put(&realm, &client_id, &scope_id).await?;
    Ok(Json(serde_json::json!({
        "message": "Optional client scope added successfully"
    })))
}

pub async fn remove_client_optional_scope(
    State(state): State<AppState>,
    Path((realm, client_id, scope_id)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_clients_with_client_uuid_optional_client_scopes_with_client_scope_id_delete(&realm, &client_id, &scope_id).await?;
    Ok(Json(serde_json::json!({
        "message": "Optional client scope removed successfully"
    })))
}

// Protocol Mappers
pub async fn get_client_protocol_mappers(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<ProtocolMapperRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let mappers = admin.realm_clients_with_client_uuid_protocol_mappers_models_get(&realm, &client_id).await?;
    Ok(Json(mappers))
}

pub async fn create_client_protocol_mapper(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
    Json(mapper): Json<ProtocolMapperRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    let response = admin.realm_clients_with_client_uuid_protocol_mappers_models_post(&realm, &client_id, mapper).await?;
    
    let mapper_id = response
        .to_id()
        .ok_or_else(|| AppError::InternalError("Failed to get mapper ID from response".into()))?;
    
    Ok(Json(serde_json::json!({
        "id": mapper_id,
        "message": "Protocol mapper created successfully"
    })))
}

pub async fn get_client_protocol_mapper(
    State(state): State<AppState>,
    Path((realm, client_id, mapper_id)): Path<(String, String, String)>,
) -> AppResult<Json<ProtocolMapperRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let mapper = admin.realm_clients_with_client_uuid_protocol_mappers_models_with_id_get(&realm, &client_id, &mapper_id).await?;
    Ok(Json(mapper))
}

pub async fn update_client_protocol_mapper(
    State(state): State<AppState>,
    Path((realm, client_id, mapper_id)): Path<(String, String, String)>,
    Json(mapper): Json<ProtocolMapperRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_clients_with_client_uuid_protocol_mappers_models_with_id_put(&realm, &client_id, &mapper_id, mapper).await?;
    Ok(Json(serde_json::json!({
        "message": "Protocol mapper updated successfully"
    })))
}

pub async fn delete_client_protocol_mapper(
    State(state): State<AppState>,
    Path((realm, client_id, mapper_id)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_clients_with_client_uuid_protocol_mappers_models_with_id_delete(&realm, &client_id, &mapper_id).await?;
    Ok(Json(serde_json::json!({
        "message": "Protocol mapper deleted successfully"
    })))
}