use crate::{error::AppResult, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use keycloak::types::{RoleRepresentation, MappingsRepresentation};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct RoleList {
    pub roles: Vec<RoleRepresentation>,
}

// User Role Mappings
pub async fn get_user_role_mappings(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
) -> AppResult<Json<MappingsRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let mappings = admin.realm_users_with_user_id_role_mappings_get(&realm, &user_id).await?;
    Ok(Json(mappings))
}

pub async fn get_user_realm_role_mappings(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<RoleRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let roles = admin.realm_users_with_user_id_role_mappings_realm_get(&realm, &user_id).await?;
    Ok(Json(roles))
}

pub async fn add_user_realm_role_mappings(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
    Json(roles): Json<RoleList>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_users_with_user_id_role_mappings_realm_post(&realm, &user_id, roles.roles).await?;
    Ok(Json(serde_json::json!({
        "message": "Realm roles mapped to user successfully"
    })))
}

pub async fn remove_user_realm_role_mappings(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
    Json(roles): Json<RoleList>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_users_with_user_id_role_mappings_realm_delete(&realm, &user_id, roles.roles).await?;
    Ok(Json(serde_json::json!({
        "message": "Realm roles unmapped from user successfully"
    })))
}

pub async fn get_available_user_realm_role_mappings(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<RoleRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let roles = admin.realm_users_with_user_id_role_mappings_realm_available_get(&realm, &user_id).await?;
    Ok(Json(roles))
}

// User Client Role Mappings
pub async fn get_user_client_role_mappings(
    State(state): State<AppState>,
    Path((realm, user_id, client_id)): Path<(String, String, String)>,
) -> AppResult<Json<Vec<RoleRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let roles = admin.realm_users_with_user_id_role_mappings_clients_with_client_id_get(&realm, &user_id, &client_id).await?;
    Ok(Json(roles))
}

pub async fn add_user_client_role_mappings(
    State(state): State<AppState>,
    Path((realm, user_id, client_id)): Path<(String, String, String)>,
    Json(roles): Json<RoleList>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_users_with_user_id_role_mappings_clients_with_client_id_post(&realm, &user_id, &client_id, roles.roles).await?;
    Ok(Json(serde_json::json!({
        "message": "Client roles mapped to user successfully"
    })))
}

pub async fn remove_user_client_role_mappings(
    State(state): State<AppState>,
    Path((realm, user_id, client_id)): Path<(String, String, String)>,
    Json(roles): Json<RoleList>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_users_with_user_id_role_mappings_clients_with_client_id_delete(&realm, &user_id, &client_id, roles.roles).await?;
    Ok(Json(serde_json::json!({
        "message": "Client roles unmapped from user successfully"
    })))
}

pub async fn get_available_user_client_role_mappings(
    State(state): State<AppState>,
    Path((realm, user_id, client_id)): Path<(String, String, String)>,
) -> AppResult<Json<Vec<RoleRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let roles = admin.realm_users_with_user_id_role_mappings_clients_with_client_id_available_get(&realm, &user_id, &client_id).await?;
    Ok(Json(roles))
}

// Group Role Mappings
pub async fn get_group_role_mappings(
    State(state): State<AppState>,
    Path((realm, group_id)): Path<(String, String)>,
) -> AppResult<Json<MappingsRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let mappings = admin.realm_groups_with_group_id_role_mappings_get(&realm, &group_id).await?;
    Ok(Json(mappings))
}

pub async fn get_group_client_role_mappings(
    State(state): State<AppState>,
    Path((realm, group_id, client_id)): Path<(String, String, String)>,
) -> AppResult<Json<Vec<RoleRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let roles = admin.realm_groups_with_group_id_role_mappings_clients_with_client_id_get(&realm, &group_id, &client_id).await?;
    Ok(Json(roles))
}

pub async fn add_group_client_role_mappings(
    State(state): State<AppState>,
    Path((realm, group_id, client_id)): Path<(String, String, String)>,
    Json(roles): Json<RoleList>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_groups_with_group_id_role_mappings_clients_with_client_id_post(&realm, &group_id, &client_id, roles.roles).await?;
    Ok(Json(serde_json::json!({
        "message": "Client roles mapped to group successfully"
    })))
}

pub async fn remove_group_client_role_mappings(
    State(state): State<AppState>,
    Path((realm, group_id, client_id)): Path<(String, String, String)>,
    Json(roles): Json<RoleList>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_groups_with_group_id_role_mappings_clients_with_client_id_delete(&realm, &group_id, &client_id, roles.roles).await?;
    Ok(Json(serde_json::json!({
        "message": "Client roles unmapped from group successfully"
    })))
}