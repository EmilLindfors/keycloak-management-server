use crate::{error::{AppResult, AppError}, state::AppState};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use keycloak::types::RoleRepresentation;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ClientRoleQuery {
    #[serde(rename = "briefRepresentation")]
    brief_representation: Option<bool>,
    first: Option<i32>,
    max: Option<i32>,
    search: Option<String>,
}

// Client-specific roles
pub async fn list_client_roles(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
    Query(query): Query<ClientRoleQuery>,
) -> AppResult<Json<Vec<RoleRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let roles = admin
        .realm_clients_with_client_uuid_roles_get(
            &realm,
            &client_id,
            query.brief_representation,
            query.first,
            query.max,
            query.search.as_deref(),
        )
        .await?;
    Ok(Json(roles))
}

pub async fn create_client_role(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
    Json(role): Json<RoleRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_clients_with_client_uuid_roles_post(&realm, &client_id, role).await?;
    Ok(Json(serde_json::json!({
        "message": "Client role created successfully"
    })))
}

pub async fn get_client_role(
    State(state): State<AppState>,
    Path((realm, client_id, role_name)): Path<(String, String, String)>,
) -> AppResult<Json<RoleRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let role = admin
        .realm_clients_with_client_uuid_roles_with_role_name_get(&realm, &client_id, &role_name)
        .await?;
    Ok(Json(role))
}

pub async fn update_client_role(
    State(state): State<AppState>,
    Path((realm, client_id, role_name)): Path<(String, String, String)>,
    Json(role): Json<RoleRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_clients_with_client_uuid_roles_with_role_name_put(&realm, &client_id, &role_name, role)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Client role updated successfully"
    })))
}

pub async fn delete_client_role(
    State(state): State<AppState>,
    Path((realm, client_id, role_name)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_clients_with_client_uuid_roles_with_role_name_delete(&realm, &client_id, &role_name)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Client role deleted successfully"
    })))
}

pub async fn get_client_role_composites(
    State(state): State<AppState>,
    Path((realm, client_id, role_name)): Path<(String, String, String)>,
) -> AppResult<Json<Vec<RoleRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let roles = admin
        .realm_clients_with_client_uuid_roles_with_role_name_composites_get(&realm, &client_id, &role_name)
        .await?;
    Ok(Json(roles))
}

pub async fn add_client_role_composites(
    State(state): State<AppState>,
    Path((realm, client_id, role_name)): Path<(String, String, String)>,
    Json(roles): Json<Vec<RoleRepresentation>>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_clients_with_client_uuid_roles_with_role_name_composites_post(&realm, &client_id, &role_name, roles)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Composite roles added successfully"
    })))
}