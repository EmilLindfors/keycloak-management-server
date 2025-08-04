use crate::{error::{AppResult, AppError}, state::AppState};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use keycloak::types::RoleRepresentation;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct RoleQuery {
    #[serde(rename = "briefRepresentation")]
    brief_representation: Option<bool>,
    first: Option<i32>,
    max: Option<i32>,
    search: Option<String>,
}

pub async fn list_roles(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Query(query): Query<RoleQuery>,
) -> AppResult<Json<Vec<RoleRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let roles = admin
        .realm_roles_get(
            &realm,
            query.brief_representation,
            query.first,
            query.max,
            query.search.as_deref(),
        )
        .await?;
    Ok(Json(roles))
}

pub async fn create_role(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Json(role): Json<RoleRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_roles_post(&realm, role).await?;
    Ok(Json(serde_json::json!({
        "message": "Role created successfully"
    })))
}

pub async fn get_role(
    State(state): State<AppState>,
    Path((realm, role_name)): Path<(String, String)>,
) -> AppResult<Json<RoleRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let role = admin
        .realm_roles_with_role_name_get(&realm, &role_name)
        .await?;
    Ok(Json(role))
}

pub async fn update_role(
    State(state): State<AppState>,
    Path((realm, role_name)): Path<(String, String)>,
    Json(role): Json<RoleRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_roles_with_role_name_put(&realm, &role_name, role)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Role updated successfully"
    })))
}

pub async fn delete_role(
    State(state): State<AppState>,
    Path((realm, role_name)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_roles_with_role_name_delete(&realm, &role_name)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Role deleted successfully"
    })))
}