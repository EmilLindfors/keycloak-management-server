use crate::{error::{AppResult, AppError}, state::AppState};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use keycloak::types::GroupRepresentation;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct GroupQuery {
    brief: Option<bool>,
    exact: Option<bool>,
    first: Option<i32>,
    max: Option<i32>,
    search: Option<String>,
    q: Option<String>,
}

pub async fn list_groups(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Query(query): Query<GroupQuery>,
) -> AppResult<Json<Vec<GroupRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let groups = admin
        .realm_groups_get(
            &realm,
            query.brief,
            query.exact,
            query.first,
            query.max,
            None, // populateHierarchy
            query.q.as_deref(),
            query.search.as_deref(),
        )
        .await?;
    Ok(Json(groups))
}

pub async fn create_group(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Json(group): Json<GroupRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    let response = admin.realm_groups_post(&realm, group).await?;
    
    let group_id = response
        .to_id()
        .ok_or_else(|| AppError::InternalError("Failed to get group ID from response".into()))?;
    
    Ok(Json(serde_json::json!({
        "id": group_id,
        "message": "Group created successfully"
    })))
}

pub async fn get_group(
    State(state): State<AppState>,
    Path((realm, group_id)): Path<(String, String)>,
) -> AppResult<Json<GroupRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let group = admin
        .realm_groups_with_group_id_get(&realm, &group_id)
        .await?;
    Ok(Json(group))
}

pub async fn update_group(
    State(state): State<AppState>,
    Path((realm, group_id)): Path<(String, String)>,
    Json(group): Json<GroupRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_groups_with_group_id_put(&realm, &group_id, group)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Group updated successfully"
    })))
}

pub async fn delete_group(
    State(state): State<AppState>,
    Path((realm, group_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_groups_with_group_id_delete(&realm, &group_id)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Group deleted successfully"
    })))
}