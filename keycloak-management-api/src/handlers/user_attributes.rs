use crate::{error::{AppResult, AppError}, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use keycloak::types::{UserRepresentation, TypeMap, TypeVec, TypeString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize)]
pub struct UserAttributes {
    pub attributes: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
pub struct UserGroups {
    pub groups: Vec<String>,
}

#[derive(Deserialize)]
pub struct UserRequiredActions {
    pub actions: Vec<String>,
}

pub async fn get_user_attributes(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
) -> AppResult<Json<UserAttributes>> {
    let admin = state.keycloak_admin.read().await;
    let user = admin.realm_users_with_user_id_get(&realm, &user_id).await?;
    
    let attributes = user.attributes
        .map(|attrs| {
            attrs.iter()
                .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect()
        })
        .unwrap_or_default();
    
    Ok(Json(UserAttributes { attributes }))
}

pub async fn update_user_attributes(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
    Json(attrs): Json<UserAttributes>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    
    // Get current user
    let mut user = admin.realm_users_with_user_id_get(&realm, &user_id).await?;
    
    // Convert attributes to TypeMap
    let type_attrs: TypeMap<String, TypeVec<String>> = attrs.attributes
        .into_iter()
        .map(|(k, v)| {
            let type_vec: TypeVec<String> = v.into_iter()
                .map(|s| TypeString::from(s))
                .collect::<Vec<_>>()
                .into();
            (k, type_vec)
        })
        .collect::<HashMap<_, _>>()
        .into();
    
    user.attributes = Some(type_attrs);
    
    // Update user
    admin.realm_users_with_user_id_put(&realm, &user_id, user).await?;
    
    Ok(Json(serde_json::json!({
        "message": "User attributes updated successfully"
    })))
}

pub async fn add_user_to_groups(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
    Json(groups): Json<UserGroups>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    
    for group_id in groups.groups {
        admin.realm_users_with_user_id_groups_with_group_id_put(&realm, &user_id, &group_id).await?;
    }
    
    Ok(Json(serde_json::json!({
        "message": "User added to groups successfully"
    })))
}

pub async fn remove_user_from_group(
    State(state): State<AppState>,
    Path((realm, user_id, group_id)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_users_with_user_id_groups_with_group_id_delete(&realm, &user_id, &group_id).await?;
    
    Ok(Json(serde_json::json!({
        "message": "User removed from group successfully"
    })))
}

pub async fn get_user_groups(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<keycloak::types::GroupRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let groups = admin.realm_users_with_user_id_groups_get(&realm, &user_id, None, None, None, None).await?;
    Ok(Json(groups))
}

pub async fn update_user_required_actions(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
    Json(actions): Json<UserRequiredActions>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    
    // Get current user
    let mut user = admin.realm_users_with_user_id_get(&realm, &user_id).await?;
    
    // Update required actions
    user.required_actions = Some(actions.actions.into_iter().map(TypeString::from).collect::<Vec<_>>().into());
    
    // Update user
    admin.realm_users_with_user_id_put(&realm, &user_id, user).await?;
    
    Ok(Json(serde_json::json!({
        "message": "User required actions updated successfully"
    })))
}