use crate::{error::AppResult, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use keycloak::types::UserSessionRepresentation;

pub async fn logout_all_sessions(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_logout_all_post(&realm).await?;
    Ok(Json(serde_json::json!({
        "message": "All sessions logged out successfully"
    })))
}

pub async fn delete_session(
    State(state): State<AppState>,
    Path((realm, session_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_sessions_with_session_delete(&realm, &session_id).await?;
    Ok(Json(serde_json::json!({
        "message": "Session deleted successfully"
    })))
}

pub async fn get_user_sessions(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<UserSessionRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let sessions = admin
        .realm_users_with_user_id_offline_sessions_with_client_uuid_get(&realm, &user_id, "-")
        .await?;
    Ok(Json(sessions))
}

pub async fn logout_user(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_users_with_user_id_logout_post(&realm, &user_id).await?;
    Ok(Json(serde_json::json!({
        "message": "User logged out successfully"
    })))
}