use crate::{error::AppResult, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use keycloak::types::RealmRepresentation;

pub async fn list_realms(State(state): State<AppState>) -> AppResult<Json<Vec<RealmRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let realms = admin.get().await?;
    Ok(Json(realms))
}

pub async fn create_realm(
    State(state): State<AppState>,
    Json(realm): Json<RealmRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.post(realm).await?;
    Ok(Json(serde_json::json!({
        "message": "Realm created successfully"
    })))
}

pub async fn get_realm(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> AppResult<Json<RealmRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let realm_data = admin.realm_get(&realm).await?;
    Ok(Json(realm_data))
}

pub async fn update_realm(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Json(realm_data): Json<RealmRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_put(&realm, realm_data).await?;
    Ok(Json(serde_json::json!({
        "message": "Realm updated successfully"
    })))
}

pub async fn delete_realm(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_delete(&realm).await?;
    Ok(Json(serde_json::json!({
        "message": "Realm deleted successfully"
    })))
}