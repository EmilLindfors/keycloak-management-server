use crate::{error::{AppResult, AppError}, state::AppState};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use keycloak::types::ClientRepresentation;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ClientQuery {
    #[serde(rename = "clientId")]
    client_id: Option<String>,
    #[serde(rename = "viewableOnly")]
    viewable_only: Option<bool>,
    #[serde(rename = "firstResult")]
    first_result: Option<i32>,
    #[serde(rename = "maxResults")]
    max_results: Option<i32>,
    search: Option<bool>,
}

pub async fn list_clients(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Query(query): Query<ClientQuery>,
) -> AppResult<Json<Vec<ClientRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let clients = admin
        .realm_clients_get(
            &realm,
            query.client_id.as_deref(),
            query.first_result,
            query.max_results,
            query.search,
            query.viewable_only,
        )
        .await?;
    Ok(Json(clients))
}

pub async fn create_client(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Json(client): Json<ClientRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    let response = admin.realm_clients_post(&realm, client).await?;
    
    let client_id = response
        .to_id()
        .ok_or_else(|| AppError::InternalError("Failed to get client ID from response".into()))?;
    
    Ok(Json(serde_json::json!({
        "id": client_id,
        "message": "Client created successfully"
    })))
}

pub async fn get_client(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
) -> AppResult<Json<ClientRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let client = admin
        .realm_clients_with_id_get(&realm, &client_id)
        .await?;
    Ok(Json(client))
}

pub async fn update_client(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
    Json(client): Json<ClientRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_clients_with_id_put(&realm, &client_id, client)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Client updated successfully"
    })))
}

pub async fn delete_client(
    State(state): State<AppState>,
    Path((realm, client_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_clients_with_id_delete(&realm, &client_id)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Client deleted successfully"
    })))
}