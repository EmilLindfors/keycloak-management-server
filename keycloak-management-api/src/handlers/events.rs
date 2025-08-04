use crate::{error::AppResult, state::AppState};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use keycloak::types::{EventRepresentation, RealmEventsConfigRepresentation, TypeString};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct EventQuery {
    client: Option<String>,
    #[serde(rename = "dateFrom")]
    date_from: Option<String>,
    #[serde(rename = "dateTo")]
    date_to: Option<String>,
    first: Option<i32>,
    #[serde(rename = "ipAddress")]
    ip_address: Option<String>,
    max: Option<i32>,
    #[serde(rename = "type")]
    type_: Option<String>,
    user: Option<String>,
}

pub async fn list_events(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Query(query): Query<EventQuery>,
) -> AppResult<Json<Vec<EventRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    
    let type_vec = query.type_.map(|t| vec![TypeString::from(t)]);
    
    let events = admin
        .realm_events_get(
            &realm,
            query.client.as_deref(),
            query.date_from.as_deref(),
            query.date_to.as_deref(),
            query.first,
            query.ip_address.as_deref(),
            query.max,
            type_vec.as_deref(),
            query.user.as_deref(),
        )
        .await?;
    Ok(Json(events))
}

pub async fn clear_events(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_events_delete(&realm).await?;
    Ok(Json(serde_json::json!({
        "message": "Events cleared successfully"
    })))
}

pub async fn get_events_config(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> AppResult<Json<RealmEventsConfigRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let config = admin.realm_events_config_get(&realm).await?;
    Ok(Json(config))
}

pub async fn update_events_config(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Json(config): Json<RealmEventsConfigRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_events_config_put(&realm, config).await?;
    Ok(Json(serde_json::json!({
        "message": "Events configuration updated successfully"
    })))
}