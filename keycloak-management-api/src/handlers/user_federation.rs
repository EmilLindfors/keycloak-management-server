use crate::{error::AppResult, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use keycloak::types::{FederatedIdentityRepresentation, TypeString};

pub async fn list_user_federated_identities(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<FederatedIdentityRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let identities = admin
        .realm_users_with_user_id_federated_identity_get(&realm, &user_id)
        .await?;
    Ok(Json(identities))
}

pub async fn add_federated_identity(
    State(state): State<AppState>,
    Path((realm, user_id, provider)): Path<(String, String, String)>,
    Json(identity): Json<FederatedIdentityRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_users_with_user_id_federated_identity_with_provider_post(&realm, &user_id, &provider, identity)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Federated identity added successfully"
    })))
}

pub async fn remove_federated_identity(
    State(state): State<AppState>,
    Path((realm, user_id, provider)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_users_with_user_id_federated_identity_with_provider_delete(&realm, &user_id, &provider)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Federated identity removed successfully"
    })))
}