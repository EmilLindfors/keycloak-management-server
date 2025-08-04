use crate::{error::{AppResult, AppError}, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use keycloak::types::{IdentityProviderRepresentation, TypeString, TypeMap};

pub async fn list_identity_providers(
    State(state): State<AppState>,
    Path(realm): Path<String>,
) -> AppResult<Json<Vec<IdentityProviderRepresentation>>> {
    let admin = state.keycloak_admin.read().await;
    let providers = admin.realm_identity_provider_instances_get(&realm).await?;
    Ok(Json(providers))
}

pub async fn create_identity_provider(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Json(provider): Json<IdentityProviderRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin.realm_identity_provider_instances_post(&realm, provider).await?;
    Ok(Json(serde_json::json!({
        "message": "Identity provider created successfully"
    })))
}

pub async fn get_identity_provider(
    State(state): State<AppState>,
    Path((realm, alias)): Path<(String, String)>,
) -> AppResult<Json<IdentityProviderRepresentation>> {
    let admin = state.keycloak_admin.read().await;
    let provider = admin
        .realm_identity_provider_instances_with_alias_get(&realm, &alias)
        .await?;
    Ok(Json(provider))
}

pub async fn update_identity_provider(
    State(state): State<AppState>,
    Path((realm, alias)): Path<(String, String)>,
    Json(provider): Json<IdentityProviderRepresentation>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_identity_provider_instances_with_alias_put(&realm, &alias, provider)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Identity provider updated successfully"
    })))
}

pub async fn delete_identity_provider(
    State(state): State<AppState>,
    Path((realm, alias)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let admin = state.keycloak_admin.read().await;
    admin
        .realm_identity_provider_instances_with_alias_delete(&realm, &alias)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Identity provider deleted successfully"
    })))
}

#[cfg(feature = "multipart")]
pub async fn import_identity_provider_config(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    body: axum::body::Bytes,
) -> AppResult<Json<TypeMap<String, TypeString>>> {
    let admin = state.keycloak_admin.read().await;
    let config = admin
        .realm_identity_provider_import_config_post_form(
            &realm,
            "saml".to_string(),
            body.to_vec(),
        )
        .await?;
    Ok(Json(config))
}