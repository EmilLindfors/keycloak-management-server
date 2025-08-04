mod config;
mod error;
mod handlers;
mod state;

use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use std::net::SocketAddr;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keycloak_management_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = config::Config::from_env();
    let state = AppState::new(&config).await?;

    let app = Router::new()
        // Health check
        .route("/health", get(handlers::health::health_check))
        // Realm endpoints
        .route("/api/realms", get(handlers::realms::list_realms))
        .route("/api/realms", post(handlers::realms::create_realm))
        .route("/api/realms/:realm", get(handlers::realms::get_realm))
        .route("/api/realms/:realm", put(handlers::realms::update_realm))
        .route("/api/realms/:realm", delete(handlers::realms::delete_realm))
        // User endpoints
        .route("/api/realms/:realm/users", get(handlers::users::list_users))
        .route("/api/realms/:realm/users", post(handlers::users::create_user))
        .route(
            "/api/realms/:realm/users/:user_id",
            get(handlers::users::get_user),
        )
        .route(
            "/api/realms/:realm/users/:user_id",
            put(handlers::users::update_user),
        )
        .route(
            "/api/realms/:realm/users/:user_id",
            delete(handlers::users::delete_user),
        )
        // Client endpoints
        .route(
            "/api/realms/:realm/clients",
            get(handlers::clients::list_clients),
        )
        .route(
            "/api/realms/:realm/clients",
            post(handlers::clients::create_client),
        )
        .route(
            "/api/realms/:realm/clients/:client_id",
            get(handlers::clients::get_client),
        )
        .route(
            "/api/realms/:realm/clients/:client_id",
            put(handlers::clients::update_client),
        )
        .route(
            "/api/realms/:realm/clients/:client_id",
            delete(handlers::clients::delete_client),
        )
        // Group endpoints
        .route(
            "/api/realms/:realm/groups",
            get(handlers::groups::list_groups),
        )
        .route(
            "/api/realms/:realm/groups",
            post(handlers::groups::create_group),
        )
        .route(
            "/api/realms/:realm/groups/:group_id",
            get(handlers::groups::get_group),
        )
        .route(
            "/api/realms/:realm/groups/:group_id",
            put(handlers::groups::update_group),
        )
        .route(
            "/api/realms/:realm/groups/:group_id",
            delete(handlers::groups::delete_group),
        )
        // Role endpoints
        .route("/api/realms/:realm/roles", get(handlers::roles::list_roles))
        .route(
            "/api/realms/:realm/roles",
            post(handlers::roles::create_role),
        )
        .route(
            "/api/realms/:realm/roles/:role_name",
            get(handlers::roles::get_role),
        )
        .route(
            "/api/realms/:realm/roles/:role_name",
            put(handlers::roles::update_role),
        )
        .route(
            "/api/realms/:realm/roles/:role_name",
            delete(handlers::roles::delete_role),
        )
        // Session endpoints
        .route(
            "/api/realms/:realm/logout-all",
            post(handlers::sessions::logout_all_sessions),
        )
        .route(
            "/api/realms/:realm/sessions/:session_id",
            delete(handlers::sessions::delete_session),
        )
        .route(
            "/api/realms/:realm/users/:user_id/sessions",
            get(handlers::sessions::get_user_sessions),
        )
        .route(
            "/api/realms/:realm/users/:user_id/logout",
            post(handlers::sessions::logout_user),
        )
        // Credential endpoints
        .route(
            "/api/realms/:realm/users/:user_id/credentials",
            get(handlers::credentials::list_user_credentials),
        )
        .route(
            "/api/realms/:realm/users/:user_id/credentials/:credential_id",
            delete(handlers::credentials::delete_user_credential),
        )
        .route(
            "/api/realms/:realm/users/:user_id/reset-password",
            put(handlers::credentials::reset_user_password),
        )
        .route(
            "/api/realms/:realm/users/:user_id/reset-password-email",
            put(handlers::credentials::send_reset_password_email),
        )
        // Event endpoints
        .route(
            "/api/realms/:realm/events",
            get(handlers::events::list_events),
        )
        .route(
            "/api/realms/:realm/events",
            delete(handlers::events::clear_events),
        )
        .route(
            "/api/realms/:realm/events/config",
            get(handlers::events::get_events_config),
        )
        .route(
            "/api/realms/:realm/events/config",
            put(handlers::events::update_events_config),
        )
        // Identity Provider endpoints
        .route(
            "/api/realms/:realm/identity-providers",
            get(handlers::identity_providers::list_identity_providers),
        )
        .route(
            "/api/realms/:realm/identity-providers",
            post(handlers::identity_providers::create_identity_provider),
        )
        .route(
            "/api/realms/:realm/identity-providers/:alias",
            get(handlers::identity_providers::get_identity_provider),
        )
        .route(
            "/api/realms/:realm/identity-providers/:alias",
            put(handlers::identity_providers::update_identity_provider),
        )
        .route(
            "/api/realms/:realm/identity-providers/:alias",
            delete(handlers::identity_providers::delete_identity_provider),
        )
        // Client Scope endpoints
        .route(
            "/api/realms/:realm/client-scopes",
            get(handlers::client_scopes::list_client_scopes),
        )
        .route(
            "/api/realms/:realm/client-scopes",
            post(handlers::client_scopes::create_client_scope),
        )
        .route(
            "/api/realms/:realm/client-scopes/:scope_id",
            get(handlers::client_scopes::get_client_scope),
        )
        .route(
            "/api/realms/:realm/client-scopes/:scope_id",
            put(handlers::client_scopes::update_client_scope),
        )
        .route(
            "/api/realms/:realm/client-scopes/:scope_id",
            delete(handlers::client_scopes::delete_client_scope),
        )
        // User Federation endpoints
        .route(
            "/api/realms/:realm/users/:user_id/federated-identity",
            get(handlers::user_federation::list_user_federated_identities),
        )
        .route(
            "/api/realms/:realm/users/:user_id/federated-identity/:provider",
            post(handlers::user_federation::add_federated_identity),
        )
        .route(
            "/api/realms/:realm/users/:user_id/federated-identity/:provider",
            delete(handlers::user_federation::remove_federated_identity),
        )
        // User Attributes and Groups
        .route(
            "/api/realms/:realm/users/:user_id/attributes",
            get(handlers::user_attributes::get_user_attributes),
        )
        .route(
            "/api/realms/:realm/users/:user_id/attributes",
            put(handlers::user_attributes::update_user_attributes),
        )
        .route(
            "/api/realms/:realm/users/:user_id/groups",
            get(handlers::user_attributes::get_user_groups),
        )
        .route(
            "/api/realms/:realm/users/:user_id/groups",
            post(handlers::user_attributes::add_user_to_groups),
        )
        .route(
            "/api/realms/:realm/users/:user_id/groups/:group_id",
            delete(handlers::user_attributes::remove_user_from_group),
        )
        .route(
            "/api/realms/:realm/users/:user_id/required-actions",
            put(handlers::user_attributes::update_user_required_actions),
        )
        // Client Advanced Management
        .route(
            "/api/realms/:realm/clients/:client_id/secret",
            get(handlers::client_advanced::get_client_secret),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/secret",
            post(handlers::client_advanced::regenerate_client_secret),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/secret-rotated",
            get(handlers::client_advanced::get_client_secret_rotated),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/secret-rotated",
            delete(handlers::client_advanced::delete_client_secret_rotated),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/default-scopes",
            get(handlers::client_advanced::get_client_default_scopes),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/default-scopes/:scope_id",
            put(handlers::client_advanced::add_client_default_scope),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/default-scopes/:scope_id",
            delete(handlers::client_advanced::remove_client_default_scope),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/optional-scopes",
            get(handlers::client_advanced::get_client_optional_scopes),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/optional-scopes/:scope_id",
            put(handlers::client_advanced::add_client_optional_scope),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/optional-scopes/:scope_id",
            delete(handlers::client_advanced::remove_client_optional_scope),
        )
        // Client Protocol Mappers
        .route(
            "/api/realms/:realm/clients/:client_id/protocol-mappers",
            get(handlers::client_advanced::get_client_protocol_mappers),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/protocol-mappers",
            post(handlers::client_advanced::create_client_protocol_mapper),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/protocol-mappers/:mapper_id",
            get(handlers::client_advanced::get_client_protocol_mapper),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/protocol-mappers/:mapper_id",
            put(handlers::client_advanced::update_client_protocol_mapper),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/protocol-mappers/:mapper_id",
            delete(handlers::client_advanced::delete_client_protocol_mapper),
        )
        // Client Roles
        .route(
            "/api/realms/:realm/clients/:client_id/roles",
            get(handlers::client_roles::list_client_roles),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/roles",
            post(handlers::client_roles::create_client_role),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/roles/:role_name",
            get(handlers::client_roles::get_client_role),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/roles/:role_name",
            put(handlers::client_roles::update_client_role),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/roles/:role_name",
            delete(handlers::client_roles::delete_client_role),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/roles/:role_name/composites",
            get(handlers::client_roles::get_client_role_composites),
        )
        .route(
            "/api/realms/:realm/clients/:client_id/roles/:role_name/composites",
            post(handlers::client_roles::add_client_role_composites),
        )
        // Role Mappings
        .route(
            "/api/realms/:realm/users/:user_id/role-mappings",
            get(handlers::role_mappings::get_user_role_mappings),
        )
        .route(
            "/api/realms/:realm/users/:user_id/role-mappings/realm",
            get(handlers::role_mappings::get_user_realm_role_mappings),
        )
        .route(
            "/api/realms/:realm/users/:user_id/role-mappings/realm",
            post(handlers::role_mappings::add_user_realm_role_mappings),
        )
        .route(
            "/api/realms/:realm/users/:user_id/role-mappings/realm",
            delete(handlers::role_mappings::remove_user_realm_role_mappings),
        )
        .route(
            "/api/realms/:realm/users/:user_id/role-mappings/realm/available",
            get(handlers::role_mappings::get_available_user_realm_role_mappings),
        )
        .route(
            "/api/realms/:realm/users/:user_id/role-mappings/clients/:client_id",
            get(handlers::role_mappings::get_user_client_role_mappings),
        )
        .route(
            "/api/realms/:realm/users/:user_id/role-mappings/clients/:client_id",
            post(handlers::role_mappings::add_user_client_role_mappings),
        )
        .route(
            "/api/realms/:realm/users/:user_id/role-mappings/clients/:client_id",
            delete(handlers::role_mappings::remove_user_client_role_mappings),
        )
        .route(
            "/api/realms/:realm/users/:user_id/role-mappings/clients/:client_id/available",
            get(handlers::role_mappings::get_available_user_client_role_mappings),
        )
        .route(
            "/api/realms/:realm/groups/:group_id/role-mappings",
            get(handlers::role_mappings::get_group_role_mappings),
        )
        .route(
            "/api/realms/:realm/groups/:group_id/role-mappings/clients/:client_id",
            get(handlers::role_mappings::get_group_client_role_mappings),
        )
        .route(
            "/api/realms/:realm/groups/:group_id/role-mappings/clients/:client_id",
            post(handlers::role_mappings::add_group_client_role_mappings),
        )
        .route(
            "/api/realms/:realm/groups/:group_id/role-mappings/clients/:client_id",
            delete(handlers::role_mappings::remove_group_client_role_mappings),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::handlers::auth::auth_middleware,
        ))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}