use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Keycloak error: {0}")]
    Keycloak(#[from] keycloak::KeycloakError),

    #[error("Domain error: {0}")]
    Domain(#[from] keycloak_domain::domain::errors::DomainError),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Keycloak(e) => {
                match e {
                    keycloak::KeycloakError::HttpFailure { status, text, .. } => {
                        let status_code = match status {
                            400 => StatusCode::BAD_REQUEST,
                            401 => StatusCode::UNAUTHORIZED,
                            403 => StatusCode::FORBIDDEN,
                            404 => StatusCode::NOT_FOUND,
                            409 => StatusCode::CONFLICT,
                            _ => StatusCode::INTERNAL_SERVER_ERROR,
                        };
                        (status_code, text)
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
                }
            }
            AppError::Domain(e) => {
                use keycloak_domain::domain::errors::DomainError;
                match e {
                    DomainError::UserNotFound { .. } => (StatusCode::NOT_FOUND, e.to_string()),
                    DomainError::ClientNotFound { .. } => (StatusCode::NOT_FOUND, e.to_string()),
                    DomainError::GroupNotFound { .. } => (StatusCode::NOT_FOUND, e.to_string()),
                    DomainError::RoleNotFound { .. } => (StatusCode::NOT_FOUND, e.to_string()),
                    DomainError::RealmNotFound { .. } => (StatusCode::NOT_FOUND, e.to_string()),
                    DomainError::Validation { .. } => (StatusCode::BAD_REQUEST, e.to_string()),
                    DomainError::AuthenticationFailed { .. } => (StatusCode::UNAUTHORIZED, e.to_string()),
                    DomainError::AuthorizationFailed { .. } => (StatusCode::FORBIDDEN, e.to_string()),
                    DomainError::Conflict { .. } => (StatusCode::CONFLICT, e.to_string()),
                    DomainError::ExternalService { .. } => (StatusCode::BAD_GATEWAY, e.to_string()),
                    DomainError::Configuration { .. } => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
                    DomainError::Internal { .. } => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
                }
            }
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            AppError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;