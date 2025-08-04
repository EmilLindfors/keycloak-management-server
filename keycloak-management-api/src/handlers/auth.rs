use crate::{error::AppError, state::AppState};
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};

pub async fn auth_middleware<B>(
    State(state): State<AppState>,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, AppError> {
    // Skip auth for health check
    if request.uri().path() == "/health" {
        return Ok(next.run(request).await);
    }

    // Check for API key if configured
    if let Some(expected_api_key) = &state.config.api_key {
        let auth_header = request
            .headers()
            .get("x-api-key")
            .and_then(|h| h.to_str().ok());

        match auth_header {
            Some(api_key) if api_key == expected_api_key => {
                Ok(next.run(request).await)
            }
            _ => Err(AppError::Unauthorized),
        }
    } else {
        // No API key configured, allow all requests
        Ok(next.run(request).await)
    }
}