use crate::{
    error::{AppResult, AppError}, 
    state::AppState,
    dto::{UserDto, CreateUserRequest, UserQuery, ApiResponse}
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use keycloak_domain::domain::entities::{User, Credential};

pub async fn list_users(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Query(query): Query<UserQuery>,
) -> AppResult<Json<ApiResponse<Vec<UserDto>>>> {
    let filter = query.to_domain_filter();
    let users = state.user_service.list_users(&realm, &filter).await?;
    let user_dtos: Vec<UserDto> = users.into_iter().map(|u| u.into()).collect();
    Ok(Json(ApiResponse::success(user_dtos)))
}

pub async fn create_user(
    State(state): State<AppState>,
    Path(realm): Path<String>,
    Json(request): Json<CreateUserRequest>,
) -> AppResult<Json<ApiResponse<String>>> {
    let mut user = request.to_domain()?;
    let user_id = state.user_service.create_user(&realm, &user).await?;
    
    // Set password if provided
    if let Some(password) = &request.password {
        let credential = Credential {
            id: None,
            type_: "password".to_string(),
            value: Some(password.clone()),
            temporary: Some(request.temporary_password.unwrap_or(false)),
            created_date: None,
            user_label: None,
            secret_data: None,
            credential_data: None,
            priority: None,
        };
        
        state.user_service.set_user_password(&realm, user_id.as_str(), &credential).await?;
    }
    
    Ok(Json(ApiResponse::success_with_message(
        user_id.to_string(),
        "User created successfully".to_string()
    )))
}

pub async fn get_user(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
) -> AppResult<Json<ApiResponse<UserDto>>> {
    let user = state.user_service.find_user_by_id(&realm, &user_id).await?;
    Ok(Json(ApiResponse::success(user.into())))
}

pub async fn update_user(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
    Json(request): Json<CreateUserRequest>,
) -> AppResult<Json<ApiResponse<String>>> {
    let mut user = request.to_domain()?;
    user.id = Some(keycloak_domain::domain::entities::EntityId::from_string(user_id));
    
    state.user_service.update_user(&realm, &user).await?;
    
    Ok(Json(ApiResponse::success_with_message(
        "User updated successfully".to_string(),
        "User updated successfully".to_string()
    )))
}

pub async fn delete_user(
    State(state): State<AppState>,
    Path((realm, user_id)): Path<(String, String)>,
) -> AppResult<Json<ApiResponse<String>>> {
    state.user_service.delete_user(&realm, &user_id).await?;
    
    Ok(Json(ApiResponse::success_with_message(
        "User deleted successfully".to_string(),
        "User deleted successfully".to_string()
    )))
}