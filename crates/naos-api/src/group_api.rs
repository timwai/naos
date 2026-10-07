use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{get, put},
};
use naos_contract::{
    auth::{ErrorResponse, UserDto},
    group::{
        GroupDetailDto, GroupMembersReplaceRequest, GroupSummaryDto, GroupWriteRequest,
        GroupsResponse,
    },
};
use naos_core::{
    auth::{AuthService, AuthenticatedSession, UserSummary},
    group::{GroupDetail, GroupError, GroupSummary, GroupWriteInput},
};
use utoipa::OpenApi;

use super::{ApiError, AppState};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/groups", get(list_groups).post(create_group))
        .route(
            "/groups/{group_id}",
            get(get_group).put(update_group).delete(delete_group),
        )
        .route("/groups/{group_id}/members", put(replace_members))
        .route("/users/{user_id}/groups", get(list_user_groups))
}

#[utoipa::path(
    get,
    path = "/api/v1/groups",
    responses(
        (status = 200, body = GroupsResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse)
    ),
    tag = "groups"
)]
async fn list_groups(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<GroupsResponse>, ApiError> {
    AuthService::ensure_admin(&session)?;
    Ok(Json(GroupsResponse {
        items: state
            .groups
            .list()
            .await?
            .into_iter()
            .map(summary_dto)
            .collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/groups",
    request_body = GroupWriteRequest,
    responses(
        (status = 201, body = GroupDetailDto),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "groups"
)]
async fn create_group(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(input): Json<GroupWriteRequest>,
) -> Result<(StatusCode, Json<GroupDetailDto>), ApiError> {
    AuthService::ensure_admin(&session)?;
    let group = state
        .groups
        .create(GroupWriteInput {
            name: input.name,
            description: input.description,
        })
        .await?;
    Ok((StatusCode::CREATED, Json(detail_dto(group))))
}

#[utoipa::path(
    get,
    path = "/api/v1/groups/{group_id}",
    params(("group_id" = String, Path, description = "Group ID")),
    responses(
        (status = 200, body = GroupDetailDto),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse)
    ),
    tag = "groups"
)]
async fn get_group(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(group_id): Path<String>,
) -> Result<Json<GroupDetailDto>, ApiError> {
    AuthService::ensure_admin(&session)?;
    Ok(Json(detail_dto(state.groups.get(&group_id).await?)))
}

#[utoipa::path(
    put,
    path = "/api/v1/groups/{group_id}",
    params(("group_id" = String, Path, description = "Group ID")),
    request_body = GroupWriteRequest,
    responses(
        (status = 200, body = GroupDetailDto),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "groups"
)]
async fn update_group(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(group_id): Path<String>,
    Json(input): Json<GroupWriteRequest>,
) -> Result<Json<GroupDetailDto>, ApiError> {
    AuthService::ensure_admin(&session)?;
    Ok(Json(detail_dto(
        state
            .groups
            .update(
                &group_id,
                GroupWriteInput {
                    name: input.name,
                    description: input.description,
                },
            )
            .await?,
    )))
}

#[utoipa::path(
    delete,
    path = "/api/v1/groups/{group_id}",
    params(("group_id" = String, Path, description = "Group ID")),
    responses(
        (status = 204),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse)
    ),
    tag = "groups"
)]
async fn delete_group(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(group_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    AuthService::ensure_admin(&session)?;
    state.groups.delete(&group_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    put,
    path = "/api/v1/groups/{group_id}/members",
    params(("group_id" = String, Path, description = "Group ID")),
    request_body = GroupMembersReplaceRequest,
    responses(
        (status = 200, body = GroupDetailDto),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "groups"
)]
async fn replace_members(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(group_id): Path<String>,
    Json(input): Json<GroupMembersReplaceRequest>,
) -> Result<Json<GroupDetailDto>, ApiError> {
    AuthService::ensure_admin(&session)?;
    Ok(Json(detail_dto(
        state
            .groups
            .replace_members(&group_id, input.user_ids)
            .await?,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/users/{user_id}/groups",
    params(("user_id" = String, Path, description = "User ID")),
    responses(
        (status = 200, body = GroupsResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse)
    ),
    tag = "groups"
)]
async fn list_user_groups(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(user_id): Path<String>,
) -> Result<Json<GroupsResponse>, ApiError> {
    AuthService::ensure_admin(&session)?;
    Ok(Json(GroupsResponse {
        items: state
            .groups
            .list_user_groups(&user_id)
            .await?
            .into_iter()
            .map(summary_dto)
            .collect(),
    }))
}

fn summary_dto(group: GroupSummary) -> GroupSummaryDto {
    GroupSummaryDto {
        id: group.id,
        name: group.name,
        description: group.description,
        member_count: group.member_count,
    }
}

fn detail_dto(group: GroupDetail) -> GroupDetailDto {
    GroupDetailDto {
        id: group.id,
        name: group.name,
        description: group.description,
        members: group.members.into_iter().map(user_dto).collect(),
    }
}

fn user_dto(user: UserSummary) -> UserDto {
    UserDto {
        id: user.id,
        username: user.username,
        role: user.role.as_str().to_owned(),
        enabled: user.enabled,
    }
}

impl From<GroupError> for ApiError {
    fn from(error: GroupError) -> Self {
        match error {
            GroupError::NotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "GROUP_NOT_FOUND", "用户组不存在")
            }
            GroupError::Conflict => ApiError::new(
                StatusCode::CONFLICT,
                "GROUP_CONFLICT",
                "用户组名称或成员状态发生冲突",
            ),
            GroupError::AclReferenced => ApiError::new(
                StatusCode::CONFLICT,
                "GROUP_ACL_REFERENCED",
                "用户组仍被共享 ACL 引用；请先移除相关 ACL 规则",
            ),
            GroupError::UserNotFound => ApiError::new(
                StatusCode::NOT_FOUND,
                "USER_NOT_FOUND",
                "成员列表包含不存在的用户，或用户不存在",
            ),
            GroupError::Validation { field, message } => ApiError::validation(field, &message),
            GroupError::Repository => ApiError::internal(),
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_groups,
        create_group,
        get_group,
        update_group,
        delete_group,
        replace_members,
        list_user_groups
    ),
    components(schemas(
        GroupWriteRequest,
        GroupMembersReplaceRequest,
        GroupSummaryDto,
        GroupsResponse,
        GroupDetailDto,
        UserDto,
        ErrorResponse
    )),
    tags((name = "groups", description = "User group administration and atomic membership"))
)]
struct GroupApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    GroupApiDoc::openapi()
}
