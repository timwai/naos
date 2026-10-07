use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Extension, Path, Query, State},
    http::{
        HeaderValue, StatusCode,
        header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use naos_contract::{
    auth::ErrorResponse,
    files::{
        CreateDirectoryRequest, FileDirectoryResponse, FileEntryDto, FileShareDto,
        FileSharesResponse, MoveFileRequest,
    },
};
use naos_core::{
    auth::AuthenticatedSession,
    files::{FileDirectoryListing, FileServiceError},
};
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use utoipa::OpenApi;

use super::{ApiError, AppState};

#[derive(Debug, Deserialize)]
struct FilePathQuery {
    path: Option<String>,
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/files/shares", get(list_file_shares))
        .route(
            "/shares/{share_id}/files",
            get(list_directory).delete(delete_entry),
        )
        .route(
            "/shares/{share_id}/directories",
            post(create_directory),
        )
        .route("/shares/{share_id}/files/move", post(move_entry))
        .route("/shares/{share_id}/files/download", get(download_file))
}

#[utoipa::path(
    get,
    path = "/api/v1/files/shares",
    responses(
        (status = 200, body = FileSharesResponse),
        (status = 401, body = ErrorResponse)
    ),
    tag = "files"
)]
async fn list_file_shares(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<FileSharesResponse>, ApiError> {
    let items = state
        .files
        .list_accessible_shares(&session.user.id)
        .await?
        .into_iter()
        .map(|share| FileShareDto {
            id: share.id,
            name: share.name,
            effective_permission: share.effective_permission.as_str().to_owned(),
        })
        .collect();

    Ok(Json(FileSharesResponse { items }))
}

#[utoipa::path(
    get,
    path = "/api/v1/shares/{share_id}/files",
    params(
        ("share_id" = String, Path, description = "Share ID"),
        ("path" = Option<String>, Query, description = "Share-relative path; defaults to /")
    ),
    responses(
        (status = 200, body = FileDirectoryResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "files"
)]
async fn list_directory(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
    Query(query): Query<FilePathQuery>,
) -> Result<Json<FileDirectoryResponse>, ApiError> {
    let listing = state
        .files
        .list_directory(
            &session.user.id,
            &share_id,
            query.path.as_deref().unwrap_or("/"),
        )
        .await?;

    Ok(Json(listing_dto(listing)))
}

#[utoipa::path(
    post,
    path = "/api/v1/shares/{share_id}/directories",
    params(("share_id" = String, Path, description = "Share ID")),
    request_body = CreateDirectoryRequest,
    responses(
        (status = 201),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "files"
)]
async fn create_directory(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
    Json(input): Json<CreateDirectoryRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .files
        .create_directory(&session.user.id, &share_id, &input.path)
        .await?;
    Ok(StatusCode::CREATED)
}

#[utoipa::path(
    post,
    path = "/api/v1/shares/{share_id}/files/move",
    params(("share_id" = String, Path, description = "Share ID")),
    request_body = MoveFileRequest,
    responses(
        (status = 204),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "files"
)]
async fn move_entry(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
    Json(input): Json<MoveFileRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .files
        .move_entry(
            &session.user.id,
            &share_id,
            &input.source_path,
            &input.destination_path,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/api/v1/shares/{share_id}/files",
    params(
        ("share_id" = String, Path, description = "Share ID"),
        ("path" = String, Query, description = "Share-relative path")
    ),
    responses(
        (status = 204),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "files"
)]
async fn delete_entry(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
    Query(query): Query<FilePathQuery>,
) -> Result<StatusCode, ApiError> {
    let path = query
        .path
        .as_deref()
        .ok_or_else(|| ApiError::validation("path", "必须提供文件相对路径"))?;
    state
        .files
        .delete(&session.user.id, &share_id, path)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/shares/{share_id}/files/download",
    params(
        ("share_id" = String, Path, description = "Share ID"),
        ("path" = String, Query, description = "Share-relative file path")
    ),
    responses(
        (status = 200, description = "Binary file download"),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 422, body = ErrorResponse)
    ),
    tag = "files"
)]
async fn download_file(
    State(state): State<AppState>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(share_id): Path<String>,
    Query(query): Query<FilePathQuery>,
) -> Result<Response, ApiError> {
    let path = query
        .path
        .as_deref()
        .ok_or_else(|| ApiError::validation("path", "必须提供文件相对路径"))?;
    let download = state
        .files
        .prepare_download(&session.user.id, &share_id, path)
        .await?;
    let mut file = tokio::fs::File::open(&download.path)
        .await
        .map_err(|_| ApiError::internal())?;
    let stream = async_stream::stream! {
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            match file.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => {
                    yield Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(&buffer[..read]));
                }
                Err(error) => {
                    yield Err::<Bytes, std::io::Error>(error);
                    break;
                }
            }
        }
    };

    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(value) = HeaderValue::from_str(&download.len.to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, value);
    }
    let safe_name = download
        .file_name
        .chars()
        .filter(|character| character.is_ascii_graphic() && !matches!(*character, '"' | '\\'))
        .collect::<String>();
    let disposition = if safe_name.is_empty() {
        "attachment".to_owned()
    } else {
        format!("attachment; filename=\"{safe_name}\"")
    };
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        response.headers_mut().insert(CONTENT_DISPOSITION, value);
    }
    Ok(response)
}

fn listing_dto(listing: FileDirectoryListing) -> FileDirectoryResponse {
    FileDirectoryResponse {
        path: listing.path,
        entries: listing
            .entries
            .into_iter()
            .map(|entry| FileEntryDto {
                name: entry.name,
                kind: entry.kind.as_str().to_owned(),
                size: entry.size,
                modified_at: entry.modified_at,
                effective_permission: entry.effective_permission.as_str().to_owned(),
            })
            .collect(),
    }
}

impl From<FileServiceError> for ApiError {
    fn from(error: FileServiceError) -> Self {
        match error {
            FileServiceError::ShareNotFound | FileServiceError::NotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "FILE_NOT_FOUND", "共享或文件不存在")
            }
            FileServiceError::Forbidden => {
                ApiError::forbidden("FILE_ACCESS_DENIED", "没有访问该文件路径的权限")
            }
            FileServiceError::NotDirectory => ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "NOT_A_DIRECTORY",
                "目标路径不是目录",
            ),
            FileServiceError::AlreadyExists => ApiError::new(
                StatusCode::CONFLICT,
                "FILE_ALREADY_EXISTS",
                "目标路径已存在",
            ),
            FileServiceError::Validation { field, message } => {
                ApiError::validation(field, &message)
            }
            FileServiceError::Io | FileServiceError::Repository(_) => ApiError::internal(),
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_file_shares,
        list_directory,
        create_directory,
        move_entry,
        delete_entry,
        download_file
    ),
    components(schemas(
        FileShareDto,
        FileSharesResponse,
        FileEntryDto,
        FileDirectoryResponse,
        CreateDirectoryRequest,
        MoveFileRequest,
        ErrorResponse
    )),
    tags((name = "files", description = "Session-authenticated file browsing and operations"))
)]
struct FileApiDoc;

pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    FileApiDoc::openapi()
}
