pub mod auth {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(Serialize, ToSchema)]
    pub struct SetupStatusResponse {
        pub initialized: bool,
    }

    #[derive(Deserialize, ToSchema)]
    pub struct SetupAdminRequest {
        pub username: String,
        pub password: String,
    }

    #[derive(Deserialize, ToSchema)]
    pub struct LoginRequest {
        pub username: String,
        pub password: String,
    }

    #[derive(Deserialize, ToSchema)]
    pub struct PasswordChangeRequest {
        pub current_password: String,
        pub new_password: String,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct UserDto {
        pub id: String,
        pub username: String,
        pub role: String,
        pub enabled: bool,
    }

    #[derive(Serialize, ToSchema)]
    pub struct AuthSessionResponse {
        pub authenticated: bool,
        pub user: Option<UserDto>,
        pub csrf_token: Option<String>,
    }

    #[derive(Serialize, ToSchema)]
    pub struct SessionDto {
        pub id: String,
        pub created_at: String,
        pub last_seen_at: String,
        pub expires_at: String,
        pub client_ip: Option<String>,
        pub user_agent: Option<String>,
        pub current: bool,
    }

    #[derive(Serialize, ToSchema)]
    pub struct SessionsResponse {
        pub items: Vec<SessionDto>,
    }

    #[derive(Serialize, ToSchema)]
    pub struct ErrorResponse {
        pub code: String,
        pub message: String,
        pub field_errors: Option<BTreeMap<String, Vec<String>>>,
    }
}

pub mod health {
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct HealthResponse {
        pub status: &'static str,
    }

    impl HealthResponse {
        pub const fn live() -> Self {
            Self { status: "ok" }
        }

        pub const fn ready() -> Self {
            Self { status: "ready" }
        }

        pub const fn unavailable() -> Self {
            Self {
                status: "unavailable",
            }
        }
    }
}
