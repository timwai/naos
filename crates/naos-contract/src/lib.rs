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
