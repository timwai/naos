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

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct UserCreateRequest {
        pub username: String,
        pub password: String,
        pub role: String,
        pub enabled: bool,
        #[serde(default)]
        pub group_ids: Vec<String>,
    }

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct UserUpdateRequest {
        pub role: String,
        pub enabled: bool,
    }

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct AdminPasswordResetRequest {
        pub password: String,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct UserDto {
        pub id: String,
        pub username: String,
        pub role: String,
        pub enabled: bool,
    }

    #[derive(Serialize, ToSchema)]
    pub struct UsersResponse {
        pub items: Vec<UserDto>,
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

pub mod group {
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    use crate::auth::UserDto;

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct GroupWriteRequest {
        pub name: String,
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct GroupMembersReplaceRequest {
        pub user_ids: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct GroupSummaryDto {
        pub id: String,
        pub name: String,
        pub description: Option<String>,
        pub member_count: u64,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct GroupsResponse {
        pub items: Vec<GroupSummaryDto>,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct GroupDetailDto {
        pub id: String,
        pub name: String,
        pub description: Option<String>,
        pub members: Vec<UserDto>,
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

pub mod nfs {
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct NfsBindingUpsertRequest {
        pub cidr: String,
        pub uid: Option<u32>,
        pub user_id: String,
        pub permission: String,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct NfsBindingDto {
        pub id: String,
        pub share_id: String,
        pub cidr: String,
        pub uid: Option<u32>,
        pub user_id: String,
        pub permission: String,
        pub level: String,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct NfsBindingsResponse {
        pub items: Vec<NfsBindingDto>,
    }

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct NfsKrbPrincipalCreateRequest {
        pub principal: String,
        pub user_id: String,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct NfsKrbPrincipalDto {
        pub id: String,
        pub principal: String,
        pub user_id: String,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct NfsKrbPrincipalsResponse {
        pub items: Vec<NfsKrbPrincipalDto>,
    }
}

pub mod operation {
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct OperationDto {
        pub id: String,
        pub kind: String,
        pub state: String,
        pub actor_user_id: Option<String>,
        pub resource_type: Option<String>,
        pub resource_id: Option<String>,
        pub progress: u8,
        pub phase: Option<String>,
        pub error_code: Option<String>,
        pub error_detail_json: Option<String>,
        pub created_at: String,
        pub started_at: Option<String>,
        pub finished_at: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct AcceptedOperation {
        pub operation_id: String,
        pub state: String,
    }
}

pub mod doctor {
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct SmbDoctorListenerDto {
        pub local_address: String,
        pub pid: Option<u32>,
        pub process: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct SmbDoctorCapabilitiesDto {
        pub share_management: bool,
        pub credential_management: bool,
        pub requires_existing_provider: bool,
        pub manages_tcp_445_listener: bool,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct SmbDoctorFindingDto {
        pub code: String,
        pub severity: String,
        pub summary: String,
        pub detail: String,
        pub remediation: String,
        pub automatic_fix_allowed: bool,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct SmbDoctorResponse {
        pub status: String,
        pub platform: String,
        pub provider: String,
        pub expected_provider: String,
        pub installed: bool,
        pub running: bool,
        pub service_name: Option<String>,
        pub config_mode: String,
        pub managed_by_naos: bool,
        pub listener_445: Option<SmbDoctorListenerDto>,
        pub capabilities: SmbDoctorCapabilitiesDto,
        pub findings: Vec<SmbDoctorFindingDto>,
    }
}

pub mod share {
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct ShareWriteRequest {
        pub name: String,
        pub path: String,
        pub comment: Option<String>,
        pub enabled: bool,
        pub smb_enabled: bool,
        pub webdav_enabled: bool,
        pub nfs_enabled: bool,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct ShareDto {
        pub id: String,
        pub name: String,
        pub path: String,
        pub canonical_path: String,
        pub comment: Option<String>,
        pub enabled: bool,
        pub smb_enabled: bool,
        pub webdav_enabled: bool,
        pub nfs_enabled: bool,
        pub generation: u64,
        pub applied_generation: u64,
        pub apply_state: String,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct SharesResponse {
        pub items: Vec<ShareDto>,
    }
}

pub mod acl {
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct AclSubjectDto {
        #[serde(rename = "type")]
        pub subject_type: String,
        pub id: String,
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct AclRuleDto {
        pub id: String,
        pub rel_path: String,
        pub subject: AclSubjectDto,
        pub permission: String,
        pub inherit: bool,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct AclRulesResponse {
        pub items: Vec<AclRuleDto>,
    }

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct AclSubjectInput {
        #[serde(rename = "type")]
        pub subject_type: String,
        pub id: String,
    }

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct AclRuleWriteDto {
        pub rel_path: String,
        pub subject: AclSubjectInput,
        pub permission: String,
        pub inherit: bool,
    }

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct AclReplaceRequest {
        pub items: Vec<AclRuleWriteDto>,
    }

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct AclSimulateRequest {
        pub user_id: String,
        pub rel_path: String,
        pub operation: String,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct AclMatchedRuleDto {
        pub rel_path: String,
        pub subject: String,
        pub permission: String,
        pub inherit: bool,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct AclSimulationResponse {
        pub permission: String,
        pub allowed: bool,
        pub matched_depth: Option<u32>,
        pub matched_rules: Vec<AclMatchedRuleDto>,
        pub explanation: String,
    }
}

pub mod files {
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct FileShareDto {
        pub id: String,
        pub name: String,
        pub effective_permission: String,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct FileSharesResponse {
        pub items: Vec<FileShareDto>,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct FileEntryDto {
        pub name: String,
        pub kind: String,
        pub size: Option<u64>,
        pub modified_at: Option<String>,
        pub effective_permission: String,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct FileDirectoryResponse {
        pub path: String,
        pub effective_permission: String,
        pub entries: Vec<FileEntryDto>,
    }

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct CreateDirectoryRequest {
        pub path: String,
    }

    #[derive(Debug, Clone, Deserialize, ToSchema)]
    pub struct MoveFileRequest {
        pub source_path: String,
        pub destination_path: String,
    }
}

pub mod audit {
    use serde::Serialize;
    use serde_json::Value;
    use utoipa::ToSchema;

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct AuditActorDto {
        #[serde(rename = "type")]
        pub actor_type: String,
        pub id: Option<String>,
        pub name: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct AuditRecordDto {
        pub id: String,
        pub timestamp: String,
        pub actor: AuditActorDto,
        pub protocol: Option<String>,
        pub action: String,
        pub share_id: Option<String>,
        pub path: Option<String>,
        pub client_ip: Option<String>,
        pub result: String,
        pub detail: Option<Value>,
        pub request_id: Option<String>,
        pub operation_id: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, ToSchema)]
    pub struct AuditPageResponse {
        pub items: Vec<AuditRecordDto>,
        pub page: u32,
        pub page_size: u32,
        pub total: u64,
    }
}
