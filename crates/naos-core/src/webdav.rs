use async_trait::async_trait;

use crate::acl::AclRule;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebDavShare {
    pub id: String,
    pub name: String,
    pub canonical_path: String,
}

#[derive(Debug, thiserror::Error)]
pub enum WebDavRepositoryError {
    #[error("webdav store is unavailable")]
    Unavailable,
}

#[async_trait]
pub trait WebDavRepository: Send + Sync {
    async fn find_enabled_share_by_name(
        &self,
        name: &str,
    ) -> Result<Option<WebDavShare>, WebDavRepositoryError>;

    async fn list_acl_rules(
        &self,
        share_id: &str,
    ) -> Result<Vec<AclRule>, WebDavRepositoryError>;

    async fn group_ids_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<String>, WebDavRepositoryError>;
}
