use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use crate::auth::{UserSummary, now_rfc3339, prefixed_id};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSummary {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub member_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupDetail {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub members: Vec<UserSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupWriteInput {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Error)]
pub enum GroupRepositoryError {
    #[error("group was not found")]
    NotFound,
    #[error("group name or membership conflicts with current state")]
    Conflict,
    #[error("group is referenced by one or more share ACL rules")]
    AclReferenced,
    #[error("one or more users were not found")]
    UserNotFound,
    #[error("group store is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("group was not found")]
    NotFound,
    #[error("group name or membership conflicts with current state")]
    Conflict,
    #[error("group is referenced by one or more share ACL rules")]
    AclReferenced,
    #[error("one or more users were not found")]
    UserNotFound,
    #[error("{message}")]
    Validation {
        field: &'static str,
        message: String,
    },
    #[error("group store failure")]
    Repository,
}

#[async_trait]
pub trait GroupRepository: Send + Sync {
    async fn list_groups(&self) -> Result<Vec<GroupSummary>, GroupRepositoryError>;

    async fn get_group(&self, group_id: &str) -> Result<Option<GroupDetail>, GroupRepositoryError>;

    async fn create_group(
        &self,
        group_id: &str,
        input: &GroupWriteInput,
        timestamp: &str,
    ) -> Result<GroupDetail, GroupRepositoryError>;

    async fn update_group(
        &self,
        group_id: &str,
        input: &GroupWriteInput,
        timestamp: &str,
    ) -> Result<GroupDetail, GroupRepositoryError>;

    async fn delete_group(&self, group_id: &str) -> Result<(), GroupRepositoryError>;

    async fn replace_members(
        &self,
        group_id: &str,
        user_ids: &[String],
        timestamp: &str,
    ) -> Result<GroupDetail, GroupRepositoryError>;

    async fn list_user_groups(
        &self,
        user_id: &str,
    ) -> Result<Vec<GroupSummary>, GroupRepositoryError>;
}

pub struct GroupService {
    repository: Arc<dyn GroupRepository>,
}

impl GroupService {
    pub fn new(repository: Arc<dyn GroupRepository>) -> Self {
        Self { repository }
    }

    pub async fn list(&self) -> Result<Vec<GroupSummary>, GroupError> {
        self.repository.list_groups().await.map_err(map_repository)
    }

    pub async fn get(&self, group_id: &str) -> Result<GroupDetail, GroupError> {
        self.repository
            .get_group(group_id)
            .await
            .map_err(map_repository)?
            .ok_or(GroupError::NotFound)
    }

    pub async fn create(&self, input: GroupWriteInput) -> Result<GroupDetail, GroupError> {
        let input = normalize(input)?;
        let timestamp = now_rfc3339().map_err(|_| GroupError::Repository)?;
        self.repository
            .create_group(&prefixed_id("grp"), &input, &timestamp)
            .await
            .map_err(map_repository)
    }

    pub async fn update(
        &self,
        group_id: &str,
        input: GroupWriteInput,
    ) -> Result<GroupDetail, GroupError> {
        let input = normalize(input)?;
        let timestamp = now_rfc3339().map_err(|_| GroupError::Repository)?;
        self.repository
            .update_group(group_id, &input, &timestamp)
            .await
            .map_err(map_repository)
    }

    pub async fn delete(&self, group_id: &str) -> Result<(), GroupError> {
        self.repository
            .delete_group(group_id)
            .await
            .map_err(map_repository)
    }

    pub async fn replace_members(
        &self,
        group_id: &str,
        mut user_ids: Vec<String>,
    ) -> Result<GroupDetail, GroupError> {
        if user_ids.len() > 1000 {
            return Err(GroupError::Validation {
                field: "user_ids",
                message: "单个用户组最多允许 1000 个成员".to_owned(),
            });
        }
        for user_id in &mut user_ids {
            *user_id = user_id.trim().to_owned();
            if user_id.is_empty() || user_id.len() > 128 {
                return Err(GroupError::Validation {
                    field: "user_ids",
                    message: "用户 ID 无效".to_owned(),
                });
            }
        }
        user_ids.sort();
        user_ids.dedup();

        let timestamp = now_rfc3339().map_err(|_| GroupError::Repository)?;
        self.repository
            .replace_members(group_id, &user_ids, &timestamp)
            .await
            .map_err(map_repository)
    }

    pub async fn list_user_groups(
        &self,
        user_id: &str,
    ) -> Result<Vec<GroupSummary>, GroupError> {
        self.repository
            .list_user_groups(user_id)
            .await
            .map_err(map_repository)
    }
}

fn normalize(mut input: GroupWriteInput) -> Result<GroupWriteInput, GroupError> {
    input.name = input.name.trim().to_owned();
    if input.name.is_empty()
        || input.name.len() > 64
        || input
            .name
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':'))
    {
        return Err(GroupError::Validation {
            field: "name",
            message: "用户组名称必须为 1-64 个安全字符".to_owned(),
        });
    }

    input.description = input
        .description
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if input
        .description
        .as_ref()
        .is_some_and(|value| value.len() > 1024)
    {
        return Err(GroupError::Validation {
            field: "description",
            message: "用户组说明不能超过 1024 字节".to_owned(),
        });
    }

    Ok(input)
}

fn map_repository(error: GroupRepositoryError) -> GroupError {
    match error {
        GroupRepositoryError::NotFound => GroupError::NotFound,
        GroupRepositoryError::Conflict => GroupError::Conflict,
        GroupRepositoryError::AclReferenced => GroupError::AclReferenced,
        GroupRepositoryError::UserNotFound => GroupError::UserNotFound,
        GroupRepositoryError::Unavailable => GroupError::Repository,
    }
}
