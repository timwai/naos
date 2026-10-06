use std::str::FromStr;

use async_trait::async_trait;
use naos_core::nfs::{
    NfsBinding, NfsBindingPermission, NfsBindingRepository, NfsCidr, NfsRepositoryError,
};
use sqlx::Row;

use crate::Store;

#[async_trait]
impl NfsBindingRepository for Store {
    async fn list_nfs_bindings(
        &self,
        share_id: &str,
    ) -> Result<Vec<NfsBinding>, NfsRepositoryError> {
        let rows = sqlx::query(
            "SELECT id, share_id, cidr, uid, user_id, perm
             FROM nfs_bindings
             WHERE share_id = ?
             ORDER BY id",
        )
        .bind(share_id)
        .fetch_all(&self.pool)
        .await
        .map_err(store_error)?;

        rows.into_iter()
            .map(|row| {
                let cidr = row.try_get::<String, _>("cidr").map_err(store_error)?;
                let permission = row.try_get::<String, _>("perm").map_err(store_error)?;
                let uid = row
                    .try_get::<Option<i64>, _>("uid")
                    .map_err(store_error)?
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| NfsRepositoryError::Unavailable)?;

                Ok(NfsBinding {
                    id: row.try_get("id").map_err(store_error)?,
                    share_id: row.try_get("share_id").map_err(store_error)?,
                    cidr: NfsCidr::from_str(&cidr).map_err(|_| NfsRepositoryError::Unavailable)?,
                    uid,
                    user_id: row.try_get("user_id").map_err(store_error)?,
                    permission: NfsBindingPermission::from_str(&permission)
                        .map_err(|_| NfsRepositoryError::Unavailable)?,
                })
            })
            .collect()
    }
}

fn store_error(_: sqlx::Error) -> NfsRepositoryError {
    NfsRepositoryError::Unavailable
}
