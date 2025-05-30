use sea_orm_migration::prelude::*;

use crate::m20250608_142503_remove_did_mdl::{
    find_dids_with_method, remove_dids_and_related_entities,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let dids = find_dids_with_method(manager, "SD_JWT_VC_ISSUER_METADATA").await?;
        remove_dids_and_related_entities(manager, &dids).await
    }
}
