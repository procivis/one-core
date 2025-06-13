use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::Did;

#[derive(DeriveMigrationName)]
pub struct Migration;

pub const DID_IN_DID_INDEX: &str = "index-Did-Did";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name(DID_IN_DID_INDEX)
                    .table(Did::Table)
                    .col(Did::Did)
                    .to_owned(),
            )
            .await
    }
}
