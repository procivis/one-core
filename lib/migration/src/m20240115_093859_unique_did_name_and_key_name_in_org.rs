use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{Did, Key};

#[derive(DeriveMigrationName)]
pub struct Migration;

pub const UNIQUE_DID_NAME_IN_ORGANISATION_INDEX: &str = "index-Did-Name-OrganisationId-Unique";
const UNIQUE_KEY_NAME_IN_ORGANISATION_INDEX: &str = "index-Key-Name-OrganisationId-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_DID_NAME_IN_ORGANISATION_INDEX)
                    .table(Did::Table)
                    .col(Did::Name)
                    .col(Did::OrganisationId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_KEY_NAME_IN_ORGANISATION_INDEX)
                    .table(Key::Table)
                    .col(Key::Name)
                    .col(Key::OrganisationId)
                    .unique()
                    .to_owned(),
            )
            .await
    }
}
