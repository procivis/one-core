use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{Credential, Interaction, RevocationList};
use crate::m20240220_082229_add_lvvc_table::Lvvc;
use crate::m20240514_070446_add_trust_model::TrustEntity;
use crate::m20240528_090016_rename_lvvc_table_to_validity_credential::ValidityCredential;
use crate::m20240726_084216_rename_jsonldcontextprovider_to_cacheprovider::RemoteEntityCache;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::MySql {
            manager
                .alter_table(
                    Table::alter()
                        .table(RevocationList::Table)
                        .modify_column(
                            ColumnDef::new(RevocationList::Credentials)
                                .large_blob(manager)
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(Credential::Table)
                        .modify_column(
                            ColumnDef::new(Credential::Credential)
                                .large_blob(manager)
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(ValidityCredential::Table)
                        .modify_column(
                            ColumnDef::new(Lvvc::Credential)
                                .large_blob(manager)
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(RemoteEntityCache::Table)
                        .modify_column(
                            ColumnDef::new(RemoteEntityCache::Value)
                                .large_blob(manager)
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(TrustEntity::Table)
                        .modify_column(ColumnDef::new(TrustEntity::Logo).large_blob(manager))
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(Interaction::Table)
                        .modify_column(ColumnDef::new(Interaction::Data).large_blob(manager))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
