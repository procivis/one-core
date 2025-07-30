use sea_orm::{EnumIter, Iterable};
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{Did, Key, Organisation};
use crate::m20240130_105023_add_history::{History, HistoryAction, HistoryEntityType};
use crate::m20240130_153529_add_pending_variant_to_history_action_enum_in_history_table::UpdatedHistoryAction;
use crate::m20240209_144950_add_verifier_key_id_to_proof::{
    copy_data_to_new_tables, drop_and_rename_tables,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager
            .alter_table(
                Table::alter()
                    .table(Did::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(DidNew::DeletedAt).datetime_millisecond_precision(manager),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Key::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(KeyNew::DeletedAt).datetime_millisecond_precision(manager),
                    )
                    .to_owned(),
            )
            .await?;

        // make History::EntityId nullable and add Backup entity
        manager
            .create_table(
                Table::create()
                    .table(HistoryNew::Table)
                    .col(
                        ColumnDef::new(HistoryNew::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(HistoryNew::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(HistoryNew::Action)
                            .enumeration(HistoryAction::Table, UpdatedHistoryAction::iter())
                            .not_null(),
                    )
                    .col(ColumnDef::new(HistoryNew::EntityId).char_len(36))
                    .col(
                        ColumnDef::new(HistoryNew::EntityType)
                            .enumeration(HistoryEntityType::Table, HistoryEntityTypeNew::iter())
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(HistoryNew::OrganisationId)
                            .char_len(36)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-History-OrganisationId-new")
                            .from_tbl(HistoryNew::Table)
                            .from_col(HistoryNew::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        copy_data_to_new_tables(db, vec![("history", "history_new")]).await?;
        drop_and_rename_tables(
            manager,
            vec![(
                History::Table.into_table_ref(),
                HistoryNew::Table.into_table_ref(),
            )],
        )
        .await
    }
}

#[derive(DeriveIden)]
pub enum DidNew {
    DeletedAt,
}

#[derive(DeriveIden)]
enum KeyNew {
    DeletedAt,
}

#[derive(Iden, EnumIter)]
enum HistoryEntityTypeNew {
    #[iden = "KEY"]
    Key,
    #[iden = "DID"]
    Did,
    #[iden = "CREDENTIAL"]
    Credential,
    #[iden = "CREDENTIAL_SCHEMA"]
    CredentialSchema,
    #[iden = "PROOF"]
    Proof,
    #[iden = "PROOF_SCHEMA"]
    ProofSchema,
    #[iden = "ORGANISATION"]
    Organisation,
    #[iden = "BACKUP"]
    Backup,
}

#[derive(Iden)]
pub enum HistoryNew {
    Table,
    Id,
    CreatedDate,
    Action,
    EntityId,
    EntityType,
    OrganisationId,
}
