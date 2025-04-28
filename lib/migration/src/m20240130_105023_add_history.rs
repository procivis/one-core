use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::Organisation;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(History::Table)
                    .col(
                        ColumnDef::new(History::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(History::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(History::Action)
                            .enumeration(
                                HistoryAction::Table,
                                [
                                    HistoryAction::Accepted,
                                    HistoryAction::Created,
                                    HistoryAction::Deactivated,
                                    HistoryAction::Deleted,
                                    HistoryAction::Issued,
                                    HistoryAction::Offered,
                                    HistoryAction::Rejected,
                                    HistoryAction::Requested,
                                    HistoryAction::Revoked,
                                ],
                            )
                            .not_null(),
                    )
                    .col(ColumnDef::new(History::EntityId).char_len(36).not_null())
                    .col(
                        ColumnDef::new(History::EntityType)
                            .enumeration(
                                HistoryEntityType::Table,
                                [
                                    HistoryEntityType::Key,
                                    HistoryEntityType::Did,
                                    HistoryEntityType::Credential,
                                    HistoryEntityType::CredentialSchema,
                                    HistoryEntityType::Proof,
                                    HistoryEntityType::ProofSchema,
                                    HistoryEntityType::Organisation,
                                ],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(History::OrganisationId)
                            .char_len(36)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-History-OrganisationId")
                            .from_tbl(History::Table)
                            .from_col(History::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum History {
    Table,
    Id,
    CreatedDate,
    Action,
    EntityId,
    EntityType,
    OrganisationId,
}

#[derive(Iden)]
pub enum HistoryAction {
    Table,
    #[iden = "ACCEPTED"]
    Accepted,
    #[iden = "CREATED"]
    Created,
    #[iden = "DEACTIVATED"]
    Deactivated,
    #[iden = "DELETED"]
    Deleted,
    #[iden = "ISSUED"]
    Issued,
    #[iden = "OFFERED"]
    Offered,
    #[iden = "REJECTED"]
    Rejected,
    #[iden = "REQUESTED"]
    Requested,
    #[iden = "REVOKED"]
    Revoked,
}

#[derive(Iden)]
pub enum HistoryEntityType {
    Table,
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
}
