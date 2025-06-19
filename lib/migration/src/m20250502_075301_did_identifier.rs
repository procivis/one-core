use sea_orm::FromQueryResult;
use sea_orm_migration::prelude::*;
use time::OffsetDateTime;

use crate::m20240110_000001_initial::{Credential, Did, DidType, Proof};
use crate::m20240223_103849_add_backup_columns::DidNew as DidWithDeletedAt;
use crate::m20250429_142011_add_identifier::{
    CredentialNew, Identifier, IdentifierStatus, IdentifierType, ProofNew,
};
use crate::m20250502_114600_add_deleted_at_to_identifier::Identifier as IdentifierWithDeletedAt;

pub const UNIQUE_IDENTIFIER_NAME_IN_ORGANISATION_INDEX: &str =
    "index-Identifier-Name-OrganisationId-Unique";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        {
            let mut batch_no = 0;
            while create_identifiers_for_dids(manager, batch_no).await? {
                batch_no += 1;
            }
        }

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_IDENTIFIER_NAME_IN_ORGANISATION_INDEX)
                    .table(Identifier::Table)
                    .col(Identifier::Name)
                    .col(Identifier::OrganisationId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        set_identifiers(
            manager,
            Credential::Table,
            Credential::IssuerDidId,
            CredentialNew::IssuerIdentifierId,
        )
        .await?;

        set_identifiers(
            manager,
            Credential::Table,
            Credential::HolderDidId,
            CredentialNew::HolderIdentifierId,
        )
        .await?;

        set_identifiers(
            manager,
            Proof::Table,
            Proof::HolderDidId,
            ProofNew::HolderIdentifierId,
        )
        .await?;

        set_identifiers(
            manager,
            Proof::Table,
            Proof::VerifierDidId,
            ProofNew::VerifierIdentifierId,
        )
        .await?;

        Ok(())
    }
}

#[derive(FromQueryResult)]
struct DidQueryResult {
    id: String,
    name: String,
    organisation_id: Option<String>,
    deactivated: bool,
    r#type: String,
    deleted_at: Option<OffsetDateTime>,
}

const BATCH_SIZE: usize = 100;

async fn create_identifiers_for_dids(
    manager: &SchemaManager<'_>,
    batch_no: usize,
) -> Result<bool, DbErr> {
    let db = manager.get_connection();
    let backend = db.get_database_backend();

    let did_query = Query::select()
        .columns([
            Did::Id,
            Did::Name,
            Did::OrganisationId,
            Did::Deactivated,
            Did::Type,
        ])
        .column(DidWithDeletedAt::DeletedAt)
        .from(Did::Table)
        .order_by(Did::Id, Order::Asc)
        .limit(BATCH_SIZE as u64)
        .offset((batch_no * BATCH_SIZE) as u64)
        .to_owned();

    let dids = DidQueryResult::find_by_statement(backend.build(&did_query))
        .all(db)
        .await?;

    if dids.is_empty() {
        return Ok(false);
    }

    let mut insert_statement = Query::insert()
        .into_table(Identifier::Table)
        .columns([
            Identifier::Id.into_iden(),
            Identifier::CreatedDate.into_iden(),
            Identifier::LastModified.into_iden(),
            Identifier::Name.into_iden(),
            Identifier::Type.into_iden(),
            Identifier::IsRemote.into_iden(),
            Identifier::Status.into_iden(),
            Identifier::OrganisationId.into_iden(),
            Identifier::DidId.into_iden(),
            IdentifierWithDeletedAt::DeletedAt.into_iden(),
        ])
        .to_owned();

    let now = OffsetDateTime::now_utc();
    for did in dids {
        insert_statement
            .values([
                did.id.to_owned().into(),
                now.into(),
                now.into(),
                did.name.into(),
                IdentifierType::Did.to_string().into(),
                (did.r#type == DidType::Remote.to_string()).into(),
                (if did.deactivated {
                    IdentifierStatus::Deactivated
                } else {
                    IdentifierStatus::Active
                })
                .to_string()
                .into(),
                did.organisation_id.into(),
                did.id.into(),
                did.deleted_at.map(|_| now).into(),
            ])
            .map_err(|e| DbErr::Migration(e.to_string()))?;
    }

    let res = db.execute(backend.build(&insert_statement)).await?;
    Ok(res.rows_affected() >= BATCH_SIZE as u64)
}

async fn set_identifiers(
    manager: &SchemaManager<'_>,
    table: impl IntoTableRef,
    source_column: impl IntoColumnRef,
    target_column: impl IntoIden,
) -> Result<(), DbErr> {
    let update_statement = Query::update()
        .table(table)
        .value(
            target_column,
            SimpleExpr::Column(source_column.into_column_ref()),
        )
        .to_owned();

    manager.exec_stmt(update_statement).await
}
