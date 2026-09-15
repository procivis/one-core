use sea_orm::FromQueryResult;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, text};
use time::OffsetDateTime;

use crate::datatype::{timestamp, uuid_char, uuid_char_null};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::RevocationListEntry;
use crate::migrations::m20260720_091548_instance::{ManagedInstance, ManagedInstanceAttestedKey};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        managed_instance_attestation_table(manager).await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(RevocationListEntry::Table)
                    .value(RevocationListEntry::Type, "KA")
                    .cond_where(Expr::col(RevocationListEntry::Type).eq("WUA"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum ManagedInstanceAttestation {
    Table,
    Id,
    CreatedDate,
    LastModified,
    ExpirationDate,
    PublicKeyJwk,
    ManagedInstanceId,
    RevocationListEntryId,
    Type,
}

async fn managed_instance_attestation_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    disable_foreign_key_checks(manager).await?;

    manager
        .create_table(
            Table::create()
                .table(ManagedInstanceAttestation::Table)
                .if_not_exists()
                .col(uuid_char(ManagedInstanceAttestation::Id).primary_key())
                .col(timestamp(ManagedInstanceAttestation::CreatedDate, manager))
                .col(timestamp(ManagedInstanceAttestation::LastModified, manager))
                .col(timestamp(
                    ManagedInstanceAttestation::ExpirationDate,
                    manager,
                ))
                .col(text(ManagedInstanceAttestation::PublicKeyJwk))
                .col(uuid_char(ManagedInstanceAttestation::ManagedInstanceId))
                .col(uuid_char_null(
                    ManagedInstanceAttestation::RevocationListEntryId,
                ))
                .col(string(ManagedInstanceAttestation::Type))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-ManagedInstanceAttestation-ManagedInstanceId")
                        .from_tbl(ManagedInstanceAttestation::Table)
                        .from_col(ManagedInstanceAttestation::ManagedInstanceId)
                        .to_tbl(ManagedInstance::Table)
                        .to_col(ManagedInstance::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-ManagedInstanceAttestation-RevocationListEntryId")
                        .from_tbl(ManagedInstanceAttestation::Table)
                        .from_col(ManagedInstanceAttestation::RevocationListEntryId)
                        .to_tbl(RevocationListEntry::Table)
                        .to_col(RevocationListEntry::Id),
                )
                .to_owned(),
        )
        .await?;

    #[derive(FromQueryResult)]
    struct OldEntry {
        id: String,
        created_date: OffsetDateTime,
        last_modified: OffsetDateTime,
        expiration_date: OffsetDateTime,
        public_key_jwk: String,
        managed_instance_id: String,
        revocation_list_entry_id: Option<String>,
    }

    let db = manager.get_connection();
    let backend = db.get_database_backend();
    let old_entries = OldEntry::find_by_statement(
        backend.build(
            Query::select()
                .columns([
                    ManagedInstanceAttestedKey::Id,
                    ManagedInstanceAttestedKey::CreatedDate,
                    ManagedInstanceAttestedKey::LastModified,
                    ManagedInstanceAttestedKey::ExpirationDate,
                    ManagedInstanceAttestedKey::PublicKeyJwk,
                    ManagedInstanceAttestedKey::ManagedInstanceId,
                    ManagedInstanceAttestedKey::RevocationListEntryId,
                ])
                .from(ManagedInstanceAttestedKey::Table),
        ),
    )
    .all(db)
    .await?;

    for entry in old_entries {
        db.execute(
            backend.build(
                Query::insert()
                    .into_table(ManagedInstanceAttestation::Table)
                    .columns([
                        ManagedInstanceAttestation::Id,
                        ManagedInstanceAttestation::CreatedDate,
                        ManagedInstanceAttestation::LastModified,
                        ManagedInstanceAttestation::ExpirationDate,
                        ManagedInstanceAttestation::PublicKeyJwk,
                        ManagedInstanceAttestation::ManagedInstanceId,
                        ManagedInstanceAttestation::RevocationListEntryId,
                        ManagedInstanceAttestation::Type,
                    ])
                    .values([
                        entry.id.into(),
                        entry.created_date.into(),
                        entry.last_modified.into(),
                        entry.expiration_date.into(),
                        entry.public_key_jwk.into(),
                        entry.managed_instance_id.into(),
                        entry.revocation_list_entry_id.into(),
                        "KA".into(),
                    ])
                    .map_err(|e| DbErr::Migration(e.to_string()))?,
            ),
        )
        .await?;
    }

    manager
        .drop_table(
            Table::drop()
                .table(ManagedInstanceAttestedKey::Table)
                .to_owned(),
        )
        .await?;

    enable_foreign_key_checks(manager).await?;

    Ok(())
}
