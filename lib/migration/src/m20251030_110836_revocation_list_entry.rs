use sea_orm::{DatabaseBackend, FromQueryResult};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string_len_null, string_null};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::datatype::{ColumnDefExt, timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::{CredentialSchema, Interaction, Key, RevocationList};
use crate::m20250429_142011_add_identifier::Identifier;
use crate::m20250512_110852_certificate::Certificate;
use crate::m20250605_085443_add_identifier_id_field_to_revocation_list::RevocationList as RevocationListWithIdentifierId;
use crate::m20250721_102954_creation_of_blob_storage::BlobStorage;
use crate::m20251001_103610_adds_wua_column_to_credential::Credential;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_REVOCATION_LIST_INDEX_INDEX: &str = "index-RevocationList-Index-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        if backend == DatabaseBackend::Postgres {
            return Ok(());
        }

        let db = manager.get_connection();

        manager
            .create_table(
                Table::create()
                    .table(RevocationListEntry::Table)
                    .col(
                        ColumnDef::new(RevocationListEntry::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RevocationListEntry::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RevocationListEntry::RevocationListId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RevocationListEntry::Index)
                            .unsigned()
                            .not_null(),
                    )
                    .col(ColumnDef::new(RevocationListEntry::CredentialId).char_len(36))
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-RevocationListEntry-RevocationListId")
                            .from_tbl(RevocationListEntry::Table)
                            .from_col(RevocationListEntry::RevocationListId)
                            .to_tbl(RevocationList::Table)
                            .to_col(RevocationList::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-RevocationListEntry-CredentialId")
                            .from_tbl(RevocationListEntry::Table)
                            .from_col(RevocationListEntry::CredentialId)
                            .to_tbl(Credential::Table)
                            .to_col(Credential::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_REVOCATION_LIST_INDEX_INDEX)
                    .unique()
                    .table(RevocationListEntry::Table)
                    .col(RevocationListEntry::RevocationListId)
                    .col(RevocationListEntry::Index)
                    .to_owned(),
            )
            .await?;

        let stored_lists = StoredRevocationList::find_by_statement(
            backend.build(
                Query::select()
                    .column(RevocationList::Id)
                    .column(RevocationListWithIdentifierId::IssuerIdentifierId)
                    .from(RevocationList::Table),
            ),
        )
        .all(db)
        .await?;

        for stored_list in stored_lists {
            let credentials = LinkedCredential::find_by_statement(
                backend.build(
                    Query::select()
                        .columns([
                            Credential::Id,
                            Credential::CreatedDate,
                            Credential::Role,
                            Credential::CredentialSchemaId,
                        ])
                        .from(Credential::Table)
                        .and_where(
                            Expr::col(Credential::IssuerIdentifierId)
                                .eq(stored_list.issuer_identifier_id),
                        )
                        .order_by(Credential::CreatedDate, Order::Asc),
                ),
            )
            .all(db)
            .await?;

            if credentials.is_empty() {
                continue;
            }

            let mut insert_entries = Query::insert()
                .into_table(RevocationListEntry::Table)
                .columns([
                    RevocationListEntry::Id,
                    RevocationListEntry::CreatedDate,
                    RevocationListEntry::RevocationListId,
                    RevocationListEntry::Index,
                    RevocationListEntry::CredentialId,
                ])
                .to_owned();

            let mut entries_to_insert = false;
            for (index, credential) in credentials.into_iter().enumerate() {
                if credential.role != "ISSUER"
                    || !has_status_list(&credential.credential_schema_id, manager).await?
                {
                    continue;
                }

                let entry_id = Uuid::new_v4().to_string();
                insert_entries
                    .values([
                        entry_id.into(),
                        credential.created_date.into(),
                        (&stored_list.id).into(),
                        index.to_string().into(),
                        credential.id.into(),
                    ])
                    .map_err(|e| DbErr::Migration(e.to_string()))?;
                entries_to_insert = true;
            }

            if entries_to_insert {
                db.execute(backend.build(&insert_entries)).await?;
            }
        }

        match &backend {
            DatabaseBackend::Postgres => {}
            DatabaseBackend::MySql => {
                let foreign_key_drop_statement = ForeignKey::drop()
                    .name("fk-Credential-RevocationListId")
                    .table(Credential::Table)
                    .to_owned();

                db.execute(backend.build(&foreign_key_drop_statement))
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(Credential::Table)
                            .drop_column(Credential::RevocationListId)
                            .to_owned(),
                    )
                    .await?;
            }
            DatabaseBackend::Sqlite => sqlite_migration_drop_revocation_list_key(manager).await?,
        };

        Ok(())
    }
}

#[derive(Iden)]
pub enum RevocationListEntry {
    Table,
    Id,
    CreatedDate,
    RevocationListId,
    Index,
    CredentialId,
}

async fn sqlite_migration_drop_revocation_list_key(
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    let db = manager.get_connection();

    // Disable foreign keys for SQLite
    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the `RevocationListId` column removed
    manager
        .create_table(
            Table::create()
                .table(CredentialNew::Table)
                .col(uuid_char(Credential::Id).primary_key())
                .col(timestamp(Credential::CreatedDate, manager))
                .col(timestamp(Credential::LastModified, manager))
                .col(timestamp_null(Credential::IssuanceDate, manager))
                .col(timestamp_null(Credential::DeletedAt, manager))
                .col(string_null(Credential::Protocol))
                .col(uuid_char(Credential::CredentialSchemaId))
                .col(uuid_char_null(Credential::InteractionId))
                .col(uuid_char_null(Credential::KeyId))
                .col(string_null(Credential::Role))
                .col(string_len_null(Credential::RedirectUri, 1000))
                .col(string_null(Credential::State))
                .col(timestamp_null(Credential::SuspendEndDate, manager))
                .col(uuid_char_null(Credential::HolderIdentifierId))
                .col(uuid_char_null(Credential::IssuerIdentifierId))
                .col(uuid_char_null(Credential::IssuerCertificateId))
                .col(string_null(Credential::Profile))
                .col(uuid_char_null(Credential::CredentialBlobId))
                .col(uuid_char_null(Credential::WalletUnitAttestationBlobId))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Credential-CredentialSchemaId")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::CredentialSchemaId)
                        .to_tbl(CredentialSchema::Table)
                        .to_col(CredentialSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Credential-InteractionId")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::InteractionId)
                        .to_tbl(Interaction::Table)
                        .to_col(Interaction::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Credential-KeyId")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-credential-issuer_certificate")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::IssuerCertificateId)
                        .to_tbl(Certificate::Table)
                        .to_col(Certificate::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_credential_blob_id")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::CredentialBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_holder_identifier")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::HolderIdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_issuer_identifier")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::IssuerIdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_wallet_unit_attestation_blob_id")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::WalletUnitAttestationBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .take(),
        )
        .await?;

    let copied_columns = vec![
        Credential::Id,
        Credential::CreatedDate,
        Credential::LastModified,
        Credential::IssuanceDate,
        Credential::DeletedAt,
        Credential::Protocol,
        Credential::CredentialSchemaId,
        Credential::InteractionId,
        Credential::KeyId,
        Credential::Role,
        Credential::RedirectUri,
        Credential::State,
        Credential::SuspendEndDate,
        Credential::HolderIdentifierId,
        Credential::IssuerIdentifierId,
        Credential::IssuerCertificateId,
        Credential::Profile,
        Credential::CredentialBlobId,
        Credential::WalletUnitAttestationBlobId,
    ];

    manager
        .exec_stmt(
            Query::insert()
                .into_table(CredentialNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(Credential::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table
    manager
        .drop_table(Table::drop().table(Credential::Table).to_owned())
        .await?;

    // Rename new table to original name
    manager
        .rename_table(
            Table::rename()
                .table(CredentialNew::Table, Credential::Table)
                .to_owned(),
        )
        .await?;

    // Recreate indexes
    manager
        .create_index(
            Index::create()
                .name("idx_credential_list")
                .table(Credential::Table)
                .col(Credential::DeletedAt)
                .col(Credential::Role)
                .col(Credential::CreatedDate)
                .col(Credential::Id)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Credential-CreatedDate")
                .table(Credential::Table)
                .col(Credential::CreatedDate)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Credential-DeletedAt")
                .table(Credential::Table)
                .col(Credential::DeletedAt)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Credential-Role")
                .table(Credential::Table)
                .col(Credential::Role)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Credential-State")
                .table(Credential::Table)
                .col(Credential::State)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Credential-SuspendEndDate")
                .table(Credential::Table)
                .col(Credential::SuspendEndDate)
                .to_owned(),
        )
        .await?;

    // Re-enable foreign keys for SQLite
    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

#[derive(DeriveIden)]
enum CredentialNew {
    Table,
}

#[derive(FromQueryResult, Eq, PartialEq, Hash)]
pub struct StoredRevocationList {
    pub id: String,
    pub issuer_identifier_id: String,
}

#[derive(FromQueryResult, Eq, PartialEq, Hash)]
pub struct LinkedCredential {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub role: String,
    pub credential_schema_id: String,
}

#[derive(FromQueryResult, Eq, PartialEq, Hash)]
pub struct LinkedCredentialSchema {
    pub revocation_method: String,
}

async fn has_status_list(
    credential_schema_id: &str,
    manager: &SchemaManager<'_>,
) -> Result<bool, DbErr> {
    let backend = manager.get_database_backend();
    let db = manager.get_connection();

    let schema = LinkedCredentialSchema::find_by_statement(
        backend.build(
            Query::select()
                .column(CredentialSchema::RevocationMethod)
                .from(CredentialSchema::Table)
                .and_where(Expr::col(CredentialSchema::Id).eq(credential_schema_id)),
        ),
    )
    .one(db)
    .await?;

    Ok(schema.is_some_and(|schema| {
        matches!(
            schema.revocation_method.as_str(),
            "TOKENSTATUSLIST" | "BITSTRINGSTATUSLIST"
        )
    }))
}
