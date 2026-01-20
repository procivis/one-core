use std::collections::HashSet;

use sea_orm::{DatabaseBackend, FromQueryResult};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::{ColumnDefExt, timestamp, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::Credential;
use crate::m20250429_142011_add_identifier::Identifier;
use crate::m20250512_110852_certificate::Certificate;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        match backend {
            DatabaseBackend::Postgres => {
                return Ok(());
            }
            DatabaseBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(RevocationListEntry::Table)
                            // make `index` nullable
                            .modify_column(unsigned_null(RevocationListEntry::Index))
                            // add `serial`
                            .add_column(var_binary_null(RevocationListEntry::Serial, 20))
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(RevocationList::Table)
                            .drop_foreign_key(Alias::new("fk_revocation_list_issuer_identifier_id"))
                            .to_owned(),
                    )
                    .await?;

                manager
                    .drop_index(
                        Index::drop()
                            .table(RevocationList::Table)
                            .name("index-IssuerIdentifierId-Purpose-Type-Unique")
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(RevocationList::Table)
                            .add_column(string_len_null(RevocationList::IssuerCertificateId, 36))
                            .rename_column(
                                RevocationList::Credentials,
                                RevocationList::FormattedList,
                            )
                            .add_foreign_key(
                                ForeignKey::create()
                                    .name("fk_revocation_list_issuer_certificate_id")
                                    .from_tbl(RevocationList::Table)
                                    .from_col(RevocationList::IssuerCertificateId)
                                    .to_tbl(Certificate::Table)
                                    .to_col(Certificate::Id)
                                    .on_delete(ForeignKeyAction::Restrict)
                                    .get_foreign_key(),
                            )
                            .add_foreign_key(
                                ForeignKey::create()
                                    .name("fk_revocation_list_issuer_identifier_id")
                                    .from_tbl(RevocationList::Table)
                                    .from_col(RevocationList::IssuerIdentifierId)
                                    .to_tbl(Identifier::Table)
                                    .to_col(Identifier::Id)
                                    .on_delete(ForeignKeyAction::Restrict)
                                    .get_foreign_key(),
                            )
                            .to_owned(),
                    )
                    .await?;

                db.execute_unprepared("ALTER TABLE revocation_list ADD COLUMN issuer_certificate_id_materialized VARCHAR(36) AS (COALESCE(issuer_certificate_id, 'no_certificate')) PERSISTENT;")
                    .await?;
                db.execute_unprepared("CREATE UNIQUE INDEX `index-IssuerIdentifierId-IssuerCertificateId-Purpose-Type-Unique` ON revocation_list(`issuer_identifier_id`,`issuer_certificate_id_materialized`,`purpose`,`type`);")
                    .await?;
            }
            DatabaseBackend::Sqlite => {
                sqlite_migration(manager).await?;
            }
        }

        manager
            .create_index(
                Index::create()
                    .name("index-RevocationList-Serial-Unique")
                    .unique()
                    .table(RevocationListEntry::Table)
                    .col(RevocationListEntry::RevocationListId)
                    .col(RevocationListEntry::Serial)
                    .to_owned(),
            )
            .await?;

        // fill issuer_certificate_id's
        let certificate_issuer_identifier_ids = IssuerIdentifierIdResult::find_by_statement(
            backend.build(
                Query::select()
                    .column(RevocationList::IssuerIdentifierId)
                    .from(RevocationList::Table)
                    .join(
                        JoinType::InnerJoin,
                        Identifier::Table,
                        Expr::col(RevocationList::IssuerIdentifierId)
                            .eq(Expr::col((Identifier::Table, Identifier::Id))),
                    )
                    .and_where(Expr::col((Identifier::Table, Identifier::Type)).eq("CERTIFICATE")),
            ),
        )
        .all(db)
        .await?;

        let certificate_issuer_identifier_ids = HashSet::<String>::from_iter(
            certificate_issuer_identifier_ids
                .into_iter()
                .map(|id| id.issuer_identifier_id),
        );

        for certificate_issuer_identifier_id in certificate_issuer_identifier_ids {
            let certificate_id = CertificateIdResult::find_by_statement(
                backend.build(
                    Query::select()
                        .column(Certificate::Id)
                        .from(Certificate::Table)
                        .and_where(
                            Expr::col(Certificate::IdentifierId)
                                .eq(Expr::val(&certificate_issuer_identifier_id)),
                        )
                        .and_where(Expr::col(Certificate::State).eq("ACTIVE")),
                ),
            )
            .one(db)
            .await?;

            if let Some(CertificateIdResult { id: certificate_id }) = certificate_id {
                manager
                    .exec_stmt(
                        Query::update()
                            .table(RevocationList::Table)
                            .value(RevocationList::IssuerCertificateId, certificate_id)
                            .and_where(
                                Expr::col(RevocationList::IssuerIdentifierId)
                                    .eq(Expr::val(certificate_issuer_identifier_id)),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
        }

        Ok(())
    }
}

#[derive(FromQueryResult)]
struct IssuerIdentifierIdResult {
    issuer_identifier_id: String,
}

#[derive(FromQueryResult)]
struct CertificateIdResult {
    id: String,
}

#[derive(DeriveIden)]
enum RevocationListNew {
    Table,
}

#[derive(DeriveIden, Clone)]
pub enum RevocationList {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Credentials,
    IssuerIdentifierId,
    Purpose,
    Format,
    Type,
    IssuerCertificateId,
    FormattedList,
}

#[derive(DeriveIden)]
enum RevocationListEntryNew {
    Table,
}

#[derive(DeriveIden, Clone)]
enum RevocationListEntry {
    Table,
    Id,
    CreatedDate,
    RevocationListId,
    Index,
    CredentialId,
    Status,
    Type,
    SignatureType,
    Serial,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new tables with the correct columns
    manager
        .create_table(
            Table::create()
                .table(RevocationListNew::Table)
                .col(uuid_char(RevocationList::Id).primary_key())
                .col(timestamp(RevocationList::CreatedDate, manager))
                .col(timestamp(RevocationList::LastModified, manager))
                .col(
                    ColumnDef::new(RevocationList::FormattedList)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(uuid_char(RevocationList::IssuerIdentifierId))
                .col(string(RevocationList::Purpose))
                .col(string(RevocationList::Format))
                .col(string(RevocationList::Type))
                .col(uuid_char_null(RevocationList::IssuerCertificateId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk_revocation_list_issuer_identifier_id")
                        .from_tbl(RevocationList::Table)
                        .from_col(RevocationList::IssuerIdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk_revocation_list_issuer_certificate_id")
                        .from_tbl(RevocationList::Table)
                        .from_col(RevocationList::IssuerCertificateId)
                        .to_tbl(Certificate::Table)
                        .to_col(Certificate::Id),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_table(
            Table::create()
                .table(RevocationListEntryNew::Table)
                .col(uuid_char(RevocationListEntry::Id).primary_key())
                .col(timestamp(RevocationListEntry::CreatedDate, manager))
                .col(uuid_char(RevocationListEntry::RevocationListId))
                .col(unsigned_null(RevocationListEntry::Index))
                .col(uuid_char_null(RevocationListEntry::CredentialId))
                .col(string(RevocationListEntry::Status))
                .col(string(RevocationListEntry::Type))
                .col(string_null(RevocationListEntry::SignatureType))
                .col(var_binary_null(RevocationListEntry::Serial, 20))
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

    // Copy data from old table to new table
    let shared_copied_columns = &[
        RevocationList::Id,
        RevocationList::CreatedDate,
        RevocationList::LastModified,
        RevocationList::IssuerIdentifierId,
        RevocationList::Purpose,
        RevocationList::Format,
        RevocationList::Type,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(RevocationListNew::Table)
                .columns(
                    [
                        [RevocationList::FormattedList].as_slice(),
                        shared_copied_columns.as_slice(),
                    ]
                    .concat(),
                )
                .select_from(
                    Query::select()
                        .from(RevocationList::Table)
                        .columns(
                            [
                                [RevocationList::Credentials].as_slice(),
                                shared_copied_columns.as_slice(),
                            ]
                            .concat(),
                        )
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        RevocationListEntry::Id,
        RevocationListEntry::CreatedDate,
        RevocationListEntry::RevocationListId,
        RevocationListEntry::Index,
        RevocationListEntry::CredentialId,
        RevocationListEntry::Status,
        RevocationListEntry::Type,
        RevocationListEntry::SignatureType,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(RevocationListEntryNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(RevocationListEntry::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(RevocationList::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(RevocationListNew::Table, RevocationList::Table)
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(RevocationListEntry::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(RevocationListEntryNew::Table, RevocationListEntry::Table)
                .to_owned(),
        )
        .await?;

    // recreate indexes
    db.execute_unprepared("CREATE UNIQUE INDEX `index-IssuerIdentifierId-IssuerCertificateId-Purpose-Type-Unique` ON revocation_list(`issuer_identifier_id`,COALESCE(issuer_certificate_id, 'no_certificate'),`purpose`,`type`);").await?;

    manager
        .create_index(
            Index::create()
                .name("index-RevocationList-Index-Unique")
                .unique()
                .table(RevocationListEntry::Table)
                .col(RevocationListEntry::RevocationListId)
                .col(RevocationListEntry::Index)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
