use sea_orm::{DatabaseBackend, FromQueryResult};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string;

use crate::datatype::{ColumnDefExt, timestamp, uuid_char};
use crate::legacy_migrations::m20240110_000001_initial::Proof;
use crate::legacy_migrations::m20250729_114143_proof_blob::Proof as ProofWithBlobId;
use crate::legacy_migrations::m20251105_121212_waa_and_wua_blobs::Credential;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres => {}
            DatabaseBackend::MySql => {
                // change type
                manager
                    .alter_table(
                        Table::alter()
                            .table(BlobStorage::Table)
                            .modify_column(string(BlobStorage::Type))
                            .to_owned(),
                    )
                    .await?;
            }
            DatabaseBackend::Sqlite => sqlite_migration(manager).await?,
            other => {
                return Err(DbErr::BackendNotSupported {
                    db: other.as_str(),
                    ctx: "migration",
                });
            }
        };

        Ok(())
    }
}

#[derive(Iden)]
enum BlobStorageNew {
    Table,
}

#[derive(Clone, Iden)]
enum BlobStorage {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Value,
    Type,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    // blob references get cleared when the original table gets deleted,
    // recover the entries after blob table modifications
    #[derive(FromQueryResult, Debug)]
    struct CredentialWithBlobs {
        id: String,
        credential_blob_id: Option<String>,
        wallet_app_attestation_blob_id: Option<String>,
        wallet_unit_attestation_blob_id: Option<String>,
    }
    let credentials = CredentialWithBlobs::find_by_statement(
        manager.get_database_backend().build(
            Query::select()
                .from(Credential::Table)
                .columns([
                    Credential::Id,
                    Credential::CredentialBlobId,
                    Credential::WalletAppAttestationBlobId,
                    Credential::WalletUnitAttestationBlobId,
                ])
                .cond_where(
                    Cond::any()
                        .add(Expr::col(Credential::CredentialBlobId).is_not_null())
                        .add(Expr::col(Credential::WalletAppAttestationBlobId).is_not_null())
                        .add(Expr::col(Credential::WalletUnitAttestationBlobId).is_not_null()),
                ),
        ),
    )
    .all(db)
    .await?;

    #[derive(FromQueryResult, Debug)]
    struct ProofWithBlob {
        id: String,
        proof_blob_id: Option<String>,
    }
    let proofs = ProofWithBlob::find_by_statement(
        manager.get_database_backend().build(
            Query::select()
                .from(Proof::Table)
                .column(Proof::Id)
                .column(ProofWithBlobId::ProofBlobId)
                .cond_where(Expr::col(ProofWithBlobId::ProofBlobId).is_not_null()),
        ),
    )
    .all(db)
    .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(BlobStorageNew::Table)
                .col(uuid_char(BlobStorage::Id).primary_key())
                .col(timestamp(BlobStorage::CreatedDate, manager))
                .col(timestamp(BlobStorage::LastModified, manager))
                .col(
                    ColumnDef::new(BlobStorage::Value)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(string(BlobStorage::Type))
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        BlobStorage::Id,
        BlobStorage::CreatedDate,
        BlobStorage::LastModified,
        BlobStorage::Value,
        BlobStorage::Type,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(BlobStorageNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(BlobStorage::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(BlobStorage::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(BlobStorageNew::Table, BlobStorage::Table)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    for credential in credentials {
        manager
            .exec_stmt(
                Query::update()
                    .table(Credential::Table)
                    .value(Credential::CredentialBlobId, credential.credential_blob_id)
                    .value(
                        Credential::WalletAppAttestationBlobId,
                        credential.wallet_app_attestation_blob_id,
                    )
                    .value(
                        Credential::WalletUnitAttestationBlobId,
                        credential.wallet_unit_attestation_blob_id,
                    )
                    .cond_where(Expr::col(Credential::Id).eq(&credential.id))
                    .to_owned(),
            )
            .await?;
    }

    for proof in proofs {
        manager
            .exec_stmt(
                Query::update()
                    .table(Proof::Table)
                    .value(ProofWithBlobId::ProofBlobId, proof.proof_blob_id)
                    .cond_where(Expr::col(Proof::Id).eq(&proof.id))
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}
