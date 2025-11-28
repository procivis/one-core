use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_len_null, string_null};

use crate::datatype::{timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::m20251105_121212_waa_and_wua_blobs::{
    BlobStorage, Certificate, Credential, CredentialSchema, Identifier, Interaction, Key,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DatabaseBackend::Sqlite {
            return Ok(());
        }

        let db = manager.get_connection();

        db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
            .await?;

        // Create new table with the correct columns
        manager
            .create_table(
                Table::create()
                    .table(CredentialNew::Table)
                    .col(uuid_char(Credential::Id).primary_key())
                    .col(timestamp(Credential::CreatedDate, manager))
                    .col(timestamp(Credential::LastModified, manager))
                    .col(timestamp_null(Credential::IssuanceDate, manager))
                    .col(timestamp_null(Credential::DeletedAt, manager))
                    .col(string(Credential::Protocol))
                    .col(uuid_char(Credential::CredentialSchemaId))
                    .col(uuid_char_null(Credential::InteractionId))
                    .col(uuid_char_null(Credential::KeyId))
                    .col(string(Credential::Role))
                    .col(string_len_null(Credential::RedirectUri, 1000))
                    .col(string(Credential::State))
                    .col(timestamp_null(Credential::SuspendEndDate, manager))
                    .col(uuid_char_null(Credential::HolderIdentifierId))
                    .col(uuid_char_null(Credential::IssuerIdentifierId))
                    .col(uuid_char_null(Credential::IssuerCertificateId))
                    .col(string_null(Credential::Profile))
                    .col(uuid_char_null(Credential::CredentialBlobId))
                    .col(uuid_char_null(Credential::WalletUnitAttestationBlobId))
                    .col(uuid_char_null(Credential::WalletAppAttestationBlobId))
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
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_credential_wallet_app_attestation_blob_id")
                            .from_tbl(CredentialNew::Table)
                            .from_col(Credential::WalletAppAttestationBlobId)
                            .to_tbl(BlobStorage::Table)
                            .to_col(BlobStorage::Id)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
                    .to_owned(),
            )
            .await?;

        // Copy data from old table to new table
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
            Credential::WalletAppAttestationBlobId,
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

        // Drop old table & rename new table
        manager
            .drop_table(Table::drop().table(Credential::Table).to_owned())
            .await?;

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

        manager
            .get_connection()
            .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum CredentialNew {
    Table,
}
