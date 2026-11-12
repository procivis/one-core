use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::integer_null;
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::datatype::uuid_char_null;
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{
    BlobStorage, Credential, CredentialSchema, FK_CREDENTIAL_WALLET_UNIT_ATTESTATION_BLOB,
};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const FK_CREDENTIAL_WALLET_KEY_ATTESTATION_BLOB: &str =
    "fk_credential_wallet_key_attestation_blob_id";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite can only do one alter operation at a time
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(integer_null(
                        CredentialSchemaNew::PreferredKeyStorageAttestationLifetime,
                    ))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(integer_null(
                        CredentialSchemaNew::PreferredInstanceAttestationLifetime,
                    ))
                    .to_owned(),
            )
            .await?;

        disable_foreign_key_checks(manager).await?;
        if manager.supported_db_type() == SupportedDbType::Sqlite {
            rename_wallet_key_attestation_blob_sqlite(manager).await?;
        } else {
            rename_wallet_key_attestation_blob(manager).await?;
        }
        enable_foreign_key_checks(manager).await?;

        Ok(())
    }
}

async fn rename_wallet_key_attestation_blob(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .drop_foreign_key(Alias::new(FK_CREDENTIAL_WALLET_UNIT_ATTESTATION_BLOB))
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .rename_column(
                    Credential::WalletUnitAttestationBlobId,
                    CredentialNew::WalletKeyAttestationBlobId,
                )
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .add_foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_WALLET_KEY_ATTESTATION_BLOB)
                        .from_tbl(Credential::Table)
                        .from_col(CredentialNew::WalletKeyAttestationBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull)
                        .get_foreign_key(),
                )
                .to_owned(),
        )
        .await
}

async fn rename_wallet_key_attestation_blob_sqlite(
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    manager
        .recreate_table(
            Table::recreate()
                .table(Credential::Table)
                .rename_column(
                    Credential::WalletUnitAttestationBlobId,
                    CredentialNew::WalletKeyAttestationBlobId,
                )
                .modify_column(uuid_char_null(CredentialNew::Format))
                .to_owned(),
        )
        .await?;

    Ok(())
}

#[derive(DeriveIden)]
enum CredentialSchemaNew {
    PreferredKeyStorageAttestationLifetime,
    PreferredInstanceAttestationLifetime,
}

#[derive(DeriveIden)]
enum CredentialNew {
    WalletKeyAttestationBlobId,
    Format,
}
