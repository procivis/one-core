use sea_orm::{DatabaseBackend, DbBackend};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Postgres {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(
                        ColumnDef::new(Credential::WalletAppAttestationBlobId)
                            .char_len(36)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        if manager.get_database_backend() != DatabaseBackend::Sqlite {
            manager
                .alter_table(
                    Table::alter()
                        .table(Credential::Table)
                        .add_foreign_key(
                            TableForeignKey::new()
                                .name("fk_credential_wallet_app_attestation_blob_id")
                                .from_tbl(Credential::Table)
                                .from_col(Credential::WalletAppAttestationBlobId)
                                .to_tbl(BlobStorage::Table)
                                .to_col(BlobStorage::Id),
                        )
                        .to_owned(),
                )
                .await?;
        }

        manager
            .exec_stmt(
                Query::update()
                    .table(Credential::Table)
                    .value(
                        Credential::WalletAppAttestationBlobId,
                        Expr::col((Credential::Table, Credential::WalletUnitAttestationBlobId)),
                    )
                    .value(Credential::WalletUnitAttestationBlobId, Keyword::Null)
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(BlobStorage::Table)
                    .value(BlobStorage::Type, "WALLET_APP_ATTESTATION")
                    .cond_where(
                        Expr::col((BlobStorage::Table, BlobStorage::Type))
                            .eq("WALLET_UNIT_ATTESTATION"),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum BlobStorage {
    Table,
    Id,
    Type,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Credential {
    Table,
    WalletUnitAttestationBlobId,
    WalletAppAttestationBlobId,
}
