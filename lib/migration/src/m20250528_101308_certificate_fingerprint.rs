use sea_orm_migration::prelude::*;

use crate::m20250512_110852_certificate::Certificate;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Certificate::Table)
                    .add_column(
                        ColumnDef::new(CertificateWithFingerprint::Fingerprint)
                            .string()
                            .not_null()
                            .default("N/A"),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum CertificateWithFingerprint {
    Fingerprint,
}
