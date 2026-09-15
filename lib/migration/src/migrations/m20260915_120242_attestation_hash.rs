use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string_null;

use crate::migrations::m20260915_023353_managed_instance_attestation::ManagedInstanceAttestation;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ManagedInstanceAttestation::Table)
                    .drop_column(ManagedInstanceAttestation::PublicKeyJwk)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ManagedInstanceAttestation::Table)
                    .add_column(string_null(
                        ManagedInstanceAttestationNew::AttestationContentHash,
                    ))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-ManagedInstanceAttestation-AttestationContentHash-Unique")
                    .table(ManagedInstanceAttestation::Table)
                    .col(ManagedInstanceAttestationNew::AttestationContentHash)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum ManagedInstanceAttestationNew {
    AttestationContentHash,
}
