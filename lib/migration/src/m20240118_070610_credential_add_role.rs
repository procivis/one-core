use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::Credential;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(
                        ColumnDef::new(CredentialNew::Role)
                            .default(CredentialRole::Issuer.to_string())
                            .enumeration(
                                CredentialRole::Table,
                                [
                                    CredentialRole::Holder,
                                    CredentialRole::Issuer,
                                    CredentialRole::Verifier,
                                ],
                            )
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum CredentialNew {
    Role,
}

#[derive(Iden)]
pub enum CredentialRole {
    Table,
    #[iden = "HOLDER"]
    Holder,
    #[iden = "ISSUER"]
    Issuer,
    #[iden = "VERIFIER"]
    Verifier,
}
