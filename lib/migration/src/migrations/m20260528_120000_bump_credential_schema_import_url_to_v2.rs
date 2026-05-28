use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::CredentialSchema;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Bumps the SSI schema URL version embedded in `credential_schema.imported_source_url`
// from `/ssi/schema/v1/<id>` to `/ssi/schema/v2/<id>`. See ONE-10025.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::update()
                    .table(CredentialSchema::Table)
                    .value(
                        CredentialSchema::ImportedSourceUrl,
                        Expr::cust(
                            "REPLACE(imported_source_url, '/ssi/schema/v1/', '/ssi/schema/v2/')",
                        ),
                    )
                    .and_where(
                        Expr::col(CredentialSchema::ImportedSourceUrl).like("%/ssi/schema/v1/%"),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
