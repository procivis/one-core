use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{Claim, Credential, CredentialSchema};
use crate::m20250814_120106_add_selectively_disclosable_column_to_claims::ClaimNew;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        // mark all claims of JSON_LD_BBSPLUS credentials as selectively disclosable
        let credential_ids = Query::select()
            .column((Credential::Table, Credential::Id))
            .from(Credential::Table)
            .inner_join(
                CredentialSchema::Table,
                Expr::col((CredentialSchema::Table, CredentialSchema::Id))
                    .equals((Credential::Table, Credential::CredentialSchemaId)),
            )
            .cond_where(Expr::col(CredentialSchema::Format).eq("JSON_LD_BBSPLUS"))
            .to_owned();

        db.execute(
            backend.build(
                Query::update()
                    .table(Claim::Table)
                    .value(ClaimNew::SelectivelyDisclosable, true)
                    .and_where(Expr::col(Claim::CredentialId).in_subquery(credential_ids)),
            ),
        )
        .await?;

        Ok(())
    }
}
