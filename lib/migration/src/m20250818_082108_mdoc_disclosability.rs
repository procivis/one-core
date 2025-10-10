use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{Credential, CredentialSchema};
use crate::m20240611_110000_introduce_path_and_array::Claim;
use crate::m20250814_120106_add_selectively_disclosable_column_to_claims::ClaimNew;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        let mdoc_credential_ids = Query::select()
            .column((Credential::Table, Credential::Id))
            .from(Credential::Table)
            .inner_join(
                CredentialSchema::Table,
                Expr::col((CredentialSchema::Table, CredentialSchema::Id))
                    .equals((Credential::Table, Credential::CredentialSchemaId)),
            )
            .cond_where(Expr::col(CredentialSchema::Format).eq("MDOC"))
            .to_owned();

        // mark top 2 levels of claims of MDOC credentials as selectively disclosable
        db.execute(
            backend.build(
                Query::update()
                    .table(Claim::Table)
                    .value(ClaimNew::SelectivelyDisclosable, true)
                    .and_where(Expr::col(Claim::Path).not_like("%/%/%"))
                    .and_where(Expr::col(Claim::CredentialId).in_subquery(mdoc_credential_ids)),
            ),
        )
        .await?;

        Ok(())
    }
}
