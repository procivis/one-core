use sea_orm::{DatabaseBackend, FromQueryResult};
use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{
    Claim, CredentialSchema, Interaction, Proof, ProofClaim, ProofSchema,
};
use crate::m20240305_081435_proof_input_schema::ProofInputSchema;
use crate::m20250721_102954_creation_of_blob_storage::BlobStorage;
use crate::m20250729_114143_proof_blob::Proof as ProofWithBlob;
use crate::m20251030_110836_revocation_list_entry::RevocationListEntry;
use crate::m20251219_062738_claim_schema_table::ClaimSchema;
use crate::m20260108_051341_proof_input_claim_schema_table::ProofInputClaimSchema;
use crate::m20260108_062033_validity_credential_table::ValidityCredential;
use crate::m20260206_032338_waa_to_wia::Credential;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        if backend == DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(ProofInputSchema::Table)
                    .drop_column(ProofInputSchema::ValidityConstraint)
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        let get_ids = async |query: &SelectStatement| -> Result<Vec<String>, DbErr> {
            Ok(IdResult::find_by_statement(backend.build(query))
                .all(db)
                .await?
                .into_iter()
                .map(|res| res.id)
                .collect())
        };

        let get_ids_from_multiple =
            async |queries: &[&SelectStatement]| -> Result<Vec<String>, DbErr> {
                let mut result = vec![];
                for query in queries {
                    result.extend(get_ids(query).await?);
                }
                Ok(result)
            };

        let credential_schemas = get_ids(
            Query::select()
                .column(CredentialSchema::Id)
                .from(CredentialSchema::Table)
                .and_where(Expr::col(CredentialSchema::RevocationMethod).eq("LVVC")),
        )
        .await?;

        let claim_schemas = get_ids(
            Query::select()
                .column(ClaimSchema::Id)
                .from(ClaimSchema::Table)
                .and_where(Expr::col(ClaimSchema::CredentialSchemaId).is_in(&credential_schemas)),
        )
        .await?;

        let credentials = get_ids(
            Query::select()
                .column(Credential::Id)
                .from(Credential::Table)
                .and_where(Expr::col(Credential::CredentialSchemaId).is_in(&credential_schemas)),
        )
        .await?;

        let claims = get_ids(
            Query::select()
                .column(Claim::Id)
                .from(Claim::Table)
                .cond_where(
                    Expr::col(Claim::CredentialId)
                        .is_in(&credentials)
                        .or(Expr::col(Claim::ClaimSchemaId).is_in(&claim_schemas)),
                ),
        )
        .await?;

        let proof_schemas = get_ids(
            Query::select()
                .expr_as(Expr::col(ProofInputSchema::ProofSchema), "id")
                .from(ProofInputSchema::Table)
                .and_where(
                    Expr::col(ProofInputSchema::CredentialSchema).is_in(&credential_schemas),
                ),
        )
        .await?;

        let proofs = get_ids_from_multiple(&[
            Query::select()
                .column(Proof::Id)
                .from(Proof::Table)
                .and_where(Expr::col(Proof::ProofSchemaId).is_in(&proof_schemas)),
            Query::select()
                .expr_as(Expr::col(ProofClaim::ProofId), "id")
                .from(ProofClaim::Table)
                .and_where(Expr::col(ProofClaim::ClaimId).is_in(&claims)),
        ])
        .await?;

        let interactions = get_ids_from_multiple(&[
            Query::select()
                .expr_as(Expr::col(Credential::InteractionId), "id")
                .from(Credential::Table)
                .and_where(Expr::col(Credential::Id).is_in(&credentials))
                .and_where(Expr::col(Credential::InteractionId).is_not_null()),
            Query::select()
                .expr_as(Expr::col(Proof::InteractionId), "id")
                .from(Proof::Table)
                .and_where(Expr::col(Proof::Id).is_in(&proofs))
                .and_where(Expr::col(Proof::InteractionId).is_not_null()),
        ])
        .await?;

        let blobs = get_ids_from_multiple(&[
            Query::select()
                .expr_as(Expr::col(Credential::CredentialBlobId), "id")
                .from(Credential::Table)
                .and_where(Expr::col(Credential::Id).is_in(&credentials))
                .and_where(Expr::col(Credential::CredentialBlobId).is_not_null()),
            Query::select()
                .expr_as(Expr::col(Credential::WalletInstanceAttestationBlobId), "id")
                .from(Credential::Table)
                .and_where(Expr::col(Credential::Id).is_in(&credentials))
                .and_where(Expr::col(Credential::WalletInstanceAttestationBlobId).is_not_null()),
            Query::select()
                .expr_as(Expr::col(Credential::WalletUnitAttestationBlobId), "id")
                .from(Credential::Table)
                .and_where(Expr::col(Credential::Id).is_in(&credentials))
                .and_where(Expr::col(Credential::WalletUnitAttestationBlobId).is_not_null()),
            Query::select()
                .expr_as(Expr::col(ProofWithBlob::ProofBlobId), "id")
                .from(Proof::Table)
                .and_where(Expr::col(Proof::Id).is_in(&proofs))
                .and_where(Expr::col(ProofWithBlob::ProofBlobId).is_not_null()),
        ])
        .await?;

        delete(
            ProofInputClaimSchema::Table,
            ProofInputClaimSchema::ClaimSchemaId,
            &claim_schemas,
            manager,
        )
        .await?;

        delete(
            ProofInputSchema::Table,
            ProofInputSchema::CredentialSchema,
            &credential_schemas,
            manager,
        )
        .await?;

        delete(ProofClaim::Table, ProofClaim::ProofId, &proofs, manager).await?;

        delete(
            ValidityCredential::Table,
            ValidityCredential::CredentialId,
            &credentials,
            manager,
        )
        .await?;

        delete(
            RevocationListEntry::Table,
            RevocationListEntry::CredentialId,
            &credentials,
            manager,
        )
        .await?;

        delete(Claim::Table, Claim::Id, &claims, manager).await?;

        delete(Credential::Table, Credential::Id, &credentials, manager).await?;
        delete(Proof::Table, Proof::Id, &proofs, manager).await?;
        delete(Interaction::Table, Interaction::Id, &interactions, manager).await?;
        delete(BlobStorage::Table, BlobStorage::Id, &blobs, manager).await?;

        delete(ProofSchema::Table, ProofSchema::Id, &proof_schemas, manager).await?;

        delete(ClaimSchema::Table, ClaimSchema::Id, &claim_schemas, manager).await?;

        delete(
            CredentialSchema::Table,
            CredentialSchema::Id,
            &credential_schemas,
            manager,
        )
        .await?;

        Ok(())
    }
}

#[derive(FromQueryResult)]
struct IdResult {
    pub id: String,
}

async fn delete(
    table: impl IntoTableRef,
    column: impl IntoColumnRef,
    entity_ids: &[String],
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    manager
        .exec_stmt(
            Query::delete()
                .from_table(table)
                .and_where(Expr::col(column).is_in(entity_ids))
                .to_owned(),
        )
        .await
}
