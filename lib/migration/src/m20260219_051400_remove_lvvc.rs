use std::collections::HashSet;

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

        let credential_schemas = get_ids(
            manager,
            Query::select()
                .column(CredentialSchema::Id)
                .from(CredentialSchema::Table)
                .and_where(Expr::col(CredentialSchema::RevocationMethod).eq("LVVC")),
        )
        .await?;

        let claim_schemas = get_ids_batched(
            ClaimSchema::Table,
            ClaimSchema::Id,
            ClaimSchema::CredentialSchemaId,
            &credential_schemas,
            manager,
        )
        .await?;

        let credentials = get_ids_batched(
            Credential::Table,
            Credential::Id,
            Credential::CredentialSchemaId,
            &credential_schemas,
            manager,
        )
        .await?;

        let claims = [
            get_ids_batched(
                Claim::Table,
                Claim::Id,
                Claim::CredentialId,
                &credentials,
                manager,
            )
            .await?,
            get_ids_batched(
                Claim::Table,
                Claim::Id,
                Claim::ClaimSchemaId,
                &claim_schemas,
                manager,
            )
            .await?,
        ]
        .concat();

        let proof_schemas = get_ids_batched(
            ProofInputSchema::Table,
            ProofInputSchema::ProofSchema,
            ProofInputSchema::CredentialSchema,
            &credential_schemas,
            manager,
        )
        .await?;

        let proofs = [
            get_ids_batched(
                Proof::Table,
                Proof::Id,
                Proof::ProofSchemaId,
                &proof_schemas,
                manager,
            )
            .await?,
            get_ids_batched(
                ProofClaim::Table,
                ProofClaim::ProofId,
                ProofClaim::ClaimId,
                &claims,
                manager,
            )
            .await?,
        ]
        .concat();

        let interactions = [
            get_ids_batched(
                Credential::Table,
                Credential::InteractionId,
                Credential::Id,
                &credentials,
                manager,
            )
            .await?,
            get_ids_batched(
                Proof::Table,
                Proof::InteractionId,
                Proof::Id,
                &proofs,
                manager,
            )
            .await?,
        ]
        .concat();

        let blobs = [
            get_ids_batched(
                Credential::Table,
                Credential::CredentialBlobId,
                Credential::Id,
                &credentials,
                manager,
            )
            .await?,
            get_ids_batched(
                Credential::Table,
                Credential::WalletInstanceAttestationBlobId,
                Credential::Id,
                &credentials,
                manager,
            )
            .await?,
            get_ids_batched(
                Credential::Table,
                Credential::WalletUnitAttestationBlobId,
                Credential::Id,
                &credentials,
                manager,
            )
            .await?,
            get_ids_batched(
                Proof::Table,
                ProofWithBlob::ProofBlobId,
                Proof::Id,
                &proofs,
                manager,
            )
            .await?,
        ]
        .concat();

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

async fn get_ids_batched(
    table: impl IntoTableRef,
    id_column: impl IntoColumnRef,
    linked_entity_id_column: impl IntoColumnRef,
    linked_entities: &[String],
    manager: &SchemaManager<'_>,
) -> Result<Vec<String>, DbErr> {
    let table = table.into_table_ref();
    let id_column = id_column.into_column_ref();
    let linked_entity_id_column = linked_entity_id_column.into_column_ref();

    let ids = unique_ids(linked_entities);
    let mut result = vec![];
    for chunk in ids.chunks(1000) {
        result.extend(
            get_ids(
                manager,
                Query::select()
                    .expr_as(Expr::col(id_column.to_owned()), "id")
                    .from(table.to_owned())
                    .and_where(Expr::col(linked_entity_id_column.to_owned()).is_in(chunk))
                    .and_where(Expr::col(id_column.to_owned()).is_not_null()),
            )
            .await?,
        );
    }
    Ok(result)
}

async fn get_ids(
    manager: &SchemaManager<'_>,
    query: &SelectStatement,
) -> Result<Vec<String>, DbErr> {
    let backend = manager.get_database_backend();
    let db = manager.get_connection();

    Ok(IdResult::find_by_statement(backend.build(query))
        .all(db)
        .await?
        .into_iter()
        .map(|res| res.id)
        .collect())
}

async fn delete(
    table: impl IntoTableRef,
    column: impl IntoColumnRef,
    entity_ids: &[String],
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    let table = table.into_table_ref();
    let column = column.into_column_ref();

    let ids = unique_ids(entity_ids);
    for chunk in ids.chunks(1000) {
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(table.to_owned())
                    .and_where(Expr::col(column.to_owned()).is_in(chunk))
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}

fn unique_ids(input: &[String]) -> Vec<String> {
    let ids: HashSet<&String> = HashSet::from_iter(input);
    ids.into_iter().map(ToString::to_string).collect()
}
