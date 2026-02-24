use sea_orm::DbErr;
use sea_orm::sea_query::{Query, SimpleExpr};
use sea_orm_migration::SchemaManager;

use crate::batch_utils::{delete, get_ids, get_ids_batched};
use crate::m20240110_000001_initial::{
    Claim, CredentialSchema, Interaction, Proof, ProofClaim, ProofSchema,
};
use crate::m20240305_081435_proof_input_schema::ProofInputSchema;
use crate::m20250721_102954_creation_of_blob_storage::BlobStorage;
use crate::m20251030_110836_revocation_list_entry::RevocationListEntry;
use crate::m20251219_062738_claim_schema_table::ClaimSchema;
use crate::m20260108_051341_proof_input_claim_schema_table::ProofInputClaimSchema;
use crate::m20260108_062033_validity_credential_table::ValidityCredential;
use crate::m20260206_032338_waa_to_wia::Credential;

pub(crate) async fn hard_delete_credential_schemas_and_related(
    manager: &SchemaManager<'_>,
    credential_schema_filter: SimpleExpr,
) -> Result<(), DbErr> {
    let credential_schemas = get_ids(
        manager,
        Query::select()
            .column(CredentialSchema::Id)
            .from(CredentialSchema::Table)
            .and_where(credential_schema_filter),
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
            crate::m20250729_114143_proof_blob::Proof::ProofBlobId,
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
    .await
}
