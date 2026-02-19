use sea_orm::{DbBackend, FromQueryResult};
use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{Did, Key, KeyDid, Proof, ProofClaim};
use crate::m20240130_105023_add_history::History;
use crate::m20240611_110000_introduce_path_and_array::Claim;
use crate::m20250429_142011_add_identifier::{CredentialNew, Identifier, ProofNew};
use crate::m20250721_102954_creation_of_blob_storage::BlobStorage;
use crate::m20250729_114143_proof_blob;
use crate::m20251030_110836_revocation_list_entry::RevocationListEntry;
use crate::m20251105_121212_waa_and_wua_blobs::Credential;
use crate::m20260108_062033_validity_credential_table::ValidityCredential;
use crate::m20260119_100418_crl_revocation::RevocationList;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(FromQueryResult)]
pub struct IdResult {
    pub id: String,
}

impl From<&IdResult> for SimpleExpr {
    fn from(val: &IdResult) -> Self {
        val.id.as_str().into()
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        // Find entities to delete
        // Note: there are no certificates or wallet unit (attestations) for dilithium keys, so these
        // are ignored.

        let keys_to_delete = IdResult::find_by_statement(
            backend.build(
                Query::select()
                    .column(Key::Id)
                    .from(Key::Table)
                    .and_where(Expr::col(Key::KeyType).eq("DILITHIUM")),
            ),
        )
        .all(db)
        .await?;
        let dids_to_delete = IdResult::find_by_statement(
            backend.build(
                Query::select()
                    .column((Did::Table, Did::Id))
                    .from(Did::Table)
                    .inner_join(
                        KeyDid::Table,
                        Expr::col((KeyDid::Table, KeyDid::DidId)).equals((Did::Table, Did::Id)),
                    )
                    .and_where(Expr::col(KeyDid::KeyId).is_in(&keys_to_delete)),
            ),
        )
        .all(db)
        .await?;
        let identifiers_to_delete =
            find_identifiers_to_delete(db, backend, &keys_to_delete, &dids_to_delete).await?;
        let revocation_lists_to_delete = IdResult::find_by_statement(
            backend.build(
                Query::select()
                    .column(RevocationList::Id)
                    .from(RevocationList::Table)
                    .and_where(
                        Expr::col(RevocationList::IssuerIdentifierId).is_in(&identifiers_to_delete),
                    ),
            ),
        )
        .all(db)
        .await?;
        let proofs_to_delete = IdResult::find_by_statement(
            backend.build(
                Query::select()
                    .column(Proof::Id)
                    .from(Proof::Table)
                    .and_where(
                        Expr::col(ProofNew::VerifierIdentifierId)
                            .is_in(&identifiers_to_delete)
                            .or(Expr::col(ProofNew::VerifierKeyId).is_in(keys_to_delete.iter())),
                    ),
            ),
        )
        .all(db)
        .await?;
        let credentials_to_delete = find_credentials_to_delete(
            &keys_to_delete,
            &identifiers_to_delete,
            &proofs_to_delete,
            manager,
        )
        .await?;

        // Delete entities in the right order
        delete_proofs(&proofs_to_delete, manager).await?;
        delete_revocation_lists(&revocation_lists_to_delete, manager).await?;
        delete_credentials(&credentials_to_delete, manager).await?;
        delete_empty_accepted_proofs(manager).await?;
        delete_identifiers(&identifiers_to_delete, manager).await?;
        delete_dids(&dids_to_delete, manager).await?;
        delete_keys(&keys_to_delete, manager).await?;

        Ok(())
    }
}

async fn find_identifiers_to_delete(
    db: &SchemaManagerConnection<'_>,
    backend: DbBackend,
    keys_to_delete: &[IdResult],
    dids_to_delete: &[IdResult],
) -> Result<Vec<IdResult>, DbErr> {
    let mut identifiers_to_delete = IdResult::find_by_statement(
        backend.build(
            Query::select()
                .column(Identifier::Id)
                .from(Identifier::Table)
                .and_where(Expr::col(Identifier::KeyId).is_in(keys_to_delete.iter())),
        ),
    )
    .all(db)
    .await?;
    identifiers_to_delete.extend(
        IdResult::find_by_statement(
            backend.build(
                Query::select()
                    .column(Identifier::Id)
                    .from(Identifier::Table)
                    .and_where(Expr::col(Identifier::DidId).is_in(dids_to_delete.iter())),
            ),
        )
        .all(db)
        .await?,
    );
    Ok(identifiers_to_delete)
}

async fn find_credentials_to_delete(
    keys_to_delete: &[IdResult],
    identifiers_to_delete: &[IdResult],
    proofs_to_delete: &[IdResult],
    manager: &SchemaManager<'_>,
) -> Result<Vec<IdResult>, DbErr> {
    let db = manager.get_connection();
    let backend = db.get_database_backend();
    let mut credentials_to_delete = IdResult::find_by_statement(
        backend.build(
            Query::select()
                .column(Credential::Id)
                .from(Credential::Table)
                .and_where(
                    Expr::col(CredentialNew::IssuerIdentifierId)
                        .is_in(identifiers_to_delete.iter())
                        .or(Expr::col(CredentialNew::HolderIdentifierId)
                            .is_in(identifiers_to_delete.iter()))
                        .or(Expr::col(Credential::KeyId).is_in(keys_to_delete.iter())),
                ),
        ),
    )
    .all(db)
    .await?;
    credentials_to_delete.extend(
        IdResult::find_by_statement(
            backend.build(
                Query::select()
                    .column((Credential::Table, Credential::Id))
                    .from(Credential::Table)
                    .inner_join(
                        Claim::Table,
                        Expr::col((Claim::Table, Claim::CredentialId))
                            .equals((Credential::Table, Credential::Id)),
                    )
                    .inner_join(
                        ProofClaim::Table,
                        Expr::col((ProofClaim::Table, ProofClaim::ClaimId))
                            .equals((Claim::Table, Claim::Id)),
                    )
                    .and_where(Expr::col(ProofClaim::ProofId).is_in(proofs_to_delete.iter())),
            ),
        )
        .all(db)
        .await?,
    );

    Ok(credentials_to_delete)
}

async fn delete_proofs(ids: &[IdResult], manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    delete(ProofClaim::Table, ProofClaim::ProofId, ids, manager).await?;
    delete(Proof::Table, Proof::Id, ids, manager).await?;
    delete_proof_blobs(ids, manager).await?;
    delete(History::Table, History::EntityId, ids, manager).await
}

async fn delete_revocation_lists(
    ids: &[IdResult],
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    delete(
        RevocationListEntry::Table,
        RevocationListEntry::RevocationListId,
        ids,
        manager,
    )
    .await?;
    delete(RevocationList::Table, RevocationList::Id, ids, manager).await
}

async fn delete_credentials(ids: &[IdResult], manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Delete proof claims for affected credentials first.
    // ACCEPTED proofs without proof claims will be deleted later.
    let claim_ids = IdResult::find_by_statement(
        manager.get_database_backend().build(
            Query::select()
                .column(Claim::Id)
                .from(Claim::Table)
                .and_where(Expr::col(Claim::CredentialId).is_in(ids.iter())),
        ),
    )
    .all(manager.get_connection())
    .await?;
    delete(ProofClaim::Table, ProofClaim::ClaimId, &claim_ids, manager).await?;
    delete(Claim::Table, Claim::CredentialId, ids, manager).await?;
    delete(
        ValidityCredential::Table,
        ValidityCredential::CredentialId,
        ids,
        manager,
    )
    .await?;
    delete(
        RevocationListEntry::Table,
        RevocationListEntry::CredentialId,
        ids,
        manager,
    )
    .await?;
    delete(History::Table, History::EntityId, ids, manager).await?;
    delete(Credential::Table, Credential::Id, ids, manager).await?;
    delete_credential_blobs(ids, Credential::CredentialBlobId, manager).await?;
    delete_credential_blobs(ids, Credential::WalletUnitAttestationBlobId, manager).await?;
    delete_credential_blobs(ids, Credential::WalletAppAttestationBlobId, manager).await
}

async fn delete_empty_accepted_proofs(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    use crate::m20250508_072524_change_enum_to_varchar::Proof as StateProof;
    let ids = IdResult::find_by_statement(
        manager.get_database_backend().build(
            Query::select()
                .column(Proof::Id)
                .from(Proof::Table)
                .and_where(Expr::col(StateProof::State).eq("ACCEPTED"))
                .and_where(
                    Expr::col(Proof::Id)
                        .in_subquery(
                            Query::select()
                                .distinct()
                                .column(ProofClaim::ProofId)
                                .from(ProofClaim::Table)
                                .to_owned(),
                        )
                        .not(),
                ),
        ),
    )
    .all(manager.get_connection())
    .await?;
    delete_proofs(&ids, manager).await
}

async fn delete_identifiers(ids: &[IdResult], manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    delete(History::Table, History::EntityId, ids, manager).await?;
    delete(Identifier::Table, Identifier::Id, ids, manager).await
}

async fn delete_dids(ids: &[IdResult], manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    delete(History::Table, History::EntityId, ids, manager).await?;
    delete(KeyDid::Table, KeyDid::DidId, ids, manager).await?;
    delete(Did::Table, Did::Id, ids, manager).await
}

async fn delete_keys(ids: &[IdResult], manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    delete(History::Table, History::EntityId, ids, manager).await?;
    delete(Key::Table, Key::Id, ids, manager).await
}

async fn delete_proof_blobs(
    proof_ids: &[IdResult],
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    use m20250729_114143_proof_blob::Proof as BlobProof;
    manager
        .exec_stmt(
            Query::delete()
                .from_table(BlobStorage::Table)
                .and_where(
                    Expr::col(BlobStorage::Id).in_subquery(
                        Query::select()
                            .column(BlobProof::ProofBlobId)
                            .from(Proof::Table)
                            .and_where(Expr::col(Proof::Id).is_in(proof_ids.iter()))
                            .to_owned(),
                    ),
                )
                .to_owned(),
        )
        .await
}

async fn delete_credential_blobs(
    credential_ids: &[IdResult],
    blob_column: impl IntoColumnRef,
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    manager
        .exec_stmt(
            Query::delete()
                .from_table(BlobStorage::Table)
                .and_where(
                    Expr::col(BlobStorage::Id).in_subquery(
                        Query::select()
                            .column(blob_column)
                            .from(Credential::Table)
                            .and_where(Expr::col(Credential::Id).is_in(credential_ids.iter()))
                            .to_owned(),
                    ),
                )
                .to_owned(),
        )
        .await
}

async fn delete(
    table: impl IntoTableRef,
    column: impl IntoColumnRef,
    entity_ids: &[IdResult],
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
