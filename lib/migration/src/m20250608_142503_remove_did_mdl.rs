use std::collections::HashSet;

use sea_orm::FromQueryResult;
use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{
    Claim, Credential, Did, Interaction, KeyDid, Proof, ProofClaim,
};
use crate::m20240130_105023_add_history::History;
use crate::m20241119_071036_add_revocation_format_type::RevocationList;
use crate::m20241120_164124_update_trust_anchor_and_entity_tables::TrustEntity;
use crate::m20250429_142011_add_identifier::{CredentialNew, Identifier, ProofNew};
use crate::m20250605_092053_drop_column_issuer_did_id_in_revocation_list::NewRevocationList;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(FromQueryResult)]
pub struct IdResult {
    pub id: String,
}

#[derive(FromQueryResult)]
struct KeyIdResult {
    key_id: String,
}

#[derive(FromQueryResult)]
struct IdAndInteractionIdResult {
    id: String,
    interaction_id: Option<String>,
}

#[derive(DeriveIden)]
enum ValidityCredential {
    Table,
    CredentialId,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mdl_dids = find_dids_with_method(manager, "MDL").await?;
        remove_dids_and_related_entities(manager, &mdl_dids).await
    }
}

async fn remove_dids_and_related_entities(
    manager: &SchemaManager<'_>,
    did_ids: &[String],
) -> Result<(), DbErr> {
    if did_ids.is_empty() {
        return Ok(());
    }

    let db = manager.get_connection();

    let mut ids_to_delete_history: HashSet<String> = HashSet::new();
    ids_to_delete_history.extend(did_ids.to_owned());
    let mut interaction_ids: HashSet<String> = HashSet::new();

    delete_trust_entities(db, did_ids, &mut ids_to_delete_history).await?;

    let identifier_ids = find_identifiers(db, did_ids).await?;
    delete_revocation_lists(db, &identifier_ids).await?;

    let key_ids_of_mdl_dids = find_key_ids_for_dids(db, did_ids).await?;

    delete_proofs(
        db,
        &identifier_ids,
        &key_ids_of_mdl_dids,
        &mut ids_to_delete_history,
        &mut interaction_ids,
    )
    .await?;
    delete_credentials(
        db,
        &identifier_ids,
        &key_ids_of_mdl_dids,
        &mut ids_to_delete_history,
        &mut interaction_ids,
    )
    .await?;
    delete_identifiers(
        db,
        &identifier_ids,
        &key_ids_of_mdl_dids,
        &mut ids_to_delete_history,
    )
    .await?;

    delete_key_did_relations(db, &key_ids_of_mdl_dids).await?;
    delete_dids(db, did_ids).await?;

    delete_interactions(db, &interaction_ids).await?;
    delete_history_events(db, &ids_to_delete_history).await?;

    Ok(())
}

pub(super) async fn find_dids_with_method(
    manager: &SchemaManager<'_>,
    method: &str,
) -> Result<Vec<String>, DbErr> {
    let db = manager.get_connection();

    let did_query = Query::select()
        .column(Did::Id)
        .from(Did::Table)
        .and_where(Expr::col(Did::Method).eq(method))
        .to_owned();

    let dids = IdResult::find_by_statement(db.get_database_backend().build(&did_query))
        .all(db)
        .await?;

    Ok(dids.into_iter().map(|did| did.id).collect())
}

pub async fn delete_revocation_lists(
    db: &SchemaManagerConnection<'_>,
    identifier_ids: &[String],
) -> Result<(), DbErr> {
    let delete_revocation_lists_query = Query::delete()
        .from_table(RevocationList::Table)
        .and_where(Expr::col(NewRevocationList::IssuerIdentifierId).is_in(identifier_ids))
        .to_owned();

    db.execute(
        db.get_database_backend()
            .build(&delete_revocation_lists_query),
    )
    .await?;

    Ok(())
}

async fn delete_trust_entities(
    db: &SchemaManagerConnection<'_>,
    did_ids: &[String],
    ids_to_delete: &mut HashSet<String>,
) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let trust_entity_query = Query::select()
        .column(TrustEntity::Id)
        .from(TrustEntity::Table)
        .and_where(Expr::col(TrustEntity::DidId).is_in(did_ids))
        .to_owned();

    let trust_entities = IdResult::find_by_statement(backend.build(&trust_entity_query))
        .all(db)
        .await?;

    let trust_entity_ids: Vec<String> = trust_entities.into_iter().map(|te| te.id).collect();
    if trust_entity_ids.is_empty() {
        return Ok(());
    }

    let delete_trust_query = Query::delete()
        .from_table(TrustEntity::Table)
        .and_where(Expr::col(TrustEntity::Id).is_in(&trust_entity_ids))
        .to_owned();

    db.execute(backend.build(&delete_trust_query)).await?;

    ids_to_delete.extend(trust_entity_ids);
    Ok(())
}

pub async fn find_identifiers(
    db: &SchemaManagerConnection<'_>,
    did_ids: &[String],
) -> Result<Vec<String>, DbErr> {
    let identifier_query = Query::select()
        .column(Identifier::Id)
        .from(Identifier::Table)
        .and_where(Expr::col(Identifier::DidId).is_in(did_ids))
        .to_owned();

    let identifiers_result =
        IdResult::find_by_statement(db.get_database_backend().build(&identifier_query))
            .all(db)
            .await?;

    Ok(identifiers_result.into_iter().map(|i| i.id).collect())
}

pub async fn delete_credentials(
    db: &SchemaManagerConnection<'_>,
    identifier_ids: &[String],
    key_ids_for_credential: &[String],
    ids_to_delete: &mut HashSet<String>,
    interaction_ids: &mut HashSet<String>,
) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let mut credential_ids_to_delete: HashSet<String> = HashSet::new();

    find_credentials_by_identifiers(
        db,
        identifier_ids,
        interaction_ids,
        &mut credential_ids_to_delete,
    )
    .await?;
    find_credentials_by_keys(
        db,
        key_ids_for_credential,
        interaction_ids,
        &mut credential_ids_to_delete,
    )
    .await?;

    if credential_ids_to_delete.is_empty() {
        return Ok(());
    }

    let delete_validity_credentials_query = Query::delete()
        .from_table(ValidityCredential::Table)
        .and_where(Expr::col(ValidityCredential::CredentialId).is_in(&credential_ids_to_delete))
        .to_owned();

    db.execute(backend.build(&delete_validity_credentials_query))
        .await?;

    ids_to_delete.extend(credential_ids_to_delete.iter().cloned());

    delete_proof_claims_for_credentials(db, &credential_ids_to_delete).await?;

    let delete_claims_query = Query::delete()
        .from_table(Claim::Table)
        .and_where(Expr::col(Claim::CredentialId).is_in(&credential_ids_to_delete))
        .to_owned();
    db.execute(backend.build(&delete_claims_query)).await?;

    let delete_credentials_query = Query::delete()
        .from_table(Credential::Table)
        .and_where(Expr::col(Credential::Id).is_in(&credential_ids_to_delete))
        .to_owned();
    db.execute(backend.build(&delete_credentials_query)).await?;

    Ok(())
}

async fn find_credentials_by_keys(
    db: &SchemaManagerConnection<'_>,
    key_ids_for_credential: &[String],
    interaction_ids: &mut HashSet<String>,
    credential_ids_to_delete: &mut HashSet<String>,
) -> Result<(), DbErr> {
    if !key_ids_for_credential.is_empty() {
        let credentials_by_key_id_query = Query::select()
            .column(Credential::Id)
            .column(CredentialNew::InteractionId)
            .from(Credential::Table)
            .and_where(Expr::col(Credential::KeyId).is_in(key_ids_for_credential))
            .to_owned();

        let credentials_by_key_id = IdAndInteractionIdResult::find_by_statement(
            db.get_database_backend()
                .build(&credentials_by_key_id_query),
        )
        .all(db)
        .await?;

        credentials_by_key_id.into_iter().for_each(|c| {
            credential_ids_to_delete.insert(c.id);
            if let Some(value) = &c.interaction_id {
                interaction_ids.insert(value.clone());
            }
        });
    }
    Ok(())
}

async fn find_credentials_by_identifiers(
    db: &SchemaManagerConnection<'_>,
    identifier_ids: &[String],
    interaction_ids: &mut HashSet<String>,
    credential_ids_to_delete: &mut HashSet<String>,
) -> Result<(), DbErr> {
    if !identifier_ids.is_empty() {
        let credential_query_by_identifier = Query::select()
            .column(Credential::Id)
            .column(CredentialNew::InteractionId)
            .from(Credential::Table)
            .and_where(
                Expr::col(CredentialNew::HolderIdentifierId)
                    .is_in(identifier_ids)
                    .or(Expr::col(CredentialNew::IssuerIdentifierId).is_in(identifier_ids)),
            )
            .to_owned();

        let credentials_by_identifier = IdAndInteractionIdResult::find_by_statement(
            db.get_database_backend()
                .build(&credential_query_by_identifier),
        )
        .all(db)
        .await?;

        credentials_by_identifier.into_iter().for_each(|c| {
            credential_ids_to_delete.insert(c.id);
            if let Some(value) = &c.interaction_id {
                interaction_ids.insert(value.clone());
            }
        });
    }
    Ok(())
}

pub async fn delete_proof_claims_for_credentials(
    db: &SchemaManagerConnection<'_>,
    credential_ids_to_delete: &HashSet<String>,
) -> Result<(), DbErr> {
    let backend = db.get_database_backend();

    let claims_query_all = Query::select()
        .column(Claim::Id)
        .from(Claim::Table)
        .and_where(Expr::col(Claim::CredentialId).is_in(credential_ids_to_delete))
        .to_owned();

    let claims_results = IdResult::find_by_statement(backend.build(&claims_query_all))
        .all(db)
        .await?;

    let all_claim_ids: HashSet<String> = claims_results.into_iter().map(|c| c.id).collect();

    if !all_claim_ids.is_empty() {
        let delete_proof_claims_query = Query::delete()
            .from_table(ProofClaim::Table)
            .and_where(Expr::col(ProofClaim::ClaimId).is_in(&all_claim_ids))
            .to_owned();
        db.execute(backend.build(&delete_proof_claims_query))
            .await?;
    }
    Ok(())
}

pub async fn delete_proofs(
    db: &SchemaManagerConnection<'_>,
    identifier_ids: &[String],
    key_ids_for_verifier: &[String],
    ids_to_delete: &mut HashSet<String>,
    interaction_ids: &mut HashSet<String>,
) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let mut proof_ids_to_delete: HashSet<String> = HashSet::new();

    if !identifier_ids.is_empty() {
        let proof_query_by_identifier = Query::select()
            .column(Proof::Id)
            .column(ProofNew::InteractionId)
            .from(Proof::Table)
            .and_where(
                Expr::col(ProofNew::HolderIdentifierId)
                    .is_in(identifier_ids)
                    .or(Expr::col(ProofNew::VerifierIdentifierId).is_in(identifier_ids)),
            )
            .to_owned();

        let proofs_by_identifier =
            IdAndInteractionIdResult::find_by_statement(backend.build(&proof_query_by_identifier))
                .all(db)
                .await?;

        proofs_by_identifier.into_iter().for_each(|p| {
            proof_ids_to_delete.insert(p.id);
            if let Some(interaction_id_val) = p.interaction_id {
                interaction_ids.insert(interaction_id_val);
            }
        });
    }

    if !key_ids_for_verifier.is_empty() {
        let proofs_by_verfier_key_query = Query::select()
            .column(Proof::Id)
            .column(ProofNew::InteractionId)
            .from(Proof::Table)
            .and_where(Expr::col(ProofNew::VerifierKeyId).is_in(key_ids_for_verifier))
            .to_owned();

        let proofs_by_verifier_key = IdAndInteractionIdResult::find_by_statement(
            backend.build(&proofs_by_verfier_key_query),
        )
        .all(db)
        .await?;

        proofs_by_verifier_key.into_iter().for_each(|p| {
            proof_ids_to_delete.insert(p.id);
            if let Some(interaction_id_val) = p.interaction_id {
                interaction_ids.insert(interaction_id_val);
            }
        });
    }

    if proof_ids_to_delete.is_empty() {
        return Ok(());
    }

    let delete_proof_claims_query = Query::delete()
        .from_table(ProofClaim::Table)
        .and_where(Expr::col(ProofClaim::ProofId).is_in(&proof_ids_to_delete))
        .to_owned();
    db.execute(backend.build(&delete_proof_claims_query))
        .await?;

    let delete_proofs_query = Query::delete()
        .from_table(Proof::Table)
        .and_where(Expr::col(Proof::Id).is_in(&proof_ids_to_delete))
        .to_owned();
    db.execute(backend.build(&delete_proofs_query)).await?;

    ids_to_delete.extend(proof_ids_to_delete.iter().cloned());
    Ok(())
}

pub async fn delete_interactions(
    db: &SchemaManagerConnection<'_>,
    interaction_ids: &HashSet<String>,
) -> Result<(), DbErr> {
    if interaction_ids.is_empty() {
        return Ok(());
    }

    let delete_interactions_query = Query::delete()
        .from_table(Interaction::Table)
        .and_where(Expr::col(Interaction::Id).is_in(interaction_ids))
        .to_owned();

    let statement = db.get_database_backend().build(&delete_interactions_query);
    db.execute(statement).await?;

    Ok(())
}

pub async fn delete_identifiers(
    db: &SchemaManagerConnection<'_>,
    identifier_ids: &[String],
    key_ids_of_mdl_dids: &[String],
    ids_to_delete_history: &mut HashSet<String>,
) -> Result<(), DbErr> {
    let backend = db.get_database_backend();

    let mut identifier_ids_to_delete: HashSet<String> = HashSet::new();
    identifier_ids_to_delete.extend(identifier_ids.iter().cloned());

    if !key_ids_of_mdl_dids.is_empty() {
        let identifiers_by_key_query = Query::select()
            .column(Identifier::Id)
            .from(Identifier::Table)
            .and_where(Expr::col(Identifier::KeyId).is_in(key_ids_of_mdl_dids))
            .to_owned();

        let result = IdResult::find_by_statement(backend.build(&identifiers_by_key_query))
            .all(db)
            .await?
            .into_iter()
            .map(|i| i.id)
            .collect::<Vec<_>>();

        identifier_ids_to_delete.extend(result);
    }

    if identifier_ids_to_delete.is_empty() {
        return Ok(());
    }

    let delete_query = Query::delete()
        .from_table(Identifier::Table)
        .and_where(Expr::col(Identifier::Id).is_in(&identifier_ids_to_delete))
        .to_owned();
    db.execute(backend.build(&delete_query)).await?;

    ids_to_delete_history.extend(identifier_ids_to_delete);
    Ok(())
}

pub async fn delete_key_did_relations(
    db: &SchemaManagerConnection<'_>,
    key_ids: &[String],
) -> Result<(), DbErr> {
    if key_ids.is_empty() {
        return Ok(());
    }

    let backend = db.get_database_backend();

    let delete_key_did_query = Query::delete()
        .from_table(KeyDid::Table)
        .and_where(Expr::col(KeyDid::KeyId).is_in(key_ids))
        .to_owned();
    db.execute(backend.build(&delete_key_did_query)).await?;

    Ok(())
}

pub async fn delete_dids(
    db: &SchemaManagerConnection<'_>,
    did_ids: &[String],
) -> Result<(), DbErr> {
    let query = Query::delete()
        .from_table(Did::Table)
        .and_where(Expr::col(Did::Id).is_in(did_ids))
        .to_owned();
    db.execute(db.get_database_backend().build(&query)).await?;

    Ok(())
}

pub async fn delete_history_events(
    db: &SchemaManagerConnection<'_>,
    ids_to_delete: &HashSet<String>,
) -> Result<(), DbErr> {
    let query = Query::delete()
        .from_table(History::Table)
        .and_where(Expr::col(History::EntityId).is_in(ids_to_delete))
        .to_owned();
    db.execute(db.get_database_backend().build(&query)).await?;

    Ok(())
}

pub async fn find_key_ids_for_dids(
    db: &SchemaManagerConnection<'_>,
    did_ids: &[String],
) -> Result<Vec<String>, DbErr> {
    if did_ids.is_empty() {
        return Ok(Vec::new());
    }

    let query = Query::select()
        .column(KeyDid::KeyId)
        .from(KeyDid::Table)
        .and_where(Expr::col(KeyDid::DidId).is_in(did_ids))
        .to_owned();

    Ok(
        KeyIdResult::find_by_statement(db.get_database_backend().build(&query))
            .all(db)
            .await?
            .into_iter()
            .map(|kd| kd.key_id)
            .collect(),
    )
}
