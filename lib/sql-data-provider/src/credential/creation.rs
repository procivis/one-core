//! Use a conservative 999-bind budget for SQLite compatibility on every backend.
//! Rounded chunk sizes leave headroom for additional columns or query filters.

use std::collections::{HashMap, HashSet};

use itertools::Itertools;
use one_core::model::credential::{Credential, CredentialRole, CredentialType};
use one_core::repository::error::DataLayerError;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
    QuerySelect, Set, TryIntoModel,
};
use shared_types::{ClaimId, CredentialId, CredentialSchemaId, OrganisationId};
use uuid::Uuid;

use super::claim_deduplication::{ClaimContents, reuse_batch_claims};
use super::mapper::request_to_active_model;
use crate::entity::{claim, credential, credential_claim, credential_schema};
use crate::mapper::to_data_layer_error;

pub(super) struct CredentialToCreate {
    pub credential: Credential,
    pub claims: Vec<claim::Model>,
}

/// Resolve lazy claims before taking database locks and reject duplicate credential IDs.
pub(super) async fn prepare_credentials(
    requests: Vec<Credential>,
) -> Result<Vec<CredentialToCreate>, DataLayerError> {
    let mut ids = HashSet::new();
    let mut credentials = Vec::with_capacity(requests.len());
    for credential in requests {
        if matches!(
            credential,
            Credential::Generic {
                role: CredentialRole::Verifier,
                ..
            } | Credential::Generic {
                role: CredentialRole::Issuer,
                r#type: CredentialType::Single,
                ..
            }
        ) {
            return Err(DataLayerError::MappingError);
        }
        if !ids.insert(credential.common().id) {
            return Err(DataLayerError::AlreadyExists);
        }
        let claims = credential
            .claims()
            .as_ref()
            .await?
            .iter()
            .cloned()
            .map(|claim| claim::ActiveModel::from(claim).try_into_model())
            .collect::<Result<_, _>>()
            .map_err(to_data_layer_error)?;
        credentials.push(CredentialToCreate { credential, claims });
    }
    Ok(credentials)
}

/// Resolve all claim identities once, then bulk-write the new rows and associations.
/// The caller's transaction covers every chunk, including all parent and item rows.
pub(super) async fn insert_credentials_with_claims(
    connection: &impl ConnectionTrait,
    mut credentials: Vec<CredentialToCreate>,
) -> Result<(), DataLayerError> {
    // Validate original IDs before deduplication can replace them with canonical IDs.
    let requested = distinct_claims(credentials.iter().flat_map(|item| &item.claims))?;
    let stored = load_claims_by_id(connection, &requested).await?;
    ensure_no_claim_conflicts(&requested, &stored)?;
    let new_claims = reuse_batch_claims(connection, &mut credentials, &stored).await?;
    ensure_paths_unique(&credentials)?;

    insert_credential_rows(connection, &credentials).await?;
    insert_new_claims(connection, new_claims).await?;
    insert_claim_associations(connection, &credentials).await
}

/// Collect each explicit ID once, rejecting contradictory payloads within the input.
fn distinct_claims<'a>(
    claims: impl Iterator<Item = &'a claim::Model>,
) -> Result<Vec<&'a claim::Model>, DataLayerError> {
    let mut distinct: HashMap<ClaimId, &claim::Model> = HashMap::new();
    for claim in claims {
        if let Some(previous) = distinct.get(&claim.id) {
            if ClaimContents::from(*previous) != ClaimContents::from(claim) {
                return Err(DataLayerError::AlreadyExists);
            }
        } else {
            distinct.insert(claim.id, claim);
        }
    }
    let mut claims: Vec<_> = distinct.into_values().collect();
    // Keep load_claims_by_id's lock order consistent across chunks; SQL ORDER BY
    // only orders the existing rows within each chunk.
    claims.sort_unstable_by_key(|claim| Uuid::from(claim.id));
    Ok(claims)
}

/// Lock existing explicit IDs against cleanup, using bounded, consistently ordered queries.
async fn load_claims_by_id(
    connection: &impl ConnectionTrait,
    claims: &[&claim::Model],
) -> Result<HashMap<ClaimId, claim::Model>, DataLayerError> {
    let mut stored = HashMap::new();
    // One bind per claim ID: 500 IDs use 500 binds.
    for chunk in claims.chunks(500) {
        stored.extend(
            claim::Entity::find()
                .filter(claim::Column::Id.is_in(chunk.iter().map(|claim| claim.id)))
                .order_by_asc(claim::Column::Id)
                .lock_shared()
                .all(connection)
                .await
                .map_err(to_data_layer_error)?
                .into_iter()
                .map(|claim| (claim.id, claim)),
        );
    }
    Ok(stored)
}

/// Existing IDs are immutable; timestamps do not participate in claim identity.
fn ensure_no_claim_conflicts(
    requested: &[&claim::Model],
    stored: &HashMap<ClaimId, claim::Model>,
) -> Result<(), DataLayerError> {
    if requested.iter().any(|claim| {
        stored
            .get(&claim.id)
            .is_some_and(|stored| ClaimContents::from(stored) != ClaimContents::from(*claim))
    }) {
        return Err(DataLayerError::AlreadyExists);
    }
    Ok(())
}

/// Every credential is new, so path uniqueness can be checked entirely in memory.
fn ensure_paths_unique(credentials: &[CredentialToCreate]) -> Result<(), DataLayerError> {
    for credential in credentials {
        let mut paths = HashMap::new();
        for claim in &credential.claims {
            if paths
                .insert(&claim.path, claim.id)
                .is_some_and(|id| id != claim.id)
            {
                return Err(DataLayerError::AlreadyExists);
            }
        }
    }
    Ok(())
}

/// Insert parents before their children, regardless of input order.
async fn insert_credential_rows(
    connection: &impl ConnectionTrait,
    credentials: &[CredentialToCreate],
) -> Result<(), DataLayerError> {
    let organisations = organisation_ids(connection, credentials).await?;
    let (parents, items): (Vec<_>, Vec<_>) = credentials
        .iter()
        .map(|item| &item.credential)
        .partition(|credential| credential.parent().is_none());
    for group in [parents, items] {
        // 30 columns per credential: 25 rows use at most 750 binds.
        for chunk in group.chunks(25) {
            let models = chunk
                .iter()
                .map(|credential| {
                    let organisation_id = organisations
                        .get(&credential.common().schema.id())
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "credential_schema",
                            id: credential.common().schema.id().to_string(),
                        })?;
                    Ok(request_to_active_model(credential, *organisation_id))
                })
                .collect::<Result<Vec<_>, DataLayerError>>()?;
            credential::Entity::insert_many(models)
                .exec_without_returning(connection)
                .await
                .map_err(to_data_layer_error)?;
        }
    }
    Ok(())
}

/// A credential belongs to the organisation of its schema. A credential read from the repository
/// holds the schema as a lazy relation, so read the organisation from the table, once per batch.
async fn organisation_ids(
    connection: &impl ConnectionTrait,
    credentials: &[CredentialToCreate],
) -> Result<HashMap<CredentialSchemaId, OrganisationId>, DataLayerError> {
    let schema_ids: HashSet<CredentialSchemaId> = credentials
        .iter()
        .map(|item| item.credential.common().schema.id())
        .collect();
    let rows: Vec<(CredentialSchemaId, OrganisationId)> = credential_schema::Entity::find()
        .select_only()
        .column(credential_schema::Column::Id)
        .column(credential_schema::Column::OrganisationId)
        .filter(credential_schema::Column::Id.is_in(schema_ids))
        .into_tuple()
        .all(connection)
        .await
        .map_err(to_data_layer_error)?;
    Ok(rows.into_iter().collect())
}

/// Insert the new claim rows returned by reuse. Unexpected ID conflicts fail the transaction.
async fn insert_new_claims(
    connection: &impl ConnectionTrait,
    claims: Vec<claim::Model>,
) -> Result<(), DataLayerError> {
    // Seven columns per claim: 100 rows use at most 700 binds.
    // Own each chunk before awaiting; itertools' chunk iterators borrow their source.
    let chunks: Vec<Vec<_>> = claims
        .into_iter()
        .chunks(100)
        .into_iter()
        .map(Iterator::collect)
        .collect();
    for chunk in chunks {
        claim::Entity::insert_many(chunk.into_iter().map(IntoActiveModel::into_active_model))
            .exec_without_returning(connection)
            .await
            .map_err(to_data_layer_error)?;
    }
    Ok(())
}

/// Insert the claim associations for each new credential.
async fn insert_claim_associations(
    connection: &impl ConnectionTrait,
    credentials: &[CredentialToCreate],
) -> Result<(), DataLayerError> {
    let associations: Vec<(CredentialId, ClaimId)> = credentials
        .iter()
        .flat_map(|item| {
            item.claims
                .iter()
                .map(|claim| (item.credential.common().id, claim.id))
        })
        .collect();
    // Two IDs per association: 400 rows use 800 binds.
    for chunk in associations.chunks(400) {
        credential_claim::Entity::insert_many(chunk.iter().map(|&(credential_id, claim_id)| {
            credential_claim::ActiveModel {
                credential_id: Set(credential_id),
                claim_id: Set(claim_id),
            }
        }))
        .exec_without_returning(connection)
        .await
        .map_err(to_data_layer_error)?;
    }
    Ok(())
}
