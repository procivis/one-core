use std::collections::{HashMap, HashSet};

use one_core::repository::error::DataLayerError;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, JoinType, QueryFilter, QueryOrder, QuerySelect,
    QueryTrait, RelationTrait,
};
use shared_types::{ClaimId, ClaimSchemaId, CredentialId};

use super::creation::CredentialToCreate;
use crate::entity::{claim, credential, credential_claim};
use crate::mapper::to_data_layer_error;

#[derive(Hash, PartialEq, Eq)]
pub(super) struct ClaimContents<'a> {
    schema_id: ClaimSchemaId,
    path: &'a str,
    value: Option<&'a [u8]>,
    selectively_disclosable: bool,
}

impl<'a> From<&'a claim::Model> for ClaimContents<'a> {
    fn from(claim: &'a claim::Model) -> Self {
        Self {
            schema_id: claim.claim_schema_id,
            path: &claim.path,
            value: claim.value.as_deref(),
            selectively_disclosable: claim.selectively_disclosable,
        }
    }
}

/// Lock existing parents in ID order so concurrent batches acquire exclusive locks
/// in the same order. Lock before inserting children to avoid parent FK lock upgrades.
/// New parents are private to this transaction and need no lookup.
async fn lock_existing_parents(
    connection: &impl ConnectionTrait,
    existing_parents: &[CredentialId],
) -> Result<(), DataLayerError> {
    if existing_parents.is_empty() {
        return Ok(());
    }
    credential::Entity::find()
        .select_only()
        .column(credential::Column::Id)
        .filter(credential::Column::Id.is_in(existing_parents.iter().copied()))
        .order_by_asc(credential::Column::Id)
        .lock_exclusive()
        .into_tuple::<CredentialId>()
        .all(connection)
        .await
        .map_err(to_data_layer_error)?;
    Ok(())
}

/// Build one lookup per batch parent and resolve every incoming item against it.
/// Load existing item claims once per parent; a new batch only uses its input claims.
/// Return each new claim row once, including claims on credentials without a parent.
pub(super) async fn reuse_batch_claims(
    connection: &impl ConnectionTrait,
    credentials: &mut [CredentialToCreate],
    stored: &HashMap<ClaimId, claim::Model>,
) -> Result<Vec<claim::Model>, DataLayerError> {
    let new_ids: HashSet<_> = credentials.iter().map(|item| item.credential.id).collect();
    let mut known_claim_ids: HashSet<_> = stored.keys().copied().collect();
    let mut new_claims = Vec::new();
    let mut groups: HashMap<_, Vec<_>> = HashMap::new();
    for item in credentials {
        if let Some(parent) = &item.credential.parent {
            groups.entry(parent.id()).or_default().push(item);
        } else {
            for claim in &item.claims {
                if known_claim_ids.insert(claim.id) {
                    new_claims.push(claim.clone());
                }
            }
        }
    }
    let existing_parents: Vec<_> = groups
        .keys()
        .copied()
        .filter(|id| !new_ids.contains(id))
        .collect();
    lock_existing_parents(connection, &existing_parents).await?;
    for (parent_id, items) in groups {
        let existing_claims = if new_ids.contains(&parent_id) {
            vec![]
        } else {
            load_batch_claims(connection, parent_id).await?
        };
        let mut canonical = HashMap::new();
        for claim in &existing_claims {
            known_claim_ids.insert(claim.id);
            canonical.entry(ClaimContents::from(claim)).or_insert((
                claim.id,
                claim.created_date,
                claim.last_modified,
            ));
        }
        for item in items {
            for claim in &mut item.claims {
                if let Some(&(id, created_date, last_modified)) =
                    canonical.get(&ClaimContents::from(&*claim))
                {
                    claim.id = id;
                    claim.created_date = created_date;
                    claim.last_modified = last_modified;
                } else {
                    canonical.insert(
                        ClaimContents::from(&*claim),
                        (claim.id, claim.created_date, claim.last_modified),
                    );
                }
                if known_claim_ids.insert(claim.id) {
                    new_claims.push(claim.clone());
                }
            }
        }
    }
    Ok(new_claims)
}

/// Load claims associated with this parent's items, including inactive items.
/// Order by creation date, then ID, so the canonical lookup keeps the oldest row
/// for each set of contents and breaks timestamp ties consistently.
/// Lock claim rows against cleanup until the new associations are committed.
async fn load_batch_claims(
    connection: &impl ConnectionTrait,
    parent_id: CredentialId,
) -> Result<Vec<claim::Model>, DataLayerError> {
    let claim_ids = credential_claim::Entity::find()
        .select_only()
        .column(credential_claim::Column::ClaimId)
        .join(
            JoinType::InnerJoin,
            credential_claim::Relation::Credential.def(),
        )
        .filter(credential::Column::ParentId.eq(parent_id))
        .into_query();
    claim::Entity::find()
        .filter(claim::Column::Id.in_subquery(claim_ids))
        .order_by_asc(claim::Column::CreatedDate)
        .order_by_asc(claim::Column::Id)
        .lock_shared()
        .all(connection)
        .await
        .map_err(to_data_layer_error)
}
