//! Common code for status list types

use std::collections::HashSet;
use std::future::Future;

use futures::FutureExt;
use one_crypto::utilities::get_rng;
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngExt};
use serde::{Deserialize, Serialize};
use shared_types::{
    CertificateId, IdentifierId, RevocationListEntryId, RevocationListId, RevocationMethodId,
};

use super::RevocationError;
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntryFilterValue, RevocationListPurpose,
};
use crate::proto::transaction_manager::TransactionManager;
use crate::repository::revocation_list_repository::RevocationListRepository;

#[derive(Serialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct StatusListSizeParams<const MINIMUM_CAPACITY: usize> {
    /// (maximum) number of entries on the generated status list
    ///
    /// Beware that increasing `capacity` breaks the already generated lists,
    /// as they are assumed to be generated with this size
    pub capacity: usize,
    /// assignment block size, when allocating indexes on the status-list,
    /// a random block is selected (to optimize for parallel execution).
    /// When a block is filled, a new status list is started.
    ///
    /// `capacity` must be a multiple of `block_size`
    ///
    /// This approach leads to statistically filling each status list
    /// to a certain amount, before starting another:
    ///
    /// | capacity | block_size | avg. fill |
    /// |---------:|-----------:|----------:|
    /// |   131072 |         16 |      32 % |
    /// |   131072 |         32 |      49 % |
    /// |   131072 |         64 |      63 % |
    /// |   131072 |        128 |      74 % |
    /// |   131072 |        256 |      82 % |
    /// |   131072 |        512 |      88 % |
    /// |  1048576 |         16 |      27 % |
    /// |  1048576 |         32 |      43 % |
    /// |  1048576 |         64 |      58 % |
    /// |  1048576 |        128 |      70 % |
    /// |  1048576 |        256 |      79 % |
    /// |  1048576 |        512 |      86 % |
    ///
    /// so, when growing `capacity`, it makes sense to grow `block_size` as well
    pub block_size: usize,
}

impl<'de, const MINIMUM_CAPACITY: usize> Deserialize<'de>
    for StatusListSizeParams<MINIMUM_CAPACITY>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Params {
            capacity: Option<usize>,
            block_size: Option<usize>,
        }
        let deserialized = Params::deserialize(deserializer)?;
        let capacity = deserialized.capacity.unwrap_or(131072);
        let block_size = deserialized.block_size.unwrap_or(128);

        if capacity < MINIMUM_CAPACITY {
            return Err(serde::de::Error::custom(format!(
                "Invalid capacity: {capacity}"
            )));
        }

        if !capacity.is_multiple_of(block_size) {
            return Err(serde::de::Error::custom(format!(
                "Invalid blockSize: {block_size} (for capacity: {capacity})"
            )));
        }

        Ok(Self {
            capacity,
            block_size,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct AllocatedIndexEntry {
    pub list_id: RevocationListId,
    pub entry_id: RevocationListEntryId,
    pub index: usize,
}

/// Common logic for selecting and allocating a (random) index on a status list
/// If no list exists or the latest is "full" already, a new list gets created.
/// Beware that this does not update the formatted list as it is expected
/// that the free indices are already marked as Valid/Active entries,
/// and the size of the status lists does not change
#[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
#[expect(clippy::too_many_arguments)]
pub(super) async fn add_entry_to_status_list<
    PrepareEmptyList,
    PrepareEmptyListFut,
    const MINIMUM_CAPACITY: usize,
>(
    entity_id: RevocationListEntityId,
    issuer_identifier_id: IdentifierId,
    issuer_certificate_id: Option<CertificateId>,
    purpose: RevocationListPurpose,
    list_type: &RevocationMethodId,
    transaction_manager: &dyn TransactionManager,
    revocation_list_repository: &dyn RevocationListRepository,
    prepare_empty_list: PrepareEmptyList,
    get_list_size_params: impl Fn(
        &RevocationList,
    )
        -> Result<StatusListSizeParams<MINIMUM_CAPACITY>, RevocationError>,
) -> Result<AllocatedIndexEntry, RevocationError>
where
    PrepareEmptyList: Fn() -> PrepareEmptyListFut,
    PrepareEmptyListFut: Future<Output = Result<RevocationList, RevocationError>> + Send,
{
    let list_lookup = ListLookup {
        issuer_identifier_id,
        issuer_certificate_id,
        purpose,
        list_type,
        revocation_list_repository,
    };

    let list = select_status_list(
        &list_lookup,
        transaction_manager,
        revocation_list_repository,
        &prepare_empty_list,
        None,
    )
    .await?;

    let mut rng = get_rng();
    {
        let available_indices = get_available_block_indices(
            list.id,
            get_list_size_params(&list)?,
            revocation_list_repository,
            &mut rng,
        )
        .await?;

        if let Some(allocated_index) = try_allocate_index(
            &entity_id,
            list.id,
            &available_indices,
            revocation_list_repository,
            transaction_manager,
        )
        .await?
        {
            return Ok(allocated_index);
        }
    }

    // There is either no available index on the current list, or all available have been populated in parallel
    // Try again with a fresh list
    let list = select_status_list(
        &list_lookup,
        transaction_manager,
        revocation_list_repository,
        &prepare_empty_list,
        // increment sequence_number
        Some(list.sequence_number + 1),
    )
    .await?;

    let available_indices = get_available_block_indices(
        list.id,
        get_list_size_params(&list)?,
        revocation_list_repository,
        &mut rng,
    )
    .await?;

    let Some(allocated_index) = try_allocate_index(
        &entity_id,
        list.id,
        &available_indices,
        revocation_list_repository,
        transaction_manager,
    )
    .await?
    else {
        return Err(RevocationError::MappingError(format!(
            "All available indices failed, num indices: {}",
            available_indices.len()
        )));
    };

    Ok(allocated_index)
}

/// Tries to allocate one of the `available_indices`
/// - returns `Some(AllocatedIndexEntry)` when an allocation succeeds
/// - returns `None` when none of the `available_indices` is free
/// - returns error otherwise
async fn try_allocate_index(
    entity_id: &RevocationListEntityId,
    list_id: RevocationListId,
    available_indices: &[usize],
    revocation_list_repository: &dyn RevocationListRepository,
    transaction_manager: &dyn TransactionManager,
) -> Result<Option<AllocatedIndexEntry>, RevocationError> {
    for available_index in available_indices {
        let maybe_entry_id = transaction_manager
            .tx(async {
                revocation_list_repository
                    .create_entry(list_id, entity_id.clone(), Some(*available_index))
                    .await
            }
            .boxed())
            .await
            .flatten();

        match maybe_entry_id {
            Ok(entry_id) => {
                return Ok(Some(AllocatedIndexEntry {
                    list_id,
                    entry_id,
                    index: *available_index,
                }));
            }
            Err(error) if error.error_code() == ErrorCode::BR_0357 => {
                tracing::debug!(%error, "Inserting at index({available_index}) failed with conflict, list: {list_id}");
                // this means the transaction failed, and the index was taken in parallel
                // try with another available index
                continue;
            }
            Err(e) => {
                return Err(e.error_while("creating revocation list entry").into());
            }
        }
    }

    Ok(None)
}

#[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
async fn select_status_list<'a, PrepareEmptyList, PrepareEmptyListFut>(
    list_lookup: &ListLookup<'a>,
    transaction_manager: &dyn TransactionManager,
    revocation_list_repository: &dyn RevocationListRepository,
    prepare_empty_list: &PrepareEmptyList,
    desired_sequence_number: Option<usize>,
) -> Result<RevocationList, RevocationError>
where
    PrepareEmptyList: Fn() -> PrepareEmptyListFut,
    PrepareEmptyListFut: Future<Output = Result<RevocationList, RevocationError>> + Send,
{
    if desired_sequence_number.is_none()
        && let Some(list) = list_lookup.lookup().await?
    {
        return Ok(list);
    }

    // no such list exists, or a list with a higher sequence_number is required, try to create a new list
    let mut new_list = prepare_empty_list().await?;
    new_list.sequence_number = desired_sequence_number.unwrap_or(0);
    let maybe_list = transaction_manager
        .tx(async {
            revocation_list_repository
                .create_revocation_list(new_list.clone())
                .await
                .error_while("creating revocation list")
        }
        .boxed())
        .await
        .error_while("creating revocation list")
        .flatten();

    match maybe_list {
        Ok(_) => {
            return Ok(new_list);
        }
        Err(error) if error.error_code() == ErrorCode::BR_0357 => {
            tracing::debug!(%error, "List creation failure with the sequence_number: {}", new_list.sequence_number);
            // this means the transaction failed, and a new list was created in parallel
            // fetch the newly created list instead
            let fresh_list = list_lookup
                .lookup()
                .await?
                .ok_or(RevocationError::MappingError(
                    "No revocation list found".to_string(),
                ))?;

            match desired_sequence_number {
                None => {
                    return Ok(fresh_list);
                }
                Some(desired_sequence_number)
                    if desired_sequence_number <= fresh_list.sequence_number =>
                {
                    return Ok(fresh_list);
                }
                Some(desired_sequence_number) => {
                    tracing::warn!(%error,
                        "Creation failed and the latest loaded list does not have \
                        the expected sequence_number (desired: {desired_sequence_number}, \
                        loaded: {})", fresh_list.sequence_number);
                    return Err(error.into());
                }
            }
        }
        Err(e) => {
            return Err(e.into());
        }
    }
}

/// Picks a randomized block on the list.
/// Returns unoccupied indices from the selected block (randomly shuffled)
async fn get_available_block_indices<const MINIMUM_CAPACITY: usize>(
    list_id: RevocationListId,
    list_size_params: StatusListSizeParams<MINIMUM_CAPACITY>,
    revocation_list_repository: &dyn RevocationListRepository,
    rng: &mut impl CryptoRng,
) -> Result<Vec<usize>, RevocationError> {
    let block_size = list_size_params.block_size;
    let num_blocks = list_size_params.capacity / block_size;

    // select a random block
    let selected_block = rng.random_range(0..num_blocks);
    tracing::trace!("Selected block: {selected_block}");

    let block_range = (selected_block * block_size)..((selected_block + 1) * block_size);
    let occupied_indices: HashSet<_> = revocation_list_repository
        .get_entries(ListQuery {
            include_count: false,
            filtering: Some(
                RevocationListEntryFilterValue::List(list_id).condition()
                    & RevocationListEntryFilterValue::index_range(block_range.clone()),
            ),
            ..Default::default()
        })
        .await
        .error_while("looking up block entries")?
        .values
        .into_iter()
        .filter_map(|entry| entry.index)
        .collect();

    if occupied_indices.len() >= block_size {
        // the block is full
        tracing::debug!("A full block found: {selected_block} on list: {list_id}");
        return Ok(vec![]);
    }

    let mut available_indices: Vec<_> = block_range
        .filter(|index| !occupied_indices.contains(index))
        .collect();
    tracing::trace!("Available indices: {}", available_indices.len());

    available_indices.shuffle(rng);
    Ok(available_indices)
}

/// Utility wrapper for looking-up the latest status list of certain issuer
struct ListLookup<'a> {
    issuer_identifier_id: IdentifierId,
    issuer_certificate_id: Option<CertificateId>,
    purpose: RevocationListPurpose,
    list_type: &'a RevocationMethodId,
    revocation_list_repository: &'a dyn RevocationListRepository,
}

impl<'a> ListLookup<'a> {
    async fn lookup(&self) -> Result<Option<RevocationList>, RevocationError> {
        Ok(self
            .revocation_list_repository
            .get_latest_list_by_issuer(
                self.issuer_identifier_id,
                self.issuer_certificate_id,
                self.purpose,
                self.list_type,
            )
            .await
            .error_while("getting revocation list")?)
    }
}
