//! Backwards compatibility for the deprecated per-collection trust collection
//! selection.
//!
//! TODO (ONE-10972): remove this module together with the deprecated
//! per-collection selection API (`trustCollections` on
//! `PATCH /api/organisation/v1/{id}` and
//! `GET /api/organisation/v1/{id}/trust-collections`). Both call sites - the
//! ecosystem sync task and `prepare_trust_collection_info` - then drop the
//! exclusion set and rely on the ecosystem selection alone.
//!
//! Selection is expressed per ecosystem now, so it applies uniformly to all
//! collections of an ecosystem. A client on the deprecated API instead selects
//! individual collections, which subscribes the selected ones and unsubscribes
//! the rest. Such a selection is still detectable afterwards: within one
//! ecosystem, a mix of subscribed and unsubscribed collections cannot be
//! produced by an ecosystem selection, only by a per-collection one.

use std::collections::{HashMap, HashSet};

use shared_types::{EcosystemId, TrustCollectionId};

use crate::model::trust_collection::TrustCollection;

/// Detects a selection made through the deprecated per-collection API and returns
/// the collections it excluded.
///
/// `subscribed` holds the collections that currently have at least one trust list
/// subscription. An ecosystem whose collections are uniformly subscribed or
/// uniformly unsubscribed has no per-collection selection in effect and
/// contributes nothing - the ecosystem selection governs it in full.
///
/// Only remote collections are considered: locally managed ones are never covered
/// by an ecosystem selection, so their subscription state carries no signal.
pub(crate) fn legacy_deselected_collections(
    collections: &[TrustCollection],
    subscribed: &HashSet<TrustCollectionId>,
) -> HashSet<TrustCollectionId> {
    let mut by_ecosystem: HashMap<&EcosystemId, Vec<&TrustCollection>> = HashMap::new();
    for collection in collections
        .iter()
        .filter(|collection| collection.remote_trust_collection_url.is_some())
    {
        by_ecosystem
            .entry(&collection.ecosystem)
            .or_default()
            .push(collection);
    }

    by_ecosystem
        .into_values()
        // an ecosystem is mixed when it holds both subscribed and unsubscribed collections
        .filter(|collections| {
            collections
                .iter()
                .any(|collection| subscribed.contains(&collection.id))
                && collections
                    .iter()
                    .any(|collection| !subscribed.contains(&collection.id))
        })
        .flat_map(|collections| {
            collections
                .into_iter()
                .map(|collection| collection.id)
                .filter(|id| !subscribed.contains(id))
        })
        .collect()
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::*;
    use crate::service::test_utilities::dummy_organisation;

    fn collection(ecosystem: &str, remote: bool) -> TrustCollection {
        TrustCollection {
            id: Uuid::new_v4().into(),
            name: Uuid::new_v4().to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            deactivated_at: None,
            remote_trust_collection_url: remote
                .then(|| "https://remote.example/collection".parse().unwrap()),
            ecosystem: ecosystem.into(),
            organisation: dummy_organisation(None).into(),
        }
    }

    #[test]
    fn test_uniformly_subscribed_ecosystem_has_no_legacy_selection() {
        let a = collection("EUDI", true);
        let b = collection("EUDI", true);
        let subscribed = HashSet::from([a.id, b.id]);

        assert_eq!(
            legacy_deselected_collections(&[a, b], &subscribed),
            HashSet::new()
        );
    }

    #[test]
    fn test_uniformly_unsubscribed_ecosystem_has_no_legacy_selection() {
        let a = collection("EUDI", true);
        let b = collection("EUDI", true);

        assert_eq!(
            legacy_deselected_collections(&[a, b], &HashSet::new()),
            HashSet::new()
        );
    }

    #[test]
    fn test_mixed_ecosystem_reports_the_unsubscribed_collections() {
        let a = collection("EUDI", true);
        let b = collection("EUDI", true);
        let c = collection("EUDI", true);
        let (b_id, c_id) = (b.id, c.id);
        let subscribed = HashSet::from([a.id]);

        assert_eq!(
            legacy_deselected_collections(&[a, b, c], &subscribed),
            HashSet::from([b_id, c_id])
        );
    }

    /// Mixedness is decided per ecosystem, a selection in one does not spill into
    /// another.
    #[test]
    fn test_ecosystems_are_evaluated_independently() {
        let eudi_selected = collection("EUDI", true);
        let eudi_deselected = collection("EUDI", true);
        let other = collection("OTHER", true);
        let deselected_id = eudi_deselected.id;
        let subscribed = HashSet::from([eudi_selected.id]);

        assert_eq!(
            legacy_deselected_collections(&[eudi_selected, eudi_deselected, other], &subscribed),
            HashSet::from([deselected_id])
        );
    }

    /// A local collection is not governed by the ecosystem selection, so it must not
    /// make its ecosystem look mixed.
    #[test]
    fn test_local_collections_are_ignored() {
        let remote = collection("EUDI", true);
        let local = collection("EUDI", false);
        let subscribed = HashSet::from([remote.id]);

        assert_eq!(
            legacy_deselected_collections(&[remote, local], &subscribed),
            HashSet::new()
        );
    }
}
