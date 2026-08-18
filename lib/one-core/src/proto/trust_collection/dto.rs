use shared_types::{EcosystemId, TrustCollectionId};

#[derive(Debug, Clone)]
pub(crate) struct RemoteTrustCollectionInfoDTO {
    pub id: TrustCollectionId,
    pub name: String,
    /// Ecosystem the collection is advertised in by the remote provider.
    pub ecosystem: EcosystemId,
}
