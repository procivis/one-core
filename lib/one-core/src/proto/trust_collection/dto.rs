use shared_types::TrustCollectionId;

#[derive(Debug, Clone)]
pub(crate) struct RemoteTrustCollectionInfoDTO {
    pub id: TrustCollectionId,
    pub name: String,
}
