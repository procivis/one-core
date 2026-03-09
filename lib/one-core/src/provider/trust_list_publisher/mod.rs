pub mod error;
pub(crate) mod etsi_lote;
pub mod provider;

use serde::Serialize;
use shared_types::{CertificateId, KeyId, OrganisationId, TrustEntryId, TrustListPublicationId};

use crate::config::core_config::{IdentifierType, KeyAlgorithmType};
use crate::model::identifier::Identifier;
use crate::model::trust_entry::{TrustEntry, TrustEntryState};
use crate::model::trust_list_publication::{TrustListPublication, TrustRoleEnum};
use crate::provider::trust_list_publisher::error::TrustListPublisherError;

pub struct CreateTrustListRequest {
    pub name: String,
    pub role: TrustRoleEnum,
    pub organisation_id: OrganisationId,
    pub identifier: Identifier,
    pub key_id: Option<KeyId>,
    pub certificate_id: Option<CertificateId>,
    pub params: Option<serde_json::Value>,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustListPublisher: Send + Sync {
    fn get_capabilities(&self) -> TrustListPublisherCapabilities;

    async fn create_trust_list(
        &self,
        request: CreateTrustListRequest,
    ) -> Result<TrustListPublicationId, TrustListPublisherError>;

    async fn add_entry(
        &self,
        publication: TrustListPublication,
        identifier: Identifier,
        params: Option<serde_json::Value>,
    ) -> Result<TrustEntryId, TrustListPublisherError>;

    async fn update_entry(
        &self,
        entry: TrustEntry,
        state: Option<TrustEntryState>,
        params: Option<serde_json::Value>,
    ) -> Result<(), TrustListPublisherError>;

    async fn remove_entry(&self, entry: TrustEntry) -> Result<(), TrustListPublisherError>;

    async fn generate_trust_list_content(
        &self,
        publication: TrustListPublication,
    ) -> Result<String, TrustListPublisherError>;
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustListPublisherCapabilities {
    pub key_algorithms: Vec<KeyAlgorithmType>,
    pub publisher_identifier_types: Vec<IdentifierType>,
    pub entry_identifier_types: Vec<IdentifierType>,
    pub supported_roles: Vec<TrustRoleEnum>,
}
