pub mod error;
pub(crate) mod etsi_lote;
pub mod provider;

use serde::Serialize;
use shared_types::{CertificateId, KeyId, OrganisationId, TrustEntryId, TrustListPublicationId};

use crate::config::core_config::{IdentifierType, KeyAlgorithmType};
use crate::model::identifier::Identifier;
use crate::model::trust_entry::{TrustEntry, TrustEntryStateEnum};
use crate::model::trust_list_publication::TrustListPublication;
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::provider::trust_list_publisher::error::TrustListPublisherError;
use crate::provider::trust_list_publisher::etsi_lote::LoteContentType;

#[derive(Debug)]
pub struct TrustListContent {
    pub content: String,
    pub content_type: LoteContentType,
}

pub struct CreateTrustListRequest {
    pub name: String,
    pub role: TrustListRoleEnum,
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
        publication: &TrustListPublication,
        identifier: &Identifier,
        params: Option<serde_json::Value>,
    ) -> Result<TrustEntryId, TrustListPublisherError>;

    async fn update_entry(
        &self,
        entry: &TrustEntry,
        state: Option<TrustEntryStateEnum>,
        params: Option<serde_json::Value>,
    ) -> Result<(), TrustListPublisherError>;

    async fn remove_entry(&self, entry: &TrustEntry) -> Result<(), TrustListPublisherError>;

    /// Regenerates and persists the content regardless of its age.
    async fn regenerate_content(
        &self,
        publication_id: TrustListPublicationId,
    ) -> Result<(), TrustListPublisherError>;

    /// Returns the published content, refreshing it if required by the provider.
    async fn get_content(
        &self,
        publication: TrustListPublication,
    ) -> Result<TrustListContent, TrustListPublisherError>;
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustListPublisherCapabilities {
    pub key_algorithms: Vec<KeyAlgorithmType>,
    pub publisher_identifier_types: Vec<IdentifierType>,
    pub entry_identifier_types: Vec<IdentifierType>,
    pub supported_roles: Vec<TrustListRoleEnum>,
    pub content_type: Vec<LoteContentType>,
}
