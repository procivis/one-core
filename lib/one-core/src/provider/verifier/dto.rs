use serde::{Deserialize, Serialize};
use shared_types::{IdentifierId, OrganisationId, RevocationListEntryId};

use crate::config::core_config::IdentifierType;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierProviderCapabilities {
    pub signer_identifier_types: Vec<IdentifierType>,
}

#[expect(unused)]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessCertificateConfiguration {
    pub provider_url: String,
    pub organisation_id: OrganisationId,
    pub relying_party_public_identifier: String,
    pub relying_party_national_registry: String,
    pub issuer_id: IdentifierId,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierAppVersion {
    pub minimum: Option<String>,
    pub minimum_recommended: Option<String>,
    pub reject: Option<Vec<String>>,
    pub update_screen: Option<VerifierUpdateScreen>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierUpdateScreen {
    pub link: String,
}

#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessCertificateProvisioningResponse {
    pub access_certificate: String,
    pub signature_id: RevocationListEntryId,
}
