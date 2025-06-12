use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use IssuanceProtocolType::OpenId4VciDraft13;
use dto::IssuanceProtocolCapabilities;
use error::IssuanceProtocolError;
use indexmap::IndexMap;
use openid4vci_draft13::model::{
    OpenID4VCICredentialValueDetails, OpenID4VCIIssuerMetadataResponseDTO,
};
use serde::de::Deserialize;
use serde_json::json;
use shared_types::CredentialId;
use url::Url;

use crate::config::ConfigValidationError;
use crate::config::core_config::IssuanceProtocolType::OpenId4VciDraft13Swiyu;
use crate::config::core_config::{CoreConfig, IssuanceProtocolConfig, IssuanceProtocolType};
use crate::model::claim::Claim;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::openid4vci_draft13::OpenID4VCI13;
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    InvitationResponseDTO, OpenID4VCIParams, ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::issuance_protocol::openid4vci_draft13_swiyu::{
    OpenID4VCI13Swiyu, OpenID4VCISwiyuParams,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::storage_proxy::StorageAccess;

pub mod dto;
pub mod error;
mod mapper;
pub mod openid4vci_draft13;
pub mod openid4vci_draft13_swiyu;
pub(crate) mod provider;

pub(crate) fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    data: Option<&Vec<u8>>,
) -> Result<DataDTO, IssuanceProtocolError> {
    let data = data.ok_or(IssuanceProtocolError::Failed(
        "interaction data is missing".to_string(),
    ))?;
    serde_json::from_slice(data).map_err(IssuanceProtocolError::JsonError)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn issuance_protocol_providers_from_config(
    config: Arc<CoreConfig>,
    issuance_config: &mut IssuanceProtocolConfig,
    core_base_url: Option<String>,
    credential_repository: Arc<dyn CredentialRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    client: Arc<dyn HttpClient>,
) -> Result<HashMap<String, Arc<dyn IssuanceProtocol>>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn IssuanceProtocol>> = HashMap::new();

    let mut openid_url_schemes = HashSet::new();

    for (name, fields) in issuance_config.iter_mut() {
        // URL schemes are used to select provider, hence must not be duplicated
        let params = fields.deserialize::<OpenID4VCIParams>().map_err(|source| {
            ConfigValidationError::FieldsDeserialization {
                key: name.to_owned(),
                source,
            }
        })?;
        let protocol: Arc<dyn IssuanceProtocol> = match fields.r#type {
            OpenId4VciDraft13 => Arc::new(OpenID4VCI13::new(
                client.clone(),
                credential_repository.clone(),
                validity_credential_repository.clone(),
                revocation_list_repository.clone(),
                history_repository.clone(),
                formatter_provider.clone(),
                revocation_method_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                key_provider.clone(),
                certificate_validator.clone(),
                core_base_url.clone(),
                config.clone(),
                params,
            )),
            OpenId4VciDraft13Swiyu => {
                let params = fields
                    .deserialize::<OpenID4VCISwiyuParams>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;
                validate_url_scheme_unique(&mut openid_url_schemes, name, "swiyu".to_string())?;
                Arc::new(OpenID4VCI13Swiyu::new(
                    client.clone(),
                    credential_repository.clone(),
                    validity_credential_repository.clone(),
                    revocation_list_repository.clone(),
                    history_repository.clone(),
                    formatter_provider.clone(),
                    revocation_method_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
                    core_base_url.clone(),
                    config.clone(),
                    params,
                ))
            }
        };
        fields.capabilities = Some(json!(protocol.get_capabilities()));
        providers.insert(name.to_string(), protocol);
    }

    Ok(providers)
}

fn validate_url_scheme_unique(
    openid_url_schemes: &mut HashSet<String>,
    name: &str,
    scheme: String,
) -> Result<(), ConfigValidationError> {
    if openid_url_schemes.contains(&scheme) {
        return Err(ConfigValidationError::DuplicateUrlScheme {
            key: name.to_string(),
            scheme,
        });
    }
    openid_url_schemes.insert(scheme);
    Ok(())
}

#[derive(Debug)]
pub(crate) struct BasicSchemaData {
    pub id: String,
    pub r#type: String,
    pub offer_id: String,
    pub external_schema: bool,
}

pub(crate) struct BuildCredentialSchemaResponse {
    pub claims: Vec<Claim>,
    pub schema: CredentialSchema,
}

/// Interface to be implemented in order to use an exchange protocol.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[allow(clippy::too_many_arguments)]
#[async_trait::async_trait]
pub(crate) trait HandleInvitationOperations: Send + Sync {
    /// Utilizes custom logic to find out credential schema
    /// type and id from credential offer
    fn find_schema_data(
        &self,
        credential_config: &openid4vci_draft13::model::OpenID4VCICredentialConfigurationData,
        offer_id: &str,
    ) -> Result<BasicSchemaData, IssuanceProtocolError>;

    /// Allows use of custom logic to create new credential schema for
    /// incoming credential
    async fn create_new_schema(
        &self,
        schema_data: BasicSchemaData,
        claim_keys: &IndexMap<String, OpenID4VCICredentialValueDetails>,
        credential_id: &CredentialId,
        credential_config: &openid4vci_draft13::model::OpenID4VCICredentialConfigurationData,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        organisation: Organisation,
    ) -> Result<BuildCredentialSchemaResponse, IssuanceProtocolError>;
}
pub(crate) type HandleInvitationOperationsAccess = dyn HandleInvitationOperations;

/// This trait contains methods for exchanging credentials between issuers and holders
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
#[allow(clippy::too_many_arguments)]
pub(crate) trait IssuanceProtocol: Send + Sync {
    // Holder methods:
    /// Check if the holder can handle the necessary URLs.
    fn holder_can_handle(&self, url: &Url) -> bool;

    /// For handling credential issuance and verification, this method
    /// saves the offer information coming in.
    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, IssuanceProtocolError>;

    /// Accepts an offered credential.
    ///
    /// Storage access must be implemented.
    async fn holder_accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, IssuanceProtocolError>;

    /// Rejects an offered credential.
    async fn holder_reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), IssuanceProtocolError>;

    /// Generates QR-code content to start the credential issuance flow.
    async fn issuer_share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse<serde_json::Value>, IssuanceProtocolError>;

    /// Creates a newly issued credential
    async fn issuer_issue_credential(
        &self,
        credential_id: &CredentialId,
        holder_did: Did,
        holder_identifier: Identifier,
        holder_key_id: String,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError>;

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities;
}
