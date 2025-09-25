use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dto::IssuanceProtocolCapabilities;
use error::IssuanceProtocolError;
use openid4vci_final1_0::OpenID4VCIFinal1_0;
use serde::Serialize;
use serde::de::Deserialize;
use serde_json::json;
use shared_types::CredentialId;
use url::Url;

use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, IssuanceProtocolConfig, IssuanceProtocolType};
use crate::model::claim::Claim;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::provider::blob_storage_provider::BlobStorageProvider;
use crate::provider::caching_loader::vct::VctTypeMetadataFetcher;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::dto::ContinueIssuanceDTO;
use crate::provider::issuance_protocol::model::InvitationResponseEnum;
use crate::provider::issuance_protocol::openid4vci_draft13::OpenID4VCI13;
use crate::provider::issuance_protocol::openid4vci_draft13::model::OpenID4VCIDraft13Params;
use crate::provider::issuance_protocol::openid4vci_draft13_swiyu::{
    OpenID4VCI13Swiyu, OpenID4VCISwiyuParams,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::model::OpenID4VCIFinal1Params;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::storage_proxy::StorageAccess;

pub mod dto;
pub mod error;
mod mapper;
pub mod model;
pub mod openid4vci_draft13;
pub mod openid4vci_draft13_swiyu;
pub mod openid4vci_final1_0;
pub(crate) mod provider;
use model::{ContinueIssuanceResponseDTO, ShareResponse, SubmitIssuerResponse, UpdateResponse};

use crate::proto::session_provider::SessionProvider;

pub(crate) fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    data: Option<&Vec<u8>>,
) -> Result<DataDTO, IssuanceProtocolError> {
    let data = data.ok_or(IssuanceProtocolError::Failed(
        "interaction data is missing".to_string(),
    ))?;
    serde_json::from_slice(data).map_err(IssuanceProtocolError::JsonError)
}

pub(crate) fn serialize_interaction_data<DataDTO: ?Sized + Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, IssuanceProtocolError> {
    serde_json::to_vec(&dto).map_err(IssuanceProtocolError::JsonError)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn issuance_protocol_providers_from_config(
    config: Arc<CoreConfig>,
    issuance_config: &mut IssuanceProtocolConfig,
    core_base_url: Option<String>,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    vct_type_metadata_cache: Arc<dyn VctTypeMetadataFetcher>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    session_provider: Arc<dyn SessionProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    client: Arc<dyn HttpClient>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
) -> Result<HashMap<String, Arc<dyn IssuanceProtocol>>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn IssuanceProtocol>> = HashMap::new();

    // URL schemes are used to select provider, hence must not be duplicated
    let mut openid_url_schemes = HashSet::new();

    for (name, fields) in issuance_config.iter_mut() {
        let protocol: Arc<dyn IssuanceProtocol> = match fields.r#type {
            IssuanceProtocolType::OpenId4VciFinal1_0 => {
                let params = fields
                    .deserialize::<OpenID4VCIFinal1Params>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;
                validate_url_scheme_unique(
                    &mut openid_url_schemes,
                    name,
                    params.url_scheme.to_string(),
                )?;

                let handle_operations = openid4vci_final1_0::handle_invitation_operations::HandleInvitationOperationsImpl::new(
                    credential_schema_repository.clone(),
                    client.clone(),
                    formatter_provider.clone(),
                );

                Arc::new(OpenID4VCIFinal1_0::new(
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
                    session_provider.clone(),
                    certificate_validator.clone(),
                    blob_storage_provider.clone(),
                    core_base_url.clone(),
                    config.clone(),
                    params,
                    Arc::new(handle_operations),
                ))
            }
            IssuanceProtocolType::OpenId4VciDraft13 => {
                let params = fields
                    .deserialize::<OpenID4VCIDraft13Params>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;
                validate_url_scheme_unique(
                    &mut openid_url_schemes,
                    name,
                    params.url_scheme.to_string(),
                )?;

                let handle_operations = openid4vci_draft13::handle_invitation_operations::HandleInvitationOperationsImpl::new(
                    credential_schema_repository.clone(),
                    vct_type_metadata_cache.clone(),
                    client.clone(),
                    formatter_provider.clone(),
                );

                Arc::new(OpenID4VCI13::new(
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
                    session_provider.clone(),
                    certificate_validator.clone(),
                    blob_storage_provider.clone(),
                    core_base_url.clone(),
                    config.clone(),
                    params,
                    Arc::new(handle_operations),
                ))
            }
            IssuanceProtocolType::OpenId4VciDraft13Swiyu => {
                let params = fields
                    .deserialize::<OpenID4VCISwiyuParams>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;
                validate_url_scheme_unique(&mut openid_url_schemes, name, "swiyu".to_string())?;

                let handle_operations = openid4vci_draft13::handle_invitation_operations::HandleInvitationOperationsImpl::new(
                    credential_schema_repository.clone(),
                    vct_type_metadata_cache.clone(),
                    client.clone(),
                    formatter_provider.clone(),
                );

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
                    blob_storage_provider.clone(),
                    session_provider.clone(),
                    core_base_url.clone(),
                    config.clone(),
                    params,
                    Arc::new(handle_operations),
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

/// This trait contains methods for exchanging credentials between issuers and holders
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
#[allow(clippy::too_many_arguments)]
pub(crate) trait IssuanceProtocol: Send + Sync {
    // Holder methods:
    /// Check if the holder can handle the invitation URL.
    fn holder_can_handle(&self, url: &Url) -> bool;

    /// For handling credential issuance, this method
    /// saves the offer information coming in.
    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        redirect_uri: Option<String>,
    ) -> Result<InvitationResponseEnum, IssuanceProtocolError>;

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
        holder_identifier: Identifier,
        holder_key_id: String,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError>;

    async fn holder_continue_issuance(
        &self,
        continue_issuance_dto: ContinueIssuanceDTO,
        organisation: Organisation,
        storage_access: &StorageAccess,
    ) -> Result<ContinueIssuanceResponseDTO, IssuanceProtocolError>;

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities;
}
