use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dto::IssuanceProtocolCapabilities;
use error::IssuanceProtocolError;
use indexmap::IndexMap;
use openid4vci_draft13::model::{
    OpenID4VCICredentialValueDetails, OpenID4VCIIssuerMetadataResponseDTO,
};
use openid4vci_draft13::openidvc_http::OpenID4VCHTTP;
use serde::de::Deserialize;
use serde_json::json;
use shared_types::CredentialId;
use url::Url;

use crate::config::core_config::{IssuanceProtocolConfig, IssuanceProtocolType};
use crate::config::ConfigValidationError;
use crate::model::claim::Claim;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::Did;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    InvitationResponseDTO, OpenID4VCIParams, ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::issuance_protocol::openid4vci_draft13::OpenID4VC;
use crate::provider::issuance_protocol::provider::{IssuanceProtocol, IssuanceProtocolProvider};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::service::storage_proxy::StorageAccess;

pub mod dto;
pub mod error;
mod mapper;
pub mod openid4vci_draft13;
pub(crate) mod provider;

#[cfg(test)]
mod test;

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
    exchange_config: &mut IssuanceProtocolConfig,
    core_base_url: Option<String>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    client: Arc<dyn HttpClient>,
) -> Result<HashMap<String, Arc<dyn IssuanceProtocol>>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn IssuanceProtocol>> = HashMap::new();

    let mut openid_url_schemes = HashSet::new();

    for (name, fields) in exchange_config.iter_mut() {
        match fields.r#type {
            IssuanceProtocolType::OpenId4VciDraft13 => {
                let params = fields.deserialize::<OpenID4VCIParams>().map_err(|source| {
                    ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    }
                })?;

                // URL schemes are used to select provider, hence must not be duplicated
                validate_url_scheme_unique(
                    &mut openid_url_schemes,
                    name,
                    params.url_scheme.to_string(),
                )?;

                let http = OpenID4VCHTTP::new(
                    core_base_url.clone(),
                    formatter_provider.clone(),
                    revocation_method_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    client.clone(),
                    params.clone(),
                );

                let protocol = Arc::new(OpenID4VC::new(http));
                fields.capabilities = Some(json!(protocol.get_capabilities()));
                providers.insert(name.to_string(), protocol);
            }
        }
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

/// This trait contains methods for exchanging credentials between issuers,
/// holders, and verifiers.
#[cfg_attr(any(test, feature = "mock"), mockall::automock(type InteractionContext = ();))]
#[async_trait::async_trait]
#[allow(clippy::too_many_arguments)]
pub(crate) trait IssuanceProtocolImpl: Send + Sync {
    type InteractionContext;

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
        format: &str,
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
        credential_format: &str,
    ) -> Result<ShareResponse<Self::InteractionContext>, IssuanceProtocolError>;

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities;
}

#[cfg(test)]
pub(crate) type MockIssuanceProtocol = IssuanceProtocolWrapper<MockIssuanceProtocolImpl>;

#[cfg(test)]
#[derive(Default)]
pub(crate) struct IssuanceProtocolWrapper<T> {
    pub inner: T,
}

#[cfg(test)]
#[async_trait::async_trait]
impl<T> IssuanceProtocolImpl for IssuanceProtocolWrapper<T>
where
    T: IssuanceProtocolImpl,
    T::InteractionContext: serde::Serialize + serde::de::DeserializeOwned,
{
    type InteractionContext = serde_json::Value;

    fn holder_can_handle(&self, url: &Url) -> bool {
        self.inner.holder_can_handle(url)
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, IssuanceProtocolError> {
        self.inner
            .holder_handle_invitation(
                url,
                organisation,
                storage_access,
                handle_invitation_operations,
            )
            .await
    }

    async fn holder_accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, IssuanceProtocolError> {
        self.inner
            .holder_accept_credential(
                credential,
                holder_did,
                key,
                jwk_key_id,
                format,
                storage_access,
                tx_code,
            )
            .await
    }

    async fn holder_reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), IssuanceProtocolError> {
        self.inner.holder_reject_credential(credential).await
    }

    async fn issuer_share_credential(
        &self,
        credential: &Credential,
        credential_format: &str,
    ) -> Result<ShareResponse<Self::InteractionContext>, IssuanceProtocolError> {
        self.inner
            .issuer_share_credential(credential, credential_format)
            .await
            .map(|resp| ShareResponse {
                url: resp.url,
                interaction_id: resp.interaction_id,
                context: serde_json::json!(resp.context),
            })
    }

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities {
        self.inner.get_capabilities()
    }
}

#[cfg(test)]
impl<T> IssuanceProtocol for IssuanceProtocolWrapper<T>
where
    T: IssuanceProtocolImpl,
    T::InteractionContext: serde::Serialize + serde::de::DeserializeOwned,
{
}

pub(crate) struct IssuanceProtocolProviderImpl {
    protocols: HashMap<String, Arc<dyn IssuanceProtocol>>,
}

impl IssuanceProtocolProviderImpl {
    pub(crate) fn new(protocols: HashMap<String, Arc<dyn IssuanceProtocol>>) -> Self {
        Self { protocols }
    }
}

#[async_trait::async_trait]
impl IssuanceProtocolProvider for IssuanceProtocolProviderImpl {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn IssuanceProtocol>> {
        self.protocols.get(protocol_id).cloned()
    }

    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn IssuanceProtocol>)> {
        self.protocols
            .iter()
            .find(|(_, protocol)| protocol.holder_can_handle(url))
            .map(|(id, protocol)| (id.to_owned(), protocol.to_owned()))
    }
}
