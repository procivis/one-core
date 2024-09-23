use std::collections::HashMap;
use std::sync::Arc;

use dto::PresentationDefinitionResponseDTO;
use error::ExchangeProtocolError;
use openid4vc::error::OpenID4VCError;
use openid4vc::model::{
    OpenID4VCICredentialOfferCredentialDTO, OpenID4VCICredentialValueDetails,
    OpenID4VCIIssuerMetadataResponseDTO, OpenID4VPFormat,
    OpenID4VPPresentationDefinitionInputDescriptorFormat,
};
use openid4vc::openidvc_ble::OpenID4VCBLE;
use openid4vc::openidvc_http::OpenID4VCHTTP;
use procivis_temp::ProcivisTemp;
use serde::de::{Deserialize, DeserializeOwned};
use serde::Serialize;
use shared_types::{CredentialId, CredentialSchemaId, DidId, DidValue, KeyId, OrganisationId};
use url::Url;

use crate::config::core_config::{CoreConfig, ExchangeType};
use crate::config::ConfigValidationError;
use crate::model::claim::Claim;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::Did;
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::exchange_protocol::iso_mdl::IsoMdl;
use crate::provider::exchange_protocol::openid4vc::model::{
    DatatypeType, InvitationResponseDTO, PresentedCredential, ShareResponse, SubmitIssuerResponse,
    UpdateResponse,
};
use crate::provider::exchange_protocol::openid4vc::OpenID4VC;
use crate::provider::exchange_protocol::provider::{ExchangeProtocol, ExchangeProtocolProvider};
use crate::provider::exchange_protocol::scan_to_verify::ScanToVerify;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::DataRepository;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::util::ble_resource::BleWaiter;

pub mod dto;
pub mod error;
pub mod iso_mdl;
mod mapper;
pub mod openid4vc;
pub mod procivis_temp;
pub(crate) mod provider;
pub mod scan_to_verify;

#[cfg(test)]
mod test;

pub(super) fn get_base_url_from_interaction(
    interaction: Option<&Interaction>,
) -> Result<Url, ExchangeProtocolError> {
    interaction
        .ok_or(ExchangeProtocolError::Failed(
            "interaction is None".to_string(),
        ))?
        .host
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "interaction host is missing".to_string(),
        ))
        .cloned()
}

pub fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    data: Option<&Vec<u8>>,
) -> Result<DataDTO, ExchangeProtocolError> {
    let data = data.ok_or(ExchangeProtocolError::Failed(
        "interaction data is missing".to_string(),
    ))?;
    serde_json::from_slice(data).map_err(ExchangeProtocolError::JsonError)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn exchange_protocol_providers_from_config(
    config: Arc<CoreConfig>,
    core_base_url: Option<String>,
    data_provider: Arc<dyn DataRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    ble: Option<BleWaiter>,
    client: Arc<dyn HttpClient>,
) -> Result<HashMap<String, Arc<dyn ExchangeProtocol>>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn ExchangeProtocol>> = HashMap::new();

    for (name, fields) in config.exchange.iter() {
        match fields.r#type {
            ExchangeType::ProcivisTemporary => {
                let protocol = Arc::new(ExchangeProtocolWrapper::new(ProcivisTemp::new(
                    core_base_url.clone(),
                    formatter_provider.clone(),
                    key_provider.clone(),
                    config.clone(),
                    client.clone(),
                )));

                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::ScanToVerify => {
                let protocol = Arc::new(ExchangeProtocolWrapper::new(ScanToVerify::new(
                    formatter_provider.clone(),
                    key_algorithm_provider.clone(),
                    did_method_provider.clone(),
                )));

                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::OpenId4Vc => {
                let params = config.exchange.get(name)?;
                let ble = OpenID4VCBLE::new(
                    data_provider.get_proof_repository(),
                    data_provider.get_interaction_repository(),
                    formatter_provider.clone(),
                    key_provider.clone(),
                    ble.clone(),
                    config.clone(),
                );
                let http = OpenID4VCHTTP::new(
                    core_base_url.clone(),
                    formatter_provider.clone(),
                    revocation_method_provider.clone(),
                    key_provider.clone(),
                    client.clone(),
                    params,
                );
                let protocol = Arc::new(OpenID4VC::new(http, ble));
                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::IsoMdl => {
                let protocol = Arc::new(ExchangeProtocolWrapper::new(IsoMdl::new(
                    config.clone(),
                    formatter_provider.clone(),
                    key_provider.clone(),
                    ble.clone(),
                )));
                providers.insert(name.to_string(), protocol);
            }
        }
    }

    Ok(providers)
}

pub type FormatMapper = Arc<dyn Fn(&str) -> Result<String, ExchangeProtocolError> + Send + Sync>;
pub type TypeToDescriptorMapper = Arc<
    dyn Fn(
            &str,
        ) -> Result<
            HashMap<String, OpenID4VPPresentationDefinitionInputDescriptorFormat>,
            ExchangeProtocolError,
        > + Send
        + Sync,
>;
pub type FnMapExternalFormatToExternalDetailed = fn(&str, &str) -> Result<String, OpenID4VCError>;

/// Interface to be implemented in order to use an exchange protocol.
///
/// The exchange protocol provider relies on storage of data for interactions,
/// credentials, credential schemas, and DIDs. A storage layer must be
/// chosen and implemented for the exchange protocol to be enabled.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait StorageProxy: Send + Sync {
    /// Store an interaction with a chosen storage layer.
    async fn create_interaction(&self, interaction: Interaction) -> anyhow::Result<InteractionId>;
    /// Get a credential schema from a chosen storage layer.
    async fn get_schema(
        &self,
        schema_id: &str,
        schema_type: &str,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<CredentialSchema>>;
    /// Get credentials from a specified schema ID, from a chosen storage layer.
    async fn get_credentials_by_credential_schema_id(
        &self,
        schema_id: &str,
    ) -> anyhow::Result<Vec<Credential>>;
    /// Create a credential schema in a chosen storage layer.
    async fn create_credential_schema(
        &self,
        schema: CredentialSchema,
    ) -> anyhow::Result<CredentialSchemaId>;
    /// Create a DID in a chosen storage layer.
    async fn create_did(&self, did: Did) -> anyhow::Result<DidId>;
    /// Obtain a DID by its address, from a chosen storage layer.
    async fn get_did_by_value(&self, value: &DidValue) -> anyhow::Result<Option<Did>>;
}
pub type StorageAccess = dyn StorageProxy;

pub struct BasicSchemaData {
    pub schema_id: String,
    pub schema_type: String,
}

pub struct BuildCredentialSchemaResponse {
    pub claims: Vec<Claim>,
    pub schema: CredentialSchema,
}

/// Interface to be implemented in order to use an exchange protocol.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[allow(clippy::too_many_arguments)]
#[async_trait::async_trait]
pub trait HandleInvitationOperations: Send + Sync {
    /// Utilizes custom logic to find out credential schema
    /// name from credential offer
    async fn get_credential_schema_name(
        &self,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        credential: &OpenID4VCICredentialOfferCredentialDTO,
    ) -> Result<String, ExchangeProtocolError>;

    /// Utilizes custom logic to find out credential schema
    /// type and id from credential offer
    async fn find_schema_data(
        &self,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        credential: &OpenID4VCICredentialOfferCredentialDTO,
    ) -> BasicSchemaData;

    /// Allows use of custom logic to create new credential schema for
    /// incoming credential
    async fn create_new_schema(
        &self,
        schema_data: &BasicSchemaData,
        claim_keys: &HashMap<String, OpenID4VCICredentialValueDetails>,
        credential_id: &CredentialId,
        credential: &OpenID4VCICredentialOfferCredentialDTO,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        credential_schema_name: &str,
        organisation: Organisation,
    ) -> Result<BuildCredentialSchemaResponse, ExchangeProtocolError>;
}
pub type HandleInvitationOperationsAccess = dyn HandleInvitationOperations;

/// This trait contains methods for exchanging credentials between issuers,
/// holders, and verifiers.
#[cfg_attr(any(test, feature = "mock"), mockall::automock(type VCInteractionContext = (); type VPInteractionContext = ();))]
#[async_trait::async_trait]
#[allow(clippy::too_many_arguments)]
pub trait ExchangeProtocolImpl: Send + Sync {
    type VCInteractionContext;
    type VPInteractionContext;

    // Holder methods:
    /// Check if the holder can handle the necessary URLs.
    fn can_handle(&self, url: &Url) -> bool;

    /// For handling credential issuance and verification, this method
    /// saves the offer information coming in.
    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError>;

    /// Rejects a verifier's request for credential presentation.
    async fn reject_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError>;

    /// Submits a presentation to a verifier.
    #[allow(clippy::too_many_arguments)]
    async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format_map: HashMap<String, String>,
        presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError>;

    /// Accepts an offered credential.
    ///
    /// Storage access must be implemented.
    async fn accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
        // This helps map to correct formatter key if crypto suite hast o be scanned.
        map_external_format_to_external: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError>;

    /// Rejects an offered credential.
    async fn reject_credential(&self, credential: &Credential)
        -> Result<(), ExchangeProtocolError>;

    /// Takes a proof request and filters held credentials,
    /// returning those which are acceptable for the request.
    ///
    /// Storage access is needed to check held credentials.
    async fn get_presentation_definition(
        &self,
        proof: &Proof,
        context: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        format_map: HashMap<String, String>,
        types: HashMap<String, DatatypeType>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError>;

    /// Validates proof properties before submitting to verifier
    async fn validate_proof_for_submission(
        &self,
        proof: &Proof,
    ) -> Result<(), ExchangeProtocolError>;

    // Issuer methods:
    /// Generates QR-code content to start the credential issuance flow.
    async fn share_credential(
        &self,
        credential: &Credential,
        credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError>;

    // Verifier methods:
    /// Called when proof needs to be retracted. Use this function for closing opened transmissions, buffers, etc.
    async fn retract_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError>;

    /// Generates QR-code content to start the proof request flow.
    async fn share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError>;

    /// Checks if the submitted presentation complies with the given proof request.
    async fn verifier_handle_proof(
        &self,
        proof: &Proof,
        submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError>;
}

#[cfg(any(test, feature = "mock"))]
pub type MockExchangeProtocol = ExchangeProtocolWrapper<MockExchangeProtocolImpl>;

#[derive(Default)]
pub struct ExchangeProtocolWrapper<T> {
    pub inner: T,
}

impl<T> ExchangeProtocolWrapper<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl<T> ExchangeProtocolImpl for ExchangeProtocolWrapper<T>
where
    T: ExchangeProtocolImpl,
    T::VCInteractionContext: Serialize + DeserializeOwned,
    T::VPInteractionContext: Serialize + DeserializeOwned,
{
    type VCInteractionContext = serde_json::Value;
    type VPInteractionContext = serde_json::Value;

    fn can_handle(&self, url: &Url) -> bool {
        self.inner.can_handle(url)
    }

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        self.inner
            .handle_invitation(
                url,
                organisation,
                storage_access,
                handle_invitation_operations,
            )
            .await
    }

    async fn reject_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError> {
        self.inner.reject_proof(proof).await
    }

    async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format_map: HashMap<String, String>,
        presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        self.inner
            .submit_proof(
                proof,
                credential_presentations,
                holder_did,
                key,
                jwk_key_id,
                format_map,
                presentation_format_map,
            )
            .await
    }

    async fn accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
        map_external_format_to_external: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        self.inner
            .accept_credential(
                credential,
                holder_did,
                key,
                jwk_key_id,
                format,
                storage_access,
                map_external_format_to_external,
            )
            .await
    }

    async fn reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        self.inner.reject_credential(credential).await
    }

    async fn get_presentation_definition(
        &self,
        proof: &Proof,
        interaction_data: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        format_map: HashMap<String, String>,
        types: HashMap<String, DatatypeType>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        let interaction_data =
            serde_json::from_value(interaction_data).map_err(ExchangeProtocolError::JsonError)?;
        self.inner
            .get_presentation_definition(proof, interaction_data, storage_access, format_map, types)
            .await
    }

    async fn validate_proof_for_submission(
        &self,
        proof: &Proof,
    ) -> Result<(), ExchangeProtocolError> {
        self.inner.validate_proof_for_submission(proof).await
    }

    async fn share_credential(
        &self,
        credential: &Credential,
        credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        self.inner
            .share_credential(credential, credential_format)
            .await
            .map(|resp| ShareResponse {
                url: resp.url,
                id: resp.id,
                context: serde_json::json!(resp.context),
            })
    }

    async fn retract_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError> {
        self.inner.retract_proof(proof).await
    }

    async fn share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        self.inner
            .share_proof(
                proof,
                format_to_type_mapper,
                key_id,
                encryption_key_jwk,
                vp_formats,
                type_to_descriptor,
            )
            .await
            .map(|resp| ShareResponse {
                url: resp.url,
                id: resp.id,
                context: serde_json::json!(resp.context),
            })
    }

    async fn verifier_handle_proof(
        &self,
        proof: &Proof,
        submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        self.inner.verifier_handle_proof(proof, submission).await
    }
}

impl<T> ExchangeProtocol for ExchangeProtocolWrapper<T>
where
    T: ExchangeProtocolImpl,
    T::VCInteractionContext: Serialize + DeserializeOwned,
    T::VPInteractionContext: Serialize + DeserializeOwned,
{
}

pub struct ExchangeProtocolProviderImpl {
    protocols: HashMap<String, Arc<dyn ExchangeProtocol>>,
}

impl ExchangeProtocolProviderImpl {
    pub fn new(protocols: HashMap<String, Arc<dyn ExchangeProtocol>>) -> Self {
        Self { protocols }
    }
}

#[async_trait::async_trait]
impl ExchangeProtocolProvider for ExchangeProtocolProviderImpl {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn ExchangeProtocol>> {
        self.protocols.get(protocol_id).cloned()
    }

    fn detect_protocol(&self, url: &Url) -> Option<Arc<dyn ExchangeProtocol>> {
        self.protocols
            .values()
            .find(|protocol| protocol.can_handle(url))
            .cloned()
    }
}
