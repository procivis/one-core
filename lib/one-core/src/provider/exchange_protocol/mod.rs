use std::collections::HashMap;
use std::sync::Arc;

use dto::{ExchangeProtocolCapabilities, PresentationDefinitionResponseDTO};
use error::ExchangeProtocolError;
use futures::future::BoxFuture;
use indexmap::IndexMap;
use openid4vc::error::OpenID4VCError;
use openid4vc::model::{
    OpenID4VCICredentialOfferCredentialDTO, OpenID4VCICredentialValueDetails,
    OpenID4VCIIssuerMetadataResponseDTO, OpenID4VPFormat,
    OpenID4VPPresentationDefinitionInputDescriptorFormat,
};
use openid4vc::openidvc_ble::OpenID4VCBLE;
use openid4vc::openidvc_http::OpenID4VCHTTP;
use openid4vc::openidvc_mqtt::OpenId4VcMqtt;
use serde::de::{Deserialize, DeserializeOwned};
use serde::Serialize;
use shared_types::{CredentialId, CredentialSchemaId, DidId, DidValue, KeyId, OrganisationId};
use url::Url;

use super::mqtt_client::MqttClient;
use crate::common_mapper::DidRole;
use crate::config::core_config::{CoreConfig, ExchangeType, TransportType};
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
    InvitationResponseDTO, PresentedCredential, ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_http::ClientIdSchemaType;
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
pub(crate) mod provider;
pub mod scan_to_verify;

#[cfg(test)]
mod test;

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
    mqtt_client: Option<Arc<dyn MqttClient>>,
) -> Result<HashMap<String, Arc<dyn ExchangeProtocol>>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn ExchangeProtocol>> = HashMap::new();

    for (name, fields) in config.exchange.iter() {
        match fields.r#type {
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
                    did_method_provider.clone(),
                    formatter_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    ble.clone(),
                    config.clone(),
                );
                let http = OpenID4VCHTTP::new(
                    core_base_url.clone(),
                    formatter_provider.clone(),
                    revocation_method_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    client.clone(),
                    params,
                );

                let mut mqtt = None;
                if let Some(mqtt_client) = mqtt_client.clone() {
                    if let Ok(params) = config.transport.get(TransportType::Mqtt.as_ref()) {
                        mqtt = Some(OpenId4VcMqtt::new(
                            mqtt_client.clone(),
                            config.clone(),
                            params,
                            data_provider.get_interaction_repository(),
                            data_provider.get_proof_repository(),
                            key_algorithm_provider.clone(),
                            formatter_provider.clone(),
                            did_method_provider.clone(),
                            key_provider.clone(),
                        ));
                    };
                }
                let protocol = Arc::new(OpenID4VC::new(config.clone(), http, ble, mqtt));
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

    /// Store an interaction with a chosen storage layer.
    async fn update_interaction(&self, interaction: Interaction) -> anyhow::Result<()>;

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
        organisation_id: OrganisationId,
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

    async fn get_or_create_did(
        &self,
        organisation: &Option<Organisation>,
        did_value: &DidValue,
        did_role: DidRole,
    ) -> anyhow::Result<Did>;
}
pub type StorageAccess = dyn StorageProxy;

#[derive(Debug)]
pub struct BasicSchemaData {
    pub id: String,
    pub r#type: String,
    pub offer_id: String,
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
        credential_config: &OpenID4VCICredentialOfferCredentialDTO,
        schema_id: &str,
    ) -> Result<String, ExchangeProtocolError>;

    /// Utilizes custom logic to find out credential schema
    /// type and id from credential offer
    fn find_schema_data(
        &self,
        credential_config: &openid4vc::model::OpenID4VCICredentialConfigurationData,
        schema_id: &str,
        offer_id: &str,
    ) -> Result<BasicSchemaData, ExchangeProtocolError>;

    /// Allows use of custom logic to create new credential schema for
    /// incoming credential
    async fn create_new_schema(
        &self,
        schema_data: BasicSchemaData,
        claim_keys: &IndexMap<String, OpenID4VCICredentialValueDetails>,
        credential_id: &CredentialId,
        credential_config: &openid4vc::model::OpenID4VCICredentialConfigurationData,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
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
    fn holder_can_handle(&self, url: &Url) -> bool;

    /// For handling credential issuance and verification, this method
    /// saves the offer information coming in.
    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
        transport: String,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError>;

    /// Rejects a verifier's request for credential presentation.
    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError>;

    /// Submits a presentation to a verifier.
    #[allow(clippy::too_many_arguments)]
    async fn holder_submit_proof(
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
    async fn holder_accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
        // This helps map to correct formatter key if crypto suite hast o be scanned.
        map_external_format_to_external: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError>;

    /// Rejects an offered credential.
    async fn holder_reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), ExchangeProtocolError>;

    /// Takes a proof request and filters held credentials,
    /// returning those which are acceptable for the request.
    ///
    /// Storage access is needed to check held credentials.
    async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        context: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        format_map: HashMap<String, String>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError>;

    // Issuer methods:
    /// Generates QR-code content to start the credential issuance flow.
    async fn issuer_share_credential(
        &self,
        credential: &Credential,
        credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError>;

    // Verifier methods:
    /// Called when proof needs to be retracted. Use this function for closing opened transmissions, buffers, etc.
    async fn verifier_retract_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError>;

    /// Generates QR-code content to start the proof request flow.
    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
        callback: Option<BoxFuture<'static, ()>>,
        client_id_schema: ClientIdSchemaType,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError>;

    /// Checks if the submitted presentation complies with the given proof request.
    async fn verifier_handle_proof(
        &self,
        proof: &Proof,
        submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError>;

    fn get_capabilities(&self) -> ExchangeProtocolCapabilities;
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

    fn holder_can_handle(&self, url: &Url) -> bool {
        self.inner.holder_can_handle(url)
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
        transport: String,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        self.inner
            .holder_handle_invitation(
                url,
                organisation,
                storage_access,
                handle_invitation_operations,
                transport,
            )
            .await
    }

    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError> {
        self.inner.holder_reject_proof(proof).await
    }

    async fn holder_submit_proof(
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
            .holder_submit_proof(
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

    async fn holder_accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
        map_external_format_to_external: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        self.inner
            .holder_accept_credential(
                credential,
                holder_did,
                key,
                jwk_key_id,
                format,
                storage_access,
                tx_code,
                map_external_format_to_external,
            )
            .await
    }

    async fn holder_reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        self.inner.holder_reject_credential(credential).await
    }

    async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        interaction_data: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        format_map: HashMap<String, String>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        let interaction_data =
            serde_json::from_value(interaction_data).map_err(ExchangeProtocolError::JsonError)?;
        self.inner
            .holder_get_presentation_definition(proof, interaction_data, storage_access, format_map)
            .await
    }

    async fn issuer_share_credential(
        &self,
        credential: &Credential,
        credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        self.inner
            .issuer_share_credential(credential, credential_format)
            .await
            .map(|resp| ShareResponse {
                url: resp.url,
                interaction_id: resp.interaction_id,
                context: serde_json::json!(resp.context),
            })
    }

    async fn verifier_retract_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError> {
        self.inner.verifier_retract_proof(proof).await
    }

    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
        callback: Option<BoxFuture<'static, ()>>,
        client_id_schema: ClientIdSchemaType,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        self.inner
            .verifier_share_proof(
                proof,
                format_to_type_mapper,
                key_id,
                encryption_key_jwk,
                vp_formats,
                type_to_descriptor,
                callback,
                client_id_schema,
            )
            .await
            .map(|resp| ShareResponse {
                url: resp.url,
                interaction_id: resp.interaction_id,
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

    fn get_capabilities(&self) -> ExchangeProtocolCapabilities {
        self.inner.get_capabilities()
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
            .find(|protocol| protocol.holder_can_handle(url))
            .cloned()
    }
}
