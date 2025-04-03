use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dto::{PresentationDefinitionResponseDTO, VerificationProtocolCapabilities};
use error::VerificationProtocolError;
use futures::future::BoxFuture;
use openid4vc::model::{ClientIdScheme, OpenID4VpPresentationFormat};
use openid4vc::openidvc_ble::OpenID4VCBLE;
use openid4vc::openidvc_http::OpenID4VCHTTP;
use openid4vc::openidvc_mqtt::OpenId4VcMqtt;
use serde::de::{Deserialize, DeserializeOwned};
use serde::Serialize;
use serde_json::json;
use shared_types::KeyId;
use url::Url;

use super::mqtt_client::MqttClient;
use crate::config::core_config::{
    CoreConfig, FormatType, TransportType, VerificationProtocolConfig, VerificationProtocolType,
};
use crate::config::ConfigValidationError;
use crate::model::did::Did;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::model::{DetailCredential, HolderBindingCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::iso_mdl::IsoMdl;
use crate::provider::verification_protocol::openid4vc::model::{
    InvitationResponseDTO, OpenID4VpParams, PresentedCredential, ShareResponse, UpdateResponse,
};
use crate::provider::verification_protocol::openid4vc::OpenID4VC;
use crate::provider::verification_protocol::provider::{
    VerificationProtocol, VerificationProtocolProvider,
};
use crate::provider::verification_protocol::scan_to_verify::ScanToVerify;
use crate::repository::DataRepository;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::storage_proxy::StorageAccess;
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

pub(crate) fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    data: Option<&Vec<u8>>,
) -> Result<DataDTO, VerificationProtocolError> {
    let data = data.ok_or(VerificationProtocolError::Failed(
        "interaction data is missing".to_string(),
    ))?;
    serde_json::from_slice(data).map_err(VerificationProtocolError::JsonError)
}

#[cfg(test)]
pub(crate) fn serialize_interaction_data<DataDTO: ?Sized + Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, VerificationProtocolError> {
    serde_json::to_vec(&dto).map_err(VerificationProtocolError::JsonError)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verification_protocol_providers_from_config(
    config: Arc<CoreConfig>,
    exchange_config: &mut VerificationProtocolConfig,
    core_base_url: Option<String>,
    data_provider: Arc<dyn DataRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    ble: Option<BleWaiter>,
    client: Arc<dyn HttpClient>,
    mqtt_client: Option<Arc<dyn MqttClient>>,
) -> Result<HashMap<String, Arc<dyn VerificationProtocol>>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn VerificationProtocol>> = HashMap::new();

    let mut openid_url_schemes = HashSet::new();

    for (name, fields) in exchange_config.iter_mut() {
        match fields.r#type {
            VerificationProtocolType::ScanToVerify => {
                let protocol = Arc::new(VerificationProtocolWrapper::new(ScanToVerify::new(
                    formatter_provider.clone(),
                    key_algorithm_provider.clone(),
                    did_method_provider.clone(),
                )));
                fields.capabilities = Some(json!(protocol.get_capabilities()));
                providers.insert(name.to_string(), protocol);
            }
            VerificationProtocolType::OpenId4VpDraft20 => {
                let params = fields.deserialize::<OpenID4VpParams>().map_err(|source| {
                    ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    }
                })?;

                // x_509_san_dns client_id scheme requires a X.509 CA certificate to be configured
                if params
                    .holder
                    .supported_client_id_schemes
                    .contains(&ClientIdScheme::X509SanDns)
                    || params
                        .verifier
                        .supported_client_id_schemes
                        .contains(&ClientIdScheme::X509SanDns)
                {
                    params
                        .x509_ca_certificate
                        .as_ref()
                        .ok_or(ConfigValidationError::MissingX509CaCertificate)?;
                };

                // URL schemes are used to select provider, hence must not be duplicated
                validate_url_scheme_unique(
                    &mut openid_url_schemes,
                    name,
                    params.url_scheme.to_string(),
                )?;

                let ble = OpenID4VCBLE::new(
                    data_provider.get_proof_repository(),
                    data_provider.get_interaction_repository(),
                    data_provider.get_did_repository(),
                    did_method_provider.clone(),
                    formatter_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    ble.clone(),
                    config.clone(),
                    params.clone(),
                );
                let http = OpenID4VCHTTP::new(
                    core_base_url.clone(),
                    formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    client.clone(),
                    params.clone(),
                );

                let mut mqtt = None;
                if let Some(mqtt_client) = mqtt_client.clone() {
                    if let Ok(transport_params) = config.transport.get(TransportType::Mqtt.as_ref())
                    {
                        mqtt = Some(OpenId4VcMqtt::new(
                            mqtt_client.clone(),
                            config.clone(),
                            transport_params,
                            params.clone(),
                            data_provider.get_interaction_repository(),
                            data_provider.get_proof_repository(),
                            data_provider.get_did_repository(),
                            key_algorithm_provider.clone(),
                            formatter_provider.clone(),
                            did_method_provider.clone(),
                            key_provider.clone(),
                        ));
                    };
                }
                let protocol = Arc::new(OpenID4VC::new(config.clone(), params, http, ble, mqtt));
                fields.capabilities = Some(json!(protocol.get_capabilities()));
                providers.insert(name.to_string(), protocol);
            }
            VerificationProtocolType::IsoMdl => {
                let protocol = Arc::new(VerificationProtocolWrapper::new(IsoMdl::new(
                    config.clone(),
                    formatter_provider.clone(),
                    key_provider.clone(),
                    key_algorithm_provider.clone(),
                    ble.clone(),
                )));
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

pub(crate) type FormatMapper =
    Arc<dyn Fn(&str) -> Result<FormatType, VerificationProtocolError> + Send + Sync>;
pub(crate) type TypeToDescriptorMapper = Arc<
    dyn Fn(
            &FormatType,
        )
            -> Result<HashMap<String, OpenID4VpPresentationFormat>, VerificationProtocolError>
        + Send
        + Sync,
>;

/// This trait contains methods for exchanging credentials between issuers,
/// holders, and verifiers.
#[cfg_attr(any(test, feature = "mock"), mockall::automock(type InteractionContext = ();))]
#[async_trait::async_trait]
#[allow(clippy::too_many_arguments)]
pub(crate) trait VerificationProtocolImpl: Send + Sync {
    type InteractionContext: Clone;

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
        transport: String,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError>;

    /// Rejects a verifier's request for credential presentation.
    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError>;

    /// Submits a presentation to a verifier.
    #[allow(clippy::too_many_arguments)]
    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<UpdateResponse, VerificationProtocolError>;

    /// Takes a proof request and filters held credentials,
    /// returning those which are acceptable for the request.
    ///
    /// Storage access is needed to check held credentials.
    async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        context: Self::InteractionContext,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError>;

    /// Takes the VP interaction context and returns a holder binding context, if any.
    fn holder_get_holder_binding_context(
        &self,
        _proof: &Proof,
        _context: Self::InteractionContext,
    ) -> Result<Option<HolderBindingCtx>, VerificationProtocolError> {
        Ok(None)
    }

    /// Generates QR-code content to start the proof request flow.
    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
        callback: Option<BoxFuture<'static, ()>>,
        client_id_scheme: ClientIdScheme,
    ) -> Result<ShareResponse<Self::InteractionContext>, VerificationProtocolError>;

    /// Checks if the submitted presentation complies with the given proof request.
    async fn verifier_handle_proof(
        &self,
        proof: &Proof,
        submission: &[u8],
    ) -> Result<Vec<DetailCredential>, VerificationProtocolError>;

    // General methods:
    /// Called when proof needs to be retracted. Use this function for closing opened transmissions, buffers, etc.
    async fn retract_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError>;

    fn get_capabilities(&self) -> VerificationProtocolCapabilities;
}

#[cfg(test)]
pub(crate) type MockVerificationProtocol =
    VerificationProtocolWrapper<MockVerificationProtocolImpl>;

#[derive(Default)]
pub(crate) struct VerificationProtocolWrapper<T> {
    pub inner: T,
}

impl<T> VerificationProtocolWrapper<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl<T> VerificationProtocolImpl for VerificationProtocolWrapper<T>
where
    T: VerificationProtocolImpl,
    T::InteractionContext: Serialize + DeserializeOwned,
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
        transport: String,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        self.inner
            .holder_handle_invitation(url, organisation, storage_access, transport)
            .await
    }

    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        self.inner.holder_reject_proof(proof).await
    }

    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        self.inner
            .holder_submit_proof(proof, credential_presentations, holder_did, key, jwk_key_id)
            .await
    }

    async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        interaction_data: Self::InteractionContext,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
        let interaction_data = serde_json::from_value(interaction_data)
            .map_err(VerificationProtocolError::JsonError)?;
        self.inner
            .holder_get_presentation_definition(proof, interaction_data, storage_access)
            .await
    }

    async fn retract_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        self.inner.retract_proof(proof).await
    }

    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
        callback: Option<BoxFuture<'static, ()>>,
        client_id_scheme: ClientIdScheme,
    ) -> Result<ShareResponse<Self::InteractionContext>, VerificationProtocolError> {
        self.inner
            .verifier_share_proof(
                proof,
                format_to_type_mapper,
                key_id,
                encryption_key_jwk,
                vp_formats,
                type_to_descriptor,
                callback,
                client_id_scheme,
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
    ) -> Result<Vec<DetailCredential>, VerificationProtocolError> {
        self.inner.verifier_handle_proof(proof, submission).await
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        self.inner.get_capabilities()
    }
}

impl<T> VerificationProtocol for VerificationProtocolWrapper<T>
where
    T: VerificationProtocolImpl,
    T::InteractionContext: Serialize + DeserializeOwned,
{
}

pub(crate) struct VerificationProtocolProviderImpl {
    protocols: HashMap<String, Arc<dyn VerificationProtocol>>,
}

impl VerificationProtocolProviderImpl {
    pub(crate) fn new(protocols: HashMap<String, Arc<dyn VerificationProtocol>>) -> Self {
        Self { protocols }
    }
}

#[async_trait::async_trait]
impl VerificationProtocolProvider for VerificationProtocolProviderImpl {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn VerificationProtocol>> {
        self.protocols.get(protocol_id).cloned()
    }

    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn VerificationProtocol>)> {
        self.protocols
            .iter()
            .find(|(_, protocol)| protocol.holder_can_handle(url))
            .map(|(id, protocol)| (id.to_owned(), protocol.to_owned()))
    }
}
