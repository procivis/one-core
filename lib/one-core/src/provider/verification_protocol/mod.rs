use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dto::{PresentationDefinitionResponseDTO, VerificationProtocolCapabilities};
use error::VerificationProtocolError;
use futures::future::BoxFuture;
use openid4vp::draft20::OpenID4VP20HTTP;
use openid4vp::draft25::OpenID4VP25HTTP;
use openid4vp::model::{ClientIdScheme, OpenID4Vp25Params, OpenID4VpPresentationFormat};
use openid4vp::proximity_draft00::{OpenID4VPProximityDraft00, OpenID4VPProximityDraft00Params};
use serde::de::Deserialize;
use serde_json::json;
use shared_types::KeyId;
use url::Url;

use super::mqtt_client::MqttClient;
use crate::config::core_config::{
    CoreConfig, FormatType, VerificationProtocolConfig, VerificationProtocolType,
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
use crate::provider::verification_protocol::openid4vp::model::{
    InvitationResponseDTO, OpenID4Vp20Params, PresentedCredential, ShareResponse, UpdateResponse,
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
pub mod openid4vp;

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
pub(crate) fn serialize_interaction_data<DataDTO: ?Sized + serde::Serialize>(
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
                let protocol = Arc::new(ScanToVerify::new(
                    formatter_provider.clone(),
                    key_algorithm_provider.clone(),
                    did_method_provider.clone(),
                ));
                fields.capabilities = Some(json!(protocol.get_capabilities()));
                providers.insert(name.to_string(), protocol);
            }
            VerificationProtocolType::OpenId4VpDraft25 => {
                let params = fields
                    .deserialize::<OpenID4Vp25Params>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
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

                let http25 = OpenID4VP25HTTP::new(
                    core_base_url.clone(),
                    formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    client.clone(),
                    params.clone(),
                    config.clone(),
                );

                let protocol = Arc::new(http25);
                fields.capabilities = Some(json!(protocol.get_capabilities()));
                providers.insert(name.to_string(), protocol);
            }
            VerificationProtocolType::OpenId4VpDraft20 => {
                let params = fields
                    .deserialize::<OpenID4Vp20Params>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
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

                let http20 = OpenID4VP20HTTP::new(
                    core_base_url.clone(),
                    formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    client.clone(),
                    params.clone(),
                    config.clone(),
                );

                let protocol = Arc::new(http20);
                fields.capabilities = Some(json!(protocol.get_capabilities()));
                providers.insert(name.to_string(), protocol);
            }
            VerificationProtocolType::OpenId4VpProximityDraft00 => {
                let params = fields
                    .deserialize::<OpenID4VPProximityDraft00Params>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;

                let protocol = OpenID4VPProximityDraft00::new(
                    mqtt_client.clone(),
                    config.clone(),
                    params.clone(),
                    data_provider.get_interaction_repository(),
                    data_provider.get_proof_repository(),
                    data_provider.get_did_repository(),
                    key_algorithm_provider.clone(),
                    formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_provider.clone(),
                );
                fields.capabilities = Some(json!(protocol.get_capabilities()));
                providers.insert(name.to_string(), Arc::new(protocol));
            }
            VerificationProtocolType::IsoMdl => {
                let protocol = Arc::new(IsoMdl::new(
                    config.clone(),
                    formatter_provider.clone(),
                    key_provider.clone(),
                    key_algorithm_provider.clone(),
                    ble.clone(),
                ));
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

/// This trait contains methods for exchanging credentials between holders and verifiers.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
#[allow(clippy::too_many_arguments)]
pub(crate) trait VerificationProtocol: Send + Sync {
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
        context: serde_json::Value,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError>;

    /// Takes the VP interaction context and returns a holder binding context, if any.
    fn holder_get_holder_binding_context(
        &self,
        _proof: &Proof,
        _context: serde_json::Value,
    ) -> Result<Option<HolderBindingCtx>, VerificationProtocolError>;

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
    ) -> Result<ShareResponse<serde_json::Value>, VerificationProtocolError>;

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
