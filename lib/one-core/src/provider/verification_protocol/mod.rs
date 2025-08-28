use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dto::{
    InvitationResponseDTO, PresentationDefinitionResponseDTO, PresentedCredential, ShareResponse,
    UpdateResponse, VerificationProtocolCapabilities,
};
use error::VerificationProtocolError;
use futures::future::BoxFuture;
use openid4vp::draft20::OpenID4VP20HTTP;
use openid4vp::draft20::model::OpenID4Vp20Params;
use openid4vp::draft20_swiyu::OpenID4VP20Swiyu;
use openid4vp::draft25::OpenID4VP25HTTP;
use openid4vp::draft25::model::OpenID4Vp25Params;
use openid4vp::model::OpenID4VpPresentationFormat;
use openid4vp::proximity_draft00::{OpenID4VPProximityDraft00, OpenID4VPProximityDraft00Params};
use serde::de::Deserialize;
use serde_json::json;
use url::Url;

use super::mqtt_client::MqttClient;
use crate::config::ConfigValidationError;
use crate::config::core_config::{
    CoreConfig, FormatType, VerificationProtocolConfig, VerificationProtocolType,
};
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
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::verification_protocol::iso_mdl::IsoMdl;
use crate::provider::verification_protocol::openid4vp::draft20_swiyu::OpenID4Vp20SwiyuParams;
use crate::provider::verification_protocol::openid4vp::final1_0::OpenID4VPFinal1_0;
use crate::provider::verification_protocol::scan_to_verify::ScanToVerify;
use crate::repository::DataRepository;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::proof::dto::ShareProofRequestParamsDTO;
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
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
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
                    credential_formatter_provider.clone(),
                    key_algorithm_provider.clone(),
                    did_method_provider.clone(),
                    certificate_validator.clone(),
                ));
                fields.capabilities = Some(json!(protocol.get_capabilities()));
                providers.insert(name.to_string(), protocol);
            }
            VerificationProtocolType::OpenId4VpFinal1_0 => {
                use openid4vp::final1_0::model::Params;
                let params = fields.deserialize::<Params>().map_err(|source| {
                    ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    }
                })?;

                let final1_0 = OpenID4VPFinal1_0::new(
                    core_base_url.clone(),
                    credential_formatter_provider.clone(),
                    presentation_formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
                    client.clone(),
                    params.clone(),
                    config.clone(),
                );

                let protocol = Arc::new(final1_0);
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

                let http25 = OpenID4VP25HTTP::new(
                    core_base_url.clone(),
                    credential_formatter_provider.clone(),
                    presentation_formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
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
                // URL schemes are used to select provider, hence must not be duplicated
                validate_url_scheme_unique(
                    &mut openid_url_schemes,
                    name,
                    params.url_scheme.to_string(),
                )?;
                let http20 = openid4vp_draft20_from_params(
                    core_base_url.clone(),
                    credential_formatter_provider.clone(),
                    presentation_formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
                    client.clone(),
                    params.clone(),
                    config.clone(),
                )?;
                let protocol = Arc::new(http20);
                fields.capabilities = Some(json!(protocol.get_capabilities()));
                providers.insert(name.to_string(), protocol);
            }
            VerificationProtocolType::OpenId4VpDraft20Swiyu => {
                let params = fields
                    .deserialize::<OpenID4Vp20SwiyuParams>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;
                // URL schemes are used to select provider, hence must not be duplicated
                validate_url_scheme_unique(&mut openid_url_schemes, name, "https".to_string())?;
                let http20 = openid4vp_draft20_from_params(
                    core_base_url.clone(),
                    credential_formatter_provider.clone(),
                    presentation_formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
                    client.clone(),
                    params.into(),
                    config.clone(),
                )?;
                let protocol = Arc::new(OpenID4VP20Swiyu::new(http20, client.clone()));
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
                    key_algorithm_provider.clone(),
                    credential_formatter_provider.clone(),
                    presentation_formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
                    ble.clone(),
                );
                fields.capabilities = Some(json!(protocol.get_capabilities()));
                providers.insert(name.to_string(), Arc::new(protocol));
            }
            VerificationProtocolType::IsoMdl => {
                let protocol = Arc::new(IsoMdl::new(
                    config.clone(),
                    presentation_formatter_provider.clone(),
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

#[allow(clippy::too_many_arguments)]
fn openid4vp_draft20_from_params(
    core_base_url: Option<String>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    client: Arc<dyn HttpClient>,
    params: OpenID4Vp20Params,
    config: Arc<CoreConfig>,
) -> Result<OpenID4VP20HTTP, ConfigValidationError> {
    Ok(OpenID4VP20HTTP::new(
        core_base_url,
        credential_formatter_provider,
        presentation_formatter_provider,
        did_method_provider,
        key_algorithm_provider,
        key_provider,
        certificate_validator,
        client,
        params,
        config,
    ))
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
        type_to_descriptor: TypeToDescriptorMapper,
        on_submission_callback: Option<BoxFuture<'static, ()>>,
        params: Option<ShareProofRequestParamsDTO>,
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
