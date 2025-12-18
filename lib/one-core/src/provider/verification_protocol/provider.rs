use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use itertools::Itertools;
use serde_json::json;
use url::Url;

use super::VerificationProtocol;
use super::iso_mdl::IsoMdl;
use super::openid4vp::draft20::OpenID4VP20HTTP;
use super::openid4vp::draft20::model::OpenID4Vp20Params;
use super::openid4vp::draft20_swiyu::{OpenID4VP20Swiyu, OpenID4Vp20SwiyuParams};
use super::openid4vp::draft25::OpenID4VP25HTTP;
use super::openid4vp::draft25::model::OpenID4Vp25Params;
use super::openid4vp::final1_0::OpenID4VPFinal1_0;
use super::openid4vp::proximity_draft00::{
    OpenID4VPProximityDraft00, OpenID4VPProximityDraft00Params,
};
use super::scan_to_verify::ScanToVerify;
use crate::config::ConfigValidationError;
use crate::config::core_config::{
    CoreConfig, VerificationProtocolConfig, VerificationProtocolType,
};
use crate::proto::bluetooth_low_energy::ble_resource::BleWaiter;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::mqtt_client::MqttClient;
use crate::proto::nfc::hce::NfcHce;
use crate::provider::caching_loader::openid_metadata::OpenIDMetadataFetcher;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait VerificationProtocolProvider: Send + Sync {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn VerificationProtocol>>;
    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn VerificationProtocol>)>;
}

struct VerificationProtocolProviderImpl {
    protocols: HashMap<String, Arc<dyn VerificationProtocol>>,
    config: VerificationProtocolConfig,
}

#[async_trait::async_trait]
impl VerificationProtocolProvider for VerificationProtocolProviderImpl {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn VerificationProtocol>> {
        self.protocols.get(protocol_id).cloned()
    }

    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn VerificationProtocol>)> {
        let get_order = |id: &str| {
            self.config
                .get_fields(id)
                .ok()
                .and_then(|entry| entry.order)
                .unwrap_or(0)
        };
        let sorted_protocols = self
            .protocols
            .iter()
            .sorted_by(|(a, _), (b, _)| Ord::cmp(&get_order(a), &get_order(b)));

        sorted_protocols
            .into_iter()
            .find(|(_, protocol)| protocol.holder_can_handle(url))
            .map(|(id, protocol)| (id.to_owned(), protocol.to_owned()))
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn verification_protocol_provider_from_config(
    config: &mut CoreConfig,
    core_base_url: Option<String>,
    interaction_repository: Arc<dyn InteractionRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    ble: Option<BleWaiter>,
    client: Arc<dyn HttpClient>,
    openid_metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
    mqtt_client: Option<Arc<dyn MqttClient>>,
    nfc_hce: Option<Arc<dyn NfcHce>>,
) -> Result<Arc<dyn VerificationProtocolProvider>, ConfigValidationError> {
    let mut protocols: HashMap<String, Arc<dyn VerificationProtocol>> = HashMap::new();

    let mut openid_url_schemes = HashSet::new();

    let core_config = Arc::new(config.to_owned());

    for (name, fields) in config.verification_protocol.iter_mut() {
        let protocol: Arc<dyn VerificationProtocol> = match fields.r#type {
            VerificationProtocolType::ScanToVerify => Arc::new(ScanToVerify::new(
                credential_formatter_provider.clone(),
                key_algorithm_provider.clone(),
                did_method_provider.clone(),
                certificate_validator.clone(),
            )),
            VerificationProtocolType::OpenId4VpFinal1_0 => {
                use super::openid4vp::final1_0::model::Params;
                let params = fields.deserialize::<Params>().map_err(|source| {
                    ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    }
                })?;

                Arc::new(OpenID4VPFinal1_0::new(
                    core_base_url.clone(),
                    credential_formatter_provider.clone(),
                    presentation_formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
                    client.clone(),
                    params.clone(),
                    core_config.clone(),
                ))
            }
            VerificationProtocolType::OpenId4VpDraft25 => {
                let params = fields
                    .deserialize::<OpenID4Vp25Params>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;

                Arc::new(OpenID4VP25HTTP::new(
                    core_base_url.clone(),
                    credential_formatter_provider.clone(),
                    presentation_formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
                    client.clone(),
                    params.clone(),
                    core_config.clone(),
                ))
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
                Arc::new(openid4vp_draft20_from_params(
                    core_base_url.clone(),
                    credential_formatter_provider.clone(),
                    presentation_formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
                    client.clone(),
                    openid_metadata_cache.clone(),
                    params.clone(),
                    core_config.clone(),
                )?)
            }
            VerificationProtocolType::OpenId4VpDraft20Swiyu => {
                let params = fields
                    .deserialize::<OpenID4Vp20SwiyuParams>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;
                let allow_insecure_http = params.allow_insecure_http_transport;
                // URL schemes are used to select provider, hence must not be duplicated
                validate_url_scheme_unique(&mut openid_url_schemes, name, "https".to_string())?;
                if allow_insecure_http {
                    validate_url_scheme_unique(&mut openid_url_schemes, name, "http".to_string())?;
                };
                let http20 = openid4vp_draft20_from_params(
                    core_base_url.clone(),
                    credential_formatter_provider.clone(),
                    presentation_formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
                    client.clone(),
                    openid_metadata_cache.clone(),
                    params.into(),
                    core_config.clone(),
                )?;
                Arc::new(OpenID4VP20Swiyu::new(
                    http20,
                    client.clone(),
                    allow_insecure_http,
                ))
            }
            VerificationProtocolType::OpenId4VpProximityDraft00 => {
                let params = fields
                    .deserialize::<OpenID4VPProximityDraft00Params>()
                    .map_err(|source| ConfigValidationError::FieldsDeserialization {
                        key: name.to_owned(),
                        source,
                    })?;

                Arc::new(OpenID4VPProximityDraft00::new(
                    mqtt_client.clone(),
                    core_config.clone(),
                    params.clone(),
                    interaction_repository.clone(),
                    proof_repository.clone(),
                    key_algorithm_provider.clone(),
                    credential_formatter_provider.clone(),
                    presentation_formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_provider.clone(),
                    certificate_validator.clone(),
                    identifier_creator.clone(),
                    ble.clone(),
                ))
            }
            VerificationProtocolType::IsoMdl => Arc::new(IsoMdl::new(
                core_config.clone(),
                presentation_formatter_provider.clone(),
                key_provider.clone(),
                key_algorithm_provider.clone(),
                ble.clone(),
                nfc_hce.clone(),
            )),
        };

        fields.capabilities = Some(json!(protocol.get_capabilities()));
        protocols.insert(name.to_string(), protocol);
    }

    Ok(Arc::new(VerificationProtocolProviderImpl {
        protocols,
        config: config.verification_protocol.to_owned(),
    }))
}

#[expect(clippy::too_many_arguments)]
fn openid4vp_draft20_from_params(
    core_base_url: Option<String>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    client: Arc<dyn HttpClient>,
    openid_metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
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
        openid_metadata_cache,
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
