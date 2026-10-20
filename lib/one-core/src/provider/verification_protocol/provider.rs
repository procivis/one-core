use std::sync::Arc;

use itertools::Itertools;
use url::Url;

use super::VerificationProtocol;
use super::decorators::CapabilityChecked;
use super::iso_mdl::IsoMdl;
use super::openid4vp::final1_0::OpenID4VPFinal1_0;
use super::openid4vp::final1_0_swiyu::{OpenID4VPFinalSwiyu, swiyu_to_final_params};
use super::openid4vp::proximity_draft00::OpenID4VPProximityDraft00;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, Fields, VerificationProtocolType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::proto::bluetooth_low_energy::ble_resource::BleWaiter;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::mqtt_client::MqttClient;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::swiyu_http_client;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::provider_directory::{InitializationError, ProviderDirectory};
use crate::provider::transaction_data::provider::TransactionDataProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait VerificationProtocolProvider: Send + Sync {
    fn get_protocol(&self, protocol_id: &str)
    -> Result<Arc<dyn VerificationProtocol>, NestedError>;
    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn VerificationProtocol>)>;
}

#[async_trait::async_trait]
impl VerificationProtocolProvider
    for ProviderDirectory<String, Fields<VerificationProtocolType>, dyn VerificationProtocol>
{
    fn get_protocol(
        &self,
        protocol_id: &str,
    ) -> Result<Arc<dyn VerificationProtocol>, NestedError> {
        self.provider(protocol_id)
    }

    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn VerificationProtocol>)> {
        let get_order = |id: &String| {
            self.config(id)
                .ok()
                .and_then(|entry| entry.order)
                .unwrap_or(0)
        };
        let sorted_protocols = self
            .iter()
            .sorted_by(|(a, _), (b, _)| Ord::cmp(&get_order(a), &get_order(b)));

        sorted_protocols
            .into_iter()
            .find(|(_, protocol)| protocol.holder_can_handle(url))
            .map(|(id, protocol)| (id.to_owned(), protocol.to_owned()))
    }
}

#[expect(clippy::too_many_arguments)]
fn initialize_provider(
    name: &str,
    fields: &Fields<VerificationProtocolType>,
    core_config: &Arc<CoreConfig>,
    core_base_url: &Option<String>,
    credential_repository: &Arc<dyn CredentialRepository>,
    credential_schema_repository: &Arc<dyn CredentialSchemaRepository>,
    interaction_repository: &Arc<dyn InteractionRepository>,
    proof_repository: &Arc<dyn ProofRepository>,
    credential_formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: &Arc<dyn PresentationFormatterProvider>,
    key_provider: &Arc<dyn KeyProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    identifier_creator: &Arc<dyn IdentifierCreator>,
    ble: &Option<BleWaiter>,
    client: &Arc<dyn HttpClient>,
    mqtt_client: &Option<Arc<dyn MqttClient>>,
    nfc_hce: &Option<Arc<dyn NfcHce>>,
    wrp_validator: &Arc<dyn WRPValidator>,
    ecosystem_provider: &Arc<dyn EcosystemDirectory>,
    transaction_data_provider: &Arc<dyn TransactionDataProvider>,
) -> Result<Arc<dyn VerificationProtocol>, InitializationError> {
    let protocol: Arc<dyn VerificationProtocol> = match fields.r#type {
        VerificationProtocolType::OpenId4VpFinal1_0 => Arc::new(OpenID4VPFinal1_0::new(
            name.to_owned(),
            core_base_url.clone(),
            credential_formatter_provider.clone(),
            presentation_formatter_provider.clone(),
            did_method_provider.clone(),
            key_algorithm_provider.clone(),
            key_provider.clone(),
            certificate_validator.clone(),
            credential_repository.clone(),
            credential_schema_repository.clone(),
            interaction_repository.clone(),
            proof_repository.clone(),
            wrp_validator.clone(),
            ecosystem_provider.clone(),
            transaction_data_provider.clone(),
            client.clone(),
            fields.merge_fields(),
            core_config.clone(),
        )?),
        VerificationProtocolType::OpenId4VpFinal1_0Swiyu => {
            let final1_params = swiyu_to_final_params(fields.merge_fields()).map_err(|err| {
                InitializationError::InvalidParams {
                    key: name.to_string(),
                    source: err,
                }
            })?;
            let client = Arc::new(swiyu_http_client::ProxySwiyuHttpClient {
                client: client.clone(),
            });
            let final1 = OpenID4VPFinal1_0::new(
                name.to_owned(),
                core_base_url.clone(),
                credential_formatter_provider.clone(),
                presentation_formatter_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                key_provider.clone(),
                certificate_validator.clone(),
                credential_repository.clone(),
                credential_schema_repository.clone(),
                interaction_repository.clone(),
                proof_repository.clone(),
                wrp_validator.clone(),
                ecosystem_provider.clone(),
                transaction_data_provider.clone(),
                client.clone(),
                final1_params,
                core_config.clone(),
            )?;
            Arc::new(OpenID4VPFinalSwiyu::new(
                final1,
                client,
                fields.merge_fields(),
            )?)
        }
        VerificationProtocolType::OpenId4VpProximityDraft00 => {
            Arc::new(OpenID4VPProximityDraft00::new(
                name.to_owned(),
                mqtt_client.clone(),
                core_config.clone(),
                fields.merge_fields(),
                credential_repository.clone(),
                credential_schema_repository.clone(),
                interaction_repository.clone(),
                proof_repository.clone(),
                key_algorithm_provider.clone(),
                credential_formatter_provider.clone(),
                presentation_formatter_provider.clone(),
                did_method_provider.clone(),
                key_provider.clone(),
                certificate_validator.clone(),
                wrp_validator.clone(),
                identifier_creator.clone(),
                ecosystem_provider.clone(),
                ble.clone(),
            )?)
        }
        VerificationProtocolType::IsoMdl => Arc::new(IsoMdl::new(
            name.to_owned(),
            fields.merge_fields(),
            core_config.clone(),
            credential_repository.clone(),
            presentation_formatter_provider.clone(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
            credential_schema_repository.clone(),
            credential_formatter_provider.clone(),
            ecosystem_provider.clone(),
            wrp_validator.clone(),
            ble.clone(),
            nfc_hce.clone(),
        )?),
    };
    Ok(protocol)
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn verification_protocol_provider_from_config(
    config: &mut CoreConfig,
    core_base_url: Option<String>,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
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
    mqtt_client: Option<Arc<dyn MqttClient>>,
    nfc_hce: Option<Arc<dyn NfcHce>>,
    wrp_validator: Arc<dyn WRPValidator>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
    transaction_data_provider: Arc<dyn TransactionDataProvider>,
) -> Result<Arc<dyn VerificationProtocolProvider>, ConfigValidationError> {
    let core_config = Arc::new(config.to_owned());

    let directory = ProviderDirectory::initialize(
        config.verification_protocol.iter_mut(),
        |name: &String, fields: &Fields<VerificationProtocolType>| {
            let provider = initialize_provider(
                name,
                fields,
                &core_config,
                &core_base_url,
                &credential_repository,
                &credential_schema_repository,
                &interaction_repository,
                &proof_repository,
                &credential_formatter_provider,
                &presentation_formatter_provider,
                &key_provider,
                &certificate_validator,
                &key_algorithm_provider,
                &did_method_provider,
                &identifier_creator,
                &ble,
                &client,
                &mqtt_client,
                &nfc_hce,
                &wrp_validator,
                &ecosystem_provider,
                &transaction_data_provider,
            )?;

            let provider: Arc<dyn VerificationProtocol> = Arc::new(CapabilityChecked {
                inner: provider,
                did_method_provider: did_method_provider.clone(),
            });

            Ok(provider)
        },
    )
    .error_while("initializing verification protocol providers")?;

    Ok(Arc::new(directory))
}
