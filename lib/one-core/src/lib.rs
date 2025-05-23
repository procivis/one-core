use std::sync::Arc;

use config::ConfigError;
use config::core_config::{
    CoreConfig, DatatypeConfig, FormatConfig, KeyAlgorithmConfig, KeyStorageConfig,
};
use one_crypto::CryptoProvider;
use provider::bluetooth_low_energy::low_level::ble_central::BleCentral;
use provider::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use provider::caching_loader::json_schema::JsonSchemaCache;
use provider::caching_loader::trust_list::TrustListCache;
use provider::caching_loader::vct::VctTypeMetadataCache;
use provider::credential_formatter::json_ld::context::caching_loader::ContextCache;
use provider::issuance_protocol::provider::IssuanceProtocolProviderImpl;
use provider::mqtt_client::MqttClient;
use provider::task::provider::TaskProviderImpl;
use provider::task::tasks_from_config;
use provider::trust_management::provider::TrustManagementProviderImpl;
use provider::verification_protocol::provider::VerificationProtocolProviderImpl;
use provider::verification_protocol::verification_protocol_providers_from_config;
use repository::DataRepository;
use service::backup::BackupService;
use service::certificate::CertificateService;
use service::config::ConfigService;
use service::credential::CredentialService;
use service::did::DidService;
use service::jsonld::JsonLdService;
use service::oid4vci_draft13::OID4VCIDraft13Service;
use service::oid4vp_draft20::OID4VPDraft20Service;
use service::oid4vp_draft25::OID4VPDraft25Service;
use service::organisation::OrganisationService;
use service::proof::ProofService;
use service::proof_schema::ProofSchemaService;
use service::ssi_holder::SSIHolderService;
use service::ssi_issuer::SSIIssuerService;
use service::task::TaskService;
use service::trust_anchor::TrustAnchorService;
use service::trust_entity::TrustEntityService;
use service::vc_api::VCAPIService;
use thiserror::Error;
use util::ble_resource::BleWaiter;

use crate::config::core_config::{DidConfig, RevocationConfig};
use crate::provider::credential_formatter::json_ld::context::caching_loader::JsonLdCachingLoader;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::mdl::DidMdlValidator;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::issuance_protocol::issuance_protocol_providers_from_config;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::service::cache::CacheService;
use crate::service::credential_schema::CredentialSchemaService;
use crate::service::history::HistoryService;
use crate::service::identifier::IdentifierService;
use crate::service::key::KeyService;
use crate::service::oid4vci_draft13_swiyu::OID4VCIDraft13SwiyuService;
use crate::service::revocation_list::RevocationListService;
pub mod config;
pub mod provider;

pub mod model;
pub mod repository;
pub mod service;

pub mod common_mapper;
mod common_validator;
pub mod util;

pub type DidMethodCreator = Box<
    dyn FnOnce(
            &mut DidConfig,
            &OneCoreBuilderProviders,
        ) -> Result<
            (Arc<dyn DidMethodProvider>, Option<Arc<dyn DidMdlValidator>>),
            OneCoreBuildError,
        > + Send,
>;

pub type KeyAlgorithmCreator = Box<
    dyn FnOnce(
            &mut KeyAlgorithmConfig,
            &OneCoreBuilderProviders,
        ) -> Result<Arc<dyn KeyAlgorithmProvider>, OneCoreBuildError>
        + Send,
>;

pub type KeyStorageCreator = Box<
    dyn FnOnce(
            &mut KeyStorageConfig,
            &OneCoreBuilderProviders,
        ) -> Result<Arc<dyn KeyProvider>, OneCoreBuildError>
        + Send,
>;

pub type FormatterProviderCreator = Box<
    dyn FnOnce(
            &mut FormatConfig,
            &DatatypeConfig,
            &OneCoreBuilderProviders,
        ) -> Result<Arc<dyn CredentialFormatterProvider>, OneCoreBuildError>
        + Send,
>;

pub type DataProviderCreator =
    Box<dyn FnOnce() -> Result<Arc<dyn DataRepository>, OneCoreBuildError> + Send>;

pub type RevocationMethodCreator = Box<
    dyn FnOnce(
            &mut RevocationConfig,
            &OneCoreBuilderProviders,
        ) -> Result<Arc<dyn RevocationMethodProvider>, OneCoreBuildError>
        + Send,
>;

pub struct OneCore {
    pub organisation_service: OrganisationService,
    pub backup_service: BackupService,
    pub trust_anchor_service: TrustAnchorService,
    pub trust_entity_service: TrustEntityService,
    pub did_service: DidService,
    pub certificate_service: CertificateService,
    pub credential_service: CredentialService,
    pub credential_schema_service: CredentialSchemaService,
    pub history_service: HistoryService,
    pub identifier_service: IdentifierService,
    pub key_service: KeyService,
    pub proof_schema_service: ProofSchemaService,
    pub proof_service: ProofService,
    pub config_service: ConfigService,
    pub revocation_list_service: RevocationListService,
    pub oid4vci_draft13_service: OID4VCIDraft13Service,
    pub oid4vci_draft13_swiyu_service: OID4VCIDraft13SwiyuService,
    pub oid4vp_draft20_service: OID4VPDraft20Service,
    pub oid4vp_draft25_service: OID4VPDraft25Service,
    pub ssi_issuer_service: SSIIssuerService,
    pub ssi_holder_service: SSIHolderService,
    pub task_service: TaskService,
    pub jsonld_service: JsonLdService,
    pub config: Arc<CoreConfig>,
    pub vc_api_service: VCAPIService,
    pub cache_service: CacheService,
}

#[derive(Default)]
pub struct OneCoreBuilderProviders {
    pub core_base_url: Option<String>,
    pub crypto: Option<Arc<dyn CryptoProvider>>,
    pub did_method_provider: Option<Arc<dyn DidMethodProvider>>,
    pub key_algorithm_provider: Option<Arc<dyn KeyAlgorithmProvider>>,
    pub key_storage_provider: Option<Arc<dyn KeyProvider>>,
    pub did_mdl_validator: Option<Arc<dyn DidMdlValidator>>,
    pub formatter_provider: Option<Arc<dyn CredentialFormatterProvider>>,
    pub revocation_method_provider: Option<Arc<dyn RevocationMethodProvider>>,
    //repository and providers that we initialize as we build
}

#[derive(Default)]
pub struct OneCoreBuilder {
    core_config: CoreConfig,
    providers: OneCoreBuilderProviders,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
    ble_central: Option<Arc<dyn BleCentral>>,
    mqtt_client: Option<Arc<dyn MqttClient>>,
    data_provider_creator: Option<DataProviderCreator>,
    jsonld_caching_loader: Option<JsonLdCachingLoader>,
    vct_type_metadata_cache: Option<Arc<VctTypeMetadataCache>>,
    json_schema_cache: Option<Arc<JsonSchemaCache>>,
    trust_list_cache: Option<Arc<TrustListCache>>,
    client: Option<Arc<dyn HttpClient>>,
}

#[derive(Debug, Error)]
pub enum OneCoreBuildError {
    #[error("Missing required field: `{0}`")]
    MissingRequiredField(&'static str),

    #[error("Missing dependency: `{0}`")]
    MissingDependency(String),

    #[error("Config error: `{0}`")]
    Config(ConfigError),

    #[error("Reqwest error: `{0}`")]
    Reqwest(reqwest::Error),
}

impl OneCoreBuilder {
    pub fn new(core_config: CoreConfig) -> Self {
        OneCoreBuilder {
            core_config,
            ..Default::default()
        }
    }

    pub fn with_crypto(mut self, crypto: Arc<dyn CryptoProvider>) -> Self {
        self.providers.crypto = Some(crypto);
        self
    }

    pub fn with_base_url(mut self, core_base_url: impl Into<String>) -> Self {
        self.providers.core_base_url = Some(core_base_url.into());
        self
    }

    pub fn with_key_algorithm_provider(
        mut self,
        key_algorithm_creator: KeyAlgorithmCreator,
    ) -> Result<Self, OneCoreBuildError> {
        let key_algorithm_provider =
            key_algorithm_creator(&mut self.core_config.key_algorithm, &self.providers)?;
        self.providers.key_algorithm_provider = Some(key_algorithm_provider);
        Ok(self)
    }

    pub fn with_key_storage_provider(
        mut self,
        key_storage_creator: KeyStorageCreator,
    ) -> Result<Self, OneCoreBuildError> {
        let key_storage_provider =
            key_storage_creator(&mut self.core_config.key_storage, &self.providers)?;
        self.providers.key_storage_provider = Some(key_storage_provider);
        Ok(self)
    }

    pub fn with_did_method_provider(
        mut self,
        did_met_provider: DidMethodCreator,
    ) -> Result<Self, OneCoreBuildError> {
        let (did_method_provider, did_mdl_validator) =
            did_met_provider(&mut self.core_config.did, &self.providers)?;
        self.providers.did_method_provider = Some(did_method_provider);
        self.providers.did_mdl_validator = did_mdl_validator;
        Ok(self)
    }

    pub fn with_revocation_method_provider(
        mut self,
        revocation_met_provider: RevocationMethodCreator,
    ) -> Result<Self, OneCoreBuildError> {
        let revocation_method_provider =
            revocation_met_provider(&mut self.core_config.revocation, &self.providers)?;
        self.providers.revocation_method_provider = Some(revocation_method_provider);
        Ok(self)
    }

    pub fn with_formatter_provider(
        mut self,
        key_storage_creator: FormatterProviderCreator,
    ) -> Result<Self, OneCoreBuildError> {
        let formatter_provider = key_storage_creator(
            &mut self.core_config.format,
            &self.core_config.datatype,
            &self.providers,
        )?;
        self.providers.formatter_provider = Some(formatter_provider);
        Ok(self)
    }

    pub fn with_mqtt_client(mut self, client: Arc<dyn MqttClient>) -> Self {
        self.mqtt_client = Some(client);
        self
    }

    // Temporary
    pub fn with_data_provider_creator(mut self, data_provider: DataProviderCreator) -> Self {
        self.data_provider_creator = Some(data_provider);
        self
    }

    pub fn with_ble(
        mut self,
        peripheral: Option<Arc<dyn BlePeripheral>>,
        central: Option<Arc<dyn BleCentral>>,
    ) -> Self {
        self.ble_peripheral = peripheral;
        self.ble_central = central;
        self
    }

    pub fn with_jsonld_caching_loader(mut self, loader: JsonLdCachingLoader) -> Self {
        self.jsonld_caching_loader = Some(loader);
        self
    }

    pub fn with_client(mut self, client: Arc<dyn HttpClient>) -> Self {
        self.client = Some(client);
        self
    }

    pub fn with_vct_type_metadata_cache(mut self, cache: Arc<VctTypeMetadataCache>) -> Self {
        self.vct_type_metadata_cache = Some(cache);
        self
    }

    pub fn with_json_schema_cache(mut self, cache: Arc<JsonSchemaCache>) -> Self {
        self.json_schema_cache = Some(cache);
        self
    }

    pub fn with_trust_listcache(mut self, cache: Arc<TrustListCache>) -> Self {
        self.trust_list_cache = Some(cache);
        self
    }

    pub fn build(self) -> Result<OneCore, OneCoreBuildError> {
        OneCore::new(
            self.data_provider_creator
                .ok_or(OneCoreBuildError::MissingRequiredField(
                    "Data provider is required",
                ))?,
            self.core_config,
            self.ble_peripheral,
            self.ble_central,
            self.mqtt_client,
            self.providers,
            self.jsonld_caching_loader,
            self.client.unwrap_or(Arc::new(ReqwestClient::default())),
            self.vct_type_metadata_cache
                .ok_or(OneCoreBuildError::MissingRequiredField(
                    "VCT type metadata cache is required",
                ))?,
            self.trust_list_cache
                .ok_or(OneCoreBuildError::MissingRequiredField(
                    "Trust list cache is required",
                ))?,
        )
    }
}

impl OneCore {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        data_provider_creator: DataProviderCreator,
        mut core_config: CoreConfig,
        ble_peripheral: Option<Arc<dyn BlePeripheral>>,
        ble_central: Option<Arc<dyn BleCentral>>,
        mqtt_client: Option<Arc<dyn MqttClient>>,
        providers: OneCoreBuilderProviders,
        jsonld_caching_loader: Option<JsonLdCachingLoader>,
        client: Arc<dyn HttpClient>,
        vct_type_metadata_cache: Arc<VctTypeMetadataCache>,
        trust_list_cache: Arc<TrustListCache>,
    ) -> Result<OneCore, OneCoreBuildError> {
        // For now we will just put them here.
        // We will introduce a builder later.

        let ble_waiter = match (ble_peripheral, ble_central) {
            (Some(ble_peripheral), Some(ble_central)) => {
                Some(BleWaiter::new(ble_central, ble_peripheral))
            }
            _ => None,
        };

        let did_mdl_validator = providers.did_mdl_validator.clone();

        let did_method_provider = providers
            .did_method_provider
            .as_ref()
            .ok_or(OneCoreBuildError::MissingRequiredField(
                "Did method provider is required",
            ))?
            .clone();

        let key_algorithm_provider = providers
            .key_algorithm_provider
            .as_ref()
            .ok_or(OneCoreBuildError::MissingRequiredField(
                "Key algorithm provider is required",
            ))?
            .clone();

        let key_provider = providers
            .key_storage_provider
            .as_ref()
            .ok_or(OneCoreBuildError::MissingRequiredField(
                "Key provider is required",
            ))?
            .clone();

        let revocation_method_provider = providers
            .revocation_method_provider
            .as_ref()
            .ok_or(OneCoreBuildError::MissingRequiredField(
                "Revocation method provider is required",
            ))?
            .clone();

        let jsonld_caching_loader = jsonld_caching_loader.ok_or(
            OneCoreBuildError::MissingRequiredField("Caching loader is required"),
        )?;

        let data_provider = data_provider_creator()?;

        let formatter_provider = providers
            .formatter_provider
            .as_ref()
            .ok_or(OneCoreBuildError::MissingRequiredField(
                "Formatter provider is required",
            ))?
            .clone();

        let trust_managers = crate::provider::trust_management::provider::from_config(
            client.clone(),
            &mut core_config.trust_management,
            trust_list_cache,
        )
        .map_err(OneCoreBuildError::Config)?;
        let trust_management_provider = Arc::new(TrustManagementProviderImpl::new(trust_managers));

        let issuance_protocols = issuance_protocol_providers_from_config(
            Arc::new(core_config.clone()),
            &mut core_config.issuance_protocol,
            providers.core_base_url.clone(),
            data_provider.get_credential_repository(),
            data_provider.get_validity_credential_repository(),
            data_provider.get_revocation_list_repository(),
            data_provider.get_history_repository(),
            formatter_provider.clone(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
            revocation_method_provider.clone(),
            did_method_provider.clone(),
            client.clone(),
        )
        .map_err(|e| OneCoreBuildError::Config(ConfigError::Validation(e)))?;

        let verification_protocols = verification_protocol_providers_from_config(
            Arc::new(core_config.clone()),
            &mut core_config.verification_protocol,
            providers.core_base_url.clone(),
            data_provider.clone(),
            formatter_provider.clone(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
            did_method_provider.clone(),
            ble_waiter.clone(),
            client.clone(),
            mqtt_client,
        )
        .map_err(|e| OneCoreBuildError::Config(ConfigError::Validation(e)))?;

        let config = Arc::new(core_config);
        let issuance_provider = Arc::new(IssuanceProtocolProviderImpl::new(issuance_protocols));

        let verification_provider = Arc::new(VerificationProtocolProviderImpl::new(
            verification_protocols,
        ));

        let certificate_service = CertificateService::new(
            data_provider.get_certificate_repository(),
            data_provider.get_key_repository(),
            key_algorithm_provider.clone(),
            client.clone(),
        );

        let did_service = DidService::new(
            data_provider.get_did_repository(),
            data_provider.get_key_repository(),
            data_provider.get_identifier_repository(),
            data_provider.get_organisation_repository(),
            did_method_provider.clone(),
            key_algorithm_provider.clone(),
            key_provider.clone(),
            config.clone(),
        );

        let credential_service = CredentialService::new(
            data_provider.get_credential_repository(),
            data_provider.get_credential_schema_repository(),
            data_provider.get_identifier_repository(),
            data_provider.get_history_repository(),
            data_provider.get_interaction_repository(),
            data_provider.get_revocation_list_repository(),
            revocation_method_provider.clone(),
            formatter_provider.clone(),
            issuance_provider.clone(),
            did_method_provider.clone(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
            config.clone(),
            data_provider.get_validity_credential_repository(),
            providers.core_base_url.clone(),
            client.clone(),
        );

        let task_providers = tasks_from_config(
            &config.task,
            data_provider.get_claim_repository(),
            data_provider.get_credential_repository(),
            data_provider.get_history_repository(),
            data_provider.get_proof_repository(),
            data_provider.get_certificate_repository(),
            data_provider.get_identifier_repository(),
            credential_service.clone(),
            certificate_service.clone(),
        )
        .map_err(OneCoreBuildError::Config)?;
        let task_provider = Arc::new(TaskProviderImpl::new(task_providers));

        Ok(OneCore {
            trust_anchor_service: TrustAnchorService::new(
                data_provider.get_trust_anchor_repository(),
                data_provider.get_trust_entity_repository(),
                providers.core_base_url.clone(),
                config.clone(),
            ),
            trust_entity_service: TrustEntityService::new(
                data_provider.get_trust_anchor_repository(),
                data_provider.get_trust_entity_repository(),
                data_provider.get_did_repository(),
                data_provider.get_identifier_repository(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                trust_management_provider,
                key_provider.clone(),
                client.clone(),
            ),
            backup_service: BackupService::new(
                data_provider.get_backup_repository(),
                data_provider.get_history_repository(),
                data_provider.get_organisation_repository(),
                config.clone(),
            ),
            organisation_service: OrganisationService::new(
                data_provider.get_organisation_repository(),
            ),
            credential_service,
            did_service: did_service.clone(),
            certificate_service: certificate_service.clone(),
            revocation_list_service: RevocationListService::new(
                providers.core_base_url.clone(),
                data_provider.get_credential_repository(),
                data_provider.get_validity_credential_repository(),
                data_provider.get_revocation_list_repository(),
                did_method_provider.clone(),
                formatter_provider.clone(),
                key_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider.clone(),
                config.clone(),
            ),
            oid4vci_draft13_service: OID4VCIDraft13Service::new(
                providers.core_base_url.clone(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_interaction_repository(),
                config.clone(),
                issuance_provider.clone(),
                data_provider.get_did_repository(),
                data_provider.get_identifier_repository(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                formatter_provider.clone(),
            ),
            oid4vci_draft13_swiyu_service: OID4VCIDraft13SwiyuService::new(
                providers.core_base_url.clone(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_interaction_repository(),
                config.clone(),
                issuance_provider.clone(),
                data_provider.get_did_repository(),
                data_provider.get_identifier_repository(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                formatter_provider.clone(),
            ),
            oid4vp_draft20_service: OID4VPDraft20Service::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_key_repository(),
                key_provider.clone(),
                config.clone(),
                data_provider.get_did_repository(),
                data_provider.get_identifier_repository(),
                formatter_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider.clone(),
                data_provider.get_validity_credential_repository(),
            ),
            oid4vp_draft25_service: OID4VPDraft25Service::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_key_repository(),
                key_provider.clone(),
                config.clone(),
                data_provider.get_did_repository(),
                data_provider.get_identifier_repository(),
                formatter_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider.clone(),
                data_provider.get_validity_credential_repository(),
            ),
            credential_schema_service: CredentialSchemaService::new(
                providers.core_base_url.clone(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_history_repository(),
                data_provider.get_organisation_repository(),
                formatter_provider.clone(),
                revocation_method_provider.clone(),
                config.clone(),
            ),
            history_service: HistoryService::new(data_provider.get_history_repository()),
            key_service: KeyService::new(
                data_provider.get_key_repository(),
                data_provider.get_organisation_repository(),
                did_mdl_validator,
                key_provider.clone(),
                config.clone(),
                key_algorithm_provider.clone(),
                data_provider.get_history_repository(),
            ),
            proof_schema_service: ProofSchemaService::new(
                data_provider.get_proof_schema_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_organisation_repository(),
                data_provider.get_history_repository(),
                formatter_provider.clone(),
                revocation_method_provider.clone(),
                config.clone(),
                providers.core_base_url.clone(),
                client.clone(),
            ),
            proof_service: ProofService::new(
                data_provider.get_proof_repository(),
                key_algorithm_provider.clone(),
                key_provider.clone(),
                data_provider.get_proof_schema_repository(),
                data_provider.get_did_repository(),
                data_provider.get_identifier_repository(),
                data_provider.get_claim_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_history_repository(),
                data_provider.get_interaction_repository(),
                formatter_provider.clone(),
                revocation_method_provider.clone(),
                verification_provider.clone(),
                did_method_provider.clone(),
                ble_waiter,
                config.clone(),
                providers.core_base_url.clone(),
                data_provider.get_organisation_repository().clone(),
                data_provider.get_validity_credential_repository().clone(),
            ),
            ssi_issuer_service: SSIIssuerService::new(
                data_provider.get_credential_schema_repository(),
                config.clone(),
                providers.core_base_url.clone(),
            ),
            // TODO - config based
            vc_api_service: VCAPIService::new(
                formatter_provider.clone(),
                key_provider.clone(),
                data_provider.get_did_repository(),
                data_provider.get_identifier_repository(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                data_provider.get_revocation_list_repository(),
                ContextCache::new(jsonld_caching_loader.clone(), client.clone()),
                providers.core_base_url,
            ),
            ssi_holder_service: SSIHolderService::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_organisation_repository(),
                data_provider.get_interaction_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_validity_credential_repository(),
                data_provider.get_did_repository(),
                data_provider.get_identifier_repository(),
                key_provider,
                key_algorithm_provider,
                formatter_provider,
                issuance_provider,
                verification_provider,
                did_method_provider,
                config.clone(),
                client.clone(),
                vct_type_metadata_cache,
            ),
            task_service: TaskService::new(task_provider),
            config_service: ConfigService::new(config.clone()),
            jsonld_service: JsonLdService::new(jsonld_caching_loader, client),
            config: config.clone(),
            cache_service: CacheService::new(data_provider.get_remote_entity_cache_repository()),
            identifier_service: IdentifierService::new(
                data_provider.get_identifier_repository(),
                data_provider.get_key_repository(),
                data_provider.get_certificate_repository(),
                data_provider.get_organisation_repository(),
                did_service,
                certificate_service,
                config,
            ),
        })
    }

    pub fn version() -> Version {
        use shadow_rs::shadow;

        shadow!(build);

        Version {
            target: build::BUILD_RUST_CHANNEL.to_owned(),
            build_time: build::BUILD_TIME_3339.to_owned(),
            branch: build::BRANCH.to_owned(),
            tag: build::TAG.to_owned(),
            commit: build::COMMIT_HASH.to_owned(),
            rust_version: build::RUST_VERSION.to_owned(),
            pipeline_id: build::CI_PIPELINE_ID.to_owned(),
        }
    }
}

pub struct Version {
    pub target: String,
    pub build_time: String,
    pub branch: String,
    pub tag: String,
    pub commit: String,
    pub rust_version: String,
    pub pipeline_id: String,
}
