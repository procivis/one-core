use std::sync::Arc;

use one_crypto::CryptoProvider;
use thiserror::Error;

use crate::config::ConfigError;
use crate::config::core_config::{
    CoreConfig, DatatypeConfig, DidConfig, FormatConfig, KeyAlgorithmConfig, KeyStorageConfig,
    RevocationConfig,
};
use crate::proto::bluetooth_low_energy::ble_resource::BleWaiter;
use crate::proto::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::proto::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::clock::DefaultClock;
use crate::proto::credential_schema::importer::CredentialSchemaImporterProto;
use crate::proto::credential_schema::parser::CredentialSchemaImportParserImpl;
use crate::proto::history_decorator::certificate::CertificateHistoryDecorator;
use crate::proto::history_decorator::credential::CredentialHistoryDecorator;
use crate::proto::history_decorator::credential_schema::CredentialSchemaHistoryDecorator;
use crate::proto::history_decorator::did::DidHistoryDecorator;
use crate::proto::history_decorator::identifier::IdentifierHistoryDecorator;
use crate::proto::history_decorator::key::KeyHistoryDecorator;
use crate::proto::history_decorator::organisation::OrganisationHistoryDecorator;
use crate::proto::history_decorator::proof::ProofHistoryDecorator;
use crate::proto::history_decorator::proof_schema::ProofSchemaHistoryDecorator;
use crate::proto::history_decorator::trust_entity::TrustEntityHistoryDecorator;
use crate::proto::http_client::HttpClient;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::mqtt_client::MqttClient;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::nfc::scanner::NfcScanner;
use crate::proto::os_provider::OSInfoProviderImpl;
use crate::proto::session_provider::{NoSessionProvider, SessionProvider};
use crate::provider::blob_storage_provider::{
    BlobStorageProviderImpl, blob_storage_providers_from_config,
};
use crate::provider::caching_loader::json_ld_context::{ContextCache, JsonLdCachingLoader};
use crate::provider::caching_loader::json_schema::JsonSchemaCache;
use crate::provider::caching_loader::trust_list::TrustListCache;
use crate::provider::caching_loader::vct::VctTypeMetadataCache;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::issuance_protocol::issuance_protocol_providers_from_config;
use crate::provider::issuance_protocol::provider::IssuanceProtocolProviderImpl;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::task::provider::TaskProviderImpl;
use crate::provider::task::tasks_from_config;
use crate::provider::trust_management::provider::TrustManagementProviderImpl;
use crate::provider::verification_protocol::provider::VerificationProtocolProviderImpl;
use crate::provider::verification_protocol::verification_protocol_providers_from_config;
use crate::provider::wallet_provider_client::http_client::HTTPWalletProviderClient;
use crate::repository::DataRepository;
use crate::service::backup::BackupService;
use crate::service::cache::CacheService;
use crate::service::certificate::CertificateService;
use crate::service::config::ConfigService;
use crate::service::credential::CredentialService;
use crate::service::credential_schema::CredentialSchemaService;
use crate::service::did::DidService;
use crate::service::history::HistoryService;
use crate::service::identifier::IdentifierService;
use crate::service::jsonld::JsonLdService;
use crate::service::key::KeyService;
use crate::service::nfc::NfcService;
use crate::service::oid4vci_draft13::OID4VCIDraft13Service;
use crate::service::oid4vci_draft13_swiyu::OID4VCIDraft13SwiyuService;
use crate::service::oid4vci_final1_0::OID4VCIFinal1_0Service;
use crate::service::oid4vp_draft20::OID4VPDraft20Service;
use crate::service::oid4vp_draft25::OID4VPDraft25Service;
use crate::service::oid4vp_final1_0::OID4VPFinal1_0Service;
use crate::service::organisation::OrganisationService;
use crate::service::proof::ProofService;
use crate::service::proof_schema::ProofSchemaService;
use crate::service::revocation_list::RevocationListService;
use crate::service::ssi_holder::SSIHolderService;
use crate::service::ssi_issuer::SSIIssuerService;
use crate::service::task::TaskService;
use crate::service::trust_anchor::TrustAnchorService;
use crate::service::trust_entity::TrustEntityService;
use crate::service::vc_api::VCAPIService;
use crate::service::wallet_provider::WalletProviderService;
use crate::service::wallet_unit::WalletUnitService;

pub mod config;
pub mod provider;

pub mod model;
pub mod repository;
pub mod service;

pub mod mapper;
pub mod proto;
pub mod util;
pub mod validator;

pub type DidMethodCreator = Box<
    dyn FnOnce(
            &mut DidConfig,
            &OneCoreBuilderProviders,
        ) -> Result<Arc<dyn DidMethodProvider>, OneCoreBuildError>
        + Send,
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
        ) -> Result<
            (
                Arc<dyn CredentialFormatterProvider>,
                Arc<dyn PresentationFormatterProvider>,
            ),
            OneCoreBuildError,
        > + Send,
>;

pub type DataTypeCreator = Box<
    dyn FnOnce(&mut DatatypeConfig) -> Result<Arc<dyn DataTypeProvider>, OneCoreBuildError> + Send,
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

pub type CertificateValidatorCreator = Box<
    dyn FnOnce(
            &CoreConfig,
            &OneCoreBuilderProviders,
        ) -> Result<Arc<dyn CertificateValidator>, OneCoreBuildError>
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
    pub oid4vci_final1_0_service: OID4VCIFinal1_0Service,
    pub oid4vp_draft20_service: OID4VPDraft20Service,
    pub oid4vp_draft25_service: OID4VPDraft25Service,
    pub oid4vp_final1_0_service: OID4VPFinal1_0Service,
    pub ssi_issuer_service: SSIIssuerService,
    pub ssi_holder_service: SSIHolderService,
    pub wallet_provider_service: WalletProviderService,
    pub task_service: TaskService,
    pub jsonld_service: JsonLdService,
    pub config: Arc<CoreConfig>,
    pub vc_api_service: VCAPIService,
    pub cache_service: CacheService,
    pub wallet_unit_service: WalletUnitService,
    pub nfc_service: NfcService,
}

pub struct OneCoreBuilderProviders {
    pub core_base_url: Option<String>,
    pub crypto: Option<Arc<dyn CryptoProvider>>,
    pub did_method_provider: Option<Arc<dyn DidMethodProvider>>,
    pub key_algorithm_provider: Option<Arc<dyn KeyAlgorithmProvider>>,
    pub key_storage_provider: Option<Arc<dyn KeyProvider>>,
    pub credential_formatter_provider: Option<Arc<dyn CredentialFormatterProvider>>,
    pub presentation_formatter_provider: Option<Arc<dyn PresentationFormatterProvider>>,
    pub revocation_method_provider: Option<Arc<dyn RevocationMethodProvider>>,
    pub certificate_validator: Option<Arc<dyn CertificateValidator>>,
    pub datatype_provider: Option<Arc<dyn DataTypeProvider>>,
    pub session_provider: Arc<dyn SessionProvider>,
    //repository and providers that we initialize as we build
}

impl Default for OneCoreBuilderProviders {
    fn default() -> Self {
        Self {
            core_base_url: None,
            crypto: None,
            did_method_provider: None,
            key_algorithm_provider: None,
            key_storage_provider: None,
            credential_formatter_provider: None,
            presentation_formatter_provider: None,
            revocation_method_provider: None,
            certificate_validator: None,
            datatype_provider: None,
            session_provider: Arc::new(NoSessionProvider),
        }
    }
}

#[derive(Default)]
pub struct OneCoreBuilder {
    core_config: CoreConfig,
    providers: OneCoreBuilderProviders,
    ble_peripheral: Option<Arc<dyn BlePeripheral>>,
    ble_central: Option<Arc<dyn BleCentral>>,
    nfc_hce: Option<Arc<dyn NfcHce>>,
    nfc_scanner: Option<Arc<dyn NfcScanner>>,
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

    pub fn with_session_provider(mut self, session_provider: Arc<dyn SessionProvider>) -> Self {
        self.providers.session_provider = session_provider;
        self
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
        let did_method_provider = did_met_provider(&mut self.core_config.did, &self.providers)?;
        self.providers.did_method_provider = Some(did_method_provider);
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
        let (credential_formatter_provider, presentation_formatter_provider) = key_storage_creator(
            &mut self.core_config.format,
            &self.core_config.datatype,
            &self.providers,
        )?;

        self.providers.credential_formatter_provider = Some(credential_formatter_provider);
        self.providers.presentation_formatter_provider = Some(presentation_formatter_provider);

        Ok(self)
    }

    pub fn with_datatype_provider(
        mut self,
        creator: DataTypeCreator,
    ) -> Result<Self, OneCoreBuildError> {
        let provider = creator(&mut self.core_config.datatype)?;
        self.providers.datatype_provider = Some(provider);
        Ok(self)
    }

    pub fn with_certificate_validator(
        mut self,
        certificate_validator_creator: CertificateValidatorCreator,
    ) -> Result<Self, OneCoreBuildError> {
        let certificate_validator =
            certificate_validator_creator(&self.core_config, &self.providers)?;
        self.providers.certificate_validator = Some(certificate_validator);
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

    pub fn with_nfc(
        mut self,
        hce: Option<Arc<dyn NfcHce>>,
        scanner: Option<Arc<dyn NfcScanner>>,
    ) -> Self {
        self.nfc_hce = hce;
        self.nfc_scanner = scanner;
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
            self.nfc_hce,
            self.nfc_scanner,
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
        nfc_hce: Option<Arc<dyn NfcHce>>,
        nfc_scanner: Option<Arc<dyn NfcScanner>>,
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

        let clock = Arc::new(DefaultClock);

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

        let certificate_validator = providers
            .certificate_validator
            .as_ref()
            .ok_or(OneCoreBuildError::MissingRequiredField(
                "certificate validator is required",
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

        let credential_formatter_provider = providers
            .credential_formatter_provider
            .as_ref()
            .ok_or(OneCoreBuildError::MissingRequiredField(
                "Formatter provider is required",
            ))?
            .clone();

        let presentation_formatter_provider = providers
            .presentation_formatter_provider
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

        let blob_storage_providers = blob_storage_providers_from_config(
            &core_config.blob_storage,
            data_provider.get_blob_repository(),
        )
        .map_err(OneCoreBuildError::Config)?;
        let blob_storage_provider = Arc::new(BlobStorageProviderImpl::new(blob_storage_providers));

        let organisation_repository = Arc::new(OrganisationHistoryDecorator {
            inner: data_provider.get_organisation_repository(),
            history_repository: data_provider.get_history_repository(),
            session_provider: providers.session_provider.clone(),
        });

        let credential_schema_repository = Arc::new(CredentialSchemaHistoryDecorator {
            history_repository: data_provider.get_history_repository(),
            inner: data_provider.get_credential_schema_repository(),
            session_provider: providers.session_provider.clone(),
            core_base_url: providers.core_base_url.clone(),
        });

        let proof_schema_repository = Arc::new(ProofSchemaHistoryDecorator {
            inner: data_provider.get_proof_schema_repository(),
            history_repository: data_provider.get_history_repository(),
            session_provider: providers.session_provider.clone(),
            core_base_url: providers.core_base_url.clone(),
        });

        let certificate_repository = Arc::new(CertificateHistoryDecorator {
            inner: data_provider.get_certificate_repository(),
            history_repository: data_provider.get_history_repository(),
            session_provider: providers.session_provider.clone(),
            identifier_repository: data_provider.get_identifier_repository(),
        });

        let credential_repository = Arc::new(CredentialHistoryDecorator {
            inner: data_provider.get_credential_repository(),
            history_repository: data_provider.get_history_repository(),
            session_provider: providers.session_provider.clone(),
        });

        let key_repository = Arc::new(KeyHistoryDecorator {
            inner: data_provider.get_key_repository(),
            history_repository: data_provider.get_history_repository(),
            session_provider: providers.session_provider.clone(),
        });

        let did_repository = Arc::new(DidHistoryDecorator {
            inner: data_provider.get_did_repository(),
            history_repository: data_provider.get_history_repository(),
            session_provider: providers.session_provider.clone(),
        });

        let identifier_repository = Arc::new(IdentifierHistoryDecorator {
            inner: data_provider.get_identifier_repository(),
            history_repository: data_provider.get_history_repository(),
            session_provider: providers.session_provider.clone(),
        });

        let proof_repository = Arc::new(ProofHistoryDecorator {
            inner: data_provider.get_proof_repository(),
            history_repository: data_provider.get_history_repository(),
            session_provider: providers.session_provider.clone(),
        });

        let trust_entity_repository = Arc::new(TrustEntityHistoryDecorator {
            inner: data_provider.get_trust_entity_repository(),
            history_repository: data_provider.get_history_repository(),
            session_provider: providers.session_provider.clone(),
        });

        let credential_schema_import_parser = Arc::new(CredentialSchemaImportParserImpl::new(
            Arc::new(core_config.clone()),
            credential_formatter_provider.clone(),
            revocation_method_provider.clone(),
        ));

        let credential_schema_importer_proto = Arc::new(CredentialSchemaImporterProto::new(
            credential_formatter_provider.clone(),
            data_provider.get_credential_schema_repository(),
        ));

        let issuance_protocols = issuance_protocol_providers_from_config(
            Arc::new(core_config.clone()),
            &mut core_config.issuance_protocol,
            providers.core_base_url.clone(),
            credential_repository.clone(),
            data_provider.get_validity_credential_repository(),
            data_provider.get_wallet_unit_attestation_repository(),
            credential_formatter_provider.clone(),
            vct_type_metadata_cache,
            key_provider.clone(),
            key_algorithm_provider.clone(),
            revocation_method_provider.clone(),
            did_method_provider.clone(),
            certificate_validator.clone(),
            client.clone(),
            blob_storage_provider.clone(),
            credential_schema_importer_proto,
            credential_schema_import_parser,
        )
        .map_err(|e| OneCoreBuildError::Config(ConfigError::Validation(e)))?;

        let verification_protocols = verification_protocol_providers_from_config(
            Arc::new(core_config.clone()),
            &mut core_config.verification_protocol,
            providers.core_base_url.clone(),
            data_provider.clone(),
            credential_formatter_provider.clone(),
            presentation_formatter_provider.clone(),
            key_provider.clone(),
            certificate_validator.clone(),
            key_algorithm_provider.clone(),
            did_method_provider.clone(),
            providers.session_provider.clone(),
            ble_waiter.clone(),
            client.clone(),
            mqtt_client,
            nfc_hce.clone(),
        )
        .map_err(|e| OneCoreBuildError::Config(ConfigError::Validation(e)))?;

        let config = Arc::new(core_config);
        let issuance_provider = Arc::new(IssuanceProtocolProviderImpl::new(issuance_protocols));

        let verification_provider = Arc::new(VerificationProtocolProviderImpl::new(
            verification_protocols,
        ));

        let certificate_service = CertificateService::new(
            certificate_repository.clone(),
            key_repository.clone(),
            certificate_validator.clone(),
            providers.session_provider.clone(),
        );

        let did_service = DidService::new(
            did_repository.clone(),
            key_repository.clone(),
            identifier_repository.clone(),
            organisation_repository.clone(),
            did_method_provider.clone(),
            key_algorithm_provider.clone(),
            key_provider.clone(),
            config.clone(),
            providers.session_provider.clone(),
        );

        let credential_service = CredentialService::new(
            credential_repository.clone(),
            credential_schema_repository.clone(),
            identifier_repository.clone(),
            data_provider.get_interaction_repository(),
            revocation_method_provider.clone(),
            credential_formatter_provider.clone(),
            issuance_provider.clone(),
            did_method_provider.clone(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
            config.clone(),
            data_provider.get_validity_credential_repository(),
            client.clone(),
            certificate_validator.clone(),
            blob_storage_provider.clone(),
            providers.session_provider.clone(),
        );

        let task_providers = tasks_from_config(
            &config.task,
            data_provider.get_claim_repository(),
            credential_repository.clone(),
            data_provider.get_history_repository(),
            proof_repository.clone(),
            certificate_repository.clone(),
            identifier_repository.clone(),
            credential_service.clone(),
            certificate_validator.clone(),
            blob_storage_provider.clone(),
        )
        .map_err(OneCoreBuildError::Config)?;
        let task_provider = Arc::new(TaskProviderImpl::new(task_providers));

        let credential_schema_import_parser = Arc::new(CredentialSchemaImportParserImpl::new(
            config.clone(),
            credential_formatter_provider.clone(),
            revocation_method_provider.clone(),
        ));

        let credential_schema_importer_proto = Arc::new(CredentialSchemaImporterProto::new(
            credential_formatter_provider.clone(),
            data_provider.get_credential_schema_repository(),
        ));

        Ok(OneCore {
            trust_anchor_service: TrustAnchorService::new(
                data_provider.get_trust_anchor_repository(),
                trust_entity_repository.clone(),
                providers.core_base_url.clone(),
                config.clone(),
            ),
            trust_entity_service: TrustEntityService::new(
                data_provider.get_trust_anchor_repository(),
                trust_entity_repository,
                did_repository.clone(),
                identifier_repository.clone(),
                organisation_repository.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                trust_management_provider,
                key_provider.clone(),
                client.clone(),
                certificate_validator.clone(),
            ),
            backup_service: BackupService::new(
                data_provider.get_backup_repository(),
                data_provider.get_history_repository(),
                organisation_repository.clone(),
                config.clone(),
            ),
            organisation_service: OrganisationService::new(
                organisation_repository.clone(),
                identifier_repository.clone(),
                config.clone(),
            ),
            credential_service,
            did_service: did_service.clone(),
            certificate_service: certificate_service.clone(),
            revocation_list_service: RevocationListService::new(
                providers.core_base_url.clone(),
                credential_repository.clone(),
                data_provider.get_validity_credential_repository(),
                data_provider.get_revocation_list_repository(),
                did_method_provider.clone(),
                credential_formatter_provider.clone(),
                key_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider.clone(),
                config.clone(),
                certificate_validator.clone(),
            ),
            oid4vci_draft13_service: OID4VCIDraft13Service::new(
                providers.core_base_url.clone(),
                credential_schema_repository.clone(),
                credential_repository.clone(),
                data_provider.get_interaction_repository(),
                key_repository.clone(),
                config.clone(),
                issuance_provider.clone(),
                did_repository.clone(),
                identifier_repository.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                credential_formatter_provider.clone(),
                revocation_method_provider.clone(),
                certificate_validator.clone(),
            ),
            oid4vci_final1_0_service: OID4VCIFinal1_0Service::new(
                providers.core_base_url.clone(),
                "OPENID4VCI_FINAL1".to_string(),
                credential_schema_repository.clone(),
                credential_repository.clone(),
                data_provider.get_interaction_repository(),
                key_repository.clone(),
                config.clone(),
                issuance_provider.clone(),
                did_repository.clone(),
                identifier_repository.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                credential_formatter_provider.clone(),
                revocation_method_provider.clone(),
                certificate_validator.clone(),
                blob_storage_provider.clone(),
            ),
            oid4vci_draft13_swiyu_service: OID4VCIDraft13SwiyuService::new(
                providers.core_base_url.clone(),
                credential_schema_repository.clone(),
                credential_repository.clone(),
                data_provider.get_interaction_repository(),
                key_repository.clone(),
                config.clone(),
                issuance_provider.clone(),
                did_repository.clone(),
                identifier_repository.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                credential_formatter_provider.clone(),
                revocation_method_provider.clone(),
                certificate_validator.clone(),
            ),
            oid4vp_draft20_service: OID4VPDraft20Service::new(
                credential_repository.clone(),
                proof_repository.clone(),
                key_repository.clone(),
                key_provider.clone(),
                config.clone(),
                did_repository.clone(),
                identifier_repository.clone(),
                credential_formatter_provider.clone(),
                presentation_formatter_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider.clone(),
                data_provider.get_validity_credential_repository(),
                certificate_validator.clone(),
                certificate_repository.clone(),
                blob_storage_provider.clone(),
            ),
            oid4vp_draft25_service: OID4VPDraft25Service::new(
                credential_repository.clone(),
                proof_repository.clone(),
                key_repository.clone(),
                key_provider.clone(),
                config.clone(),
                did_repository.clone(),
                identifier_repository.clone(),
                credential_formatter_provider.clone(),
                presentation_formatter_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider.clone(),
                data_provider.get_validity_credential_repository(),
                certificate_validator.clone(),
                certificate_repository.clone(),
                blob_storage_provider.clone(),
            ),
            oid4vp_final1_0_service: OID4VPFinal1_0Service::new(
                credential_repository.clone(),
                proof_repository.clone(),
                key_repository.clone(),
                key_provider.clone(),
                config.clone(),
                did_repository.clone(),
                identifier_repository.clone(),
                credential_formatter_provider.clone(),
                presentation_formatter_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider.clone(),
                data_provider.get_validity_credential_repository(),
                certificate_validator.clone(),
                certificate_repository.clone(),
                blob_storage_provider.clone(),
            ),
            credential_schema_service: CredentialSchemaService::new(
                providers.core_base_url.clone(),
                credential_schema_repository.clone(),
                organisation_repository.clone(),
                credential_formatter_provider.clone(),
                revocation_method_provider.clone(),
                config.clone(),
                providers.session_provider.clone(),
                credential_schema_import_parser.clone(),
                credential_schema_importer_proto.clone(),
            ),
            history_service: HistoryService::new(data_provider.get_history_repository()),
            key_service: KeyService::new(
                key_repository.clone(),
                organisation_repository.clone(),
                key_provider.clone(),
                config.clone(),
                key_algorithm_provider.clone(),
                data_provider.get_history_repository(),
                providers.session_provider.clone(),
            ),
            proof_schema_service: ProofSchemaService::new(
                proof_schema_repository.clone(),
                credential_schema_repository.clone(),
                organisation_repository.clone(),
                credential_formatter_provider.clone(),
                config.clone(),
                providers.core_base_url.clone(),
                client.clone(),
                providers.session_provider.clone(),
                credential_schema_import_parser,
                credential_schema_importer_proto,
            ),
            proof_service: ProofService::new(
                proof_repository.clone(),
                key_algorithm_provider.clone(),
                proof_schema_repository,
                did_repository.clone(),
                certificate_repository.clone(),
                identifier_repository.clone(),
                data_provider.get_claim_repository(),
                credential_repository.clone(),
                credential_schema_repository.clone(),
                data_provider.get_history_repository(),
                data_provider.get_interaction_repository(),
                credential_formatter_provider.clone(),
                presentation_formatter_provider.clone(),
                revocation_method_provider.clone(),
                verification_provider.clone(),
                did_method_provider.clone(),
                ble_waiter,
                config.clone(),
                organisation_repository.clone(),
                data_provider.get_validity_credential_repository(),
                certificate_validator.clone(),
                key_repository.clone(),
                blob_storage_provider.clone(),
                nfc_hce,
                providers.session_provider.clone(),
            ),
            ssi_issuer_service: SSIIssuerService::new(
                credential_schema_repository.clone(),
                config.clone(),
                providers.core_base_url.clone(),
            ),
            // TODO - config based
            vc_api_service: VCAPIService::new(
                credential_formatter_provider.clone(),
                presentation_formatter_provider.clone(),
                key_provider.clone(),
                did_repository.clone(),
                identifier_repository.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                data_provider.get_revocation_list_repository(),
                certificate_validator.clone(),
                ContextCache::new(jsonld_caching_loader.clone(), client.clone()),
                providers.core_base_url.clone(),
            ),
            ssi_holder_service: SSIHolderService::new(
                credential_repository,
                proof_repository,
                organisation_repository.clone(),
                data_provider.get_interaction_repository(),
                credential_schema_repository,
                data_provider.get_validity_credential_repository(),
                did_repository,
                key_repository.clone(),
                identifier_repository.clone(),
                certificate_repository.clone(),
                key_provider.clone(),
                key_algorithm_provider.clone(),
                credential_formatter_provider,
                issuance_provider,
                verification_provider,
                did_method_provider.clone(),
                certificate_validator.clone(),
                config.clone(),
                client.clone(),
                blob_storage_provider,
                providers.session_provider.clone(),
            ),
            wallet_provider_service: WalletProviderService::new(
                organisation_repository.clone(),
                data_provider.get_wallet_unit_repository(),
                identifier_repository.clone(),
                data_provider.get_history_repository(),
                key_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider.clone(),
                certificate_validator.clone(),
                clock,
                providers.session_provider.clone(),
                config.clone(),
                providers.core_base_url.clone(),
            ),
            task_service: TaskService::new(task_provider),
            config_service: ConfigService::new(config.clone()),
            jsonld_service: JsonLdService::new(jsonld_caching_loader, client.clone()),
            config: config.clone(),
            cache_service: CacheService::new(data_provider.get_remote_entity_cache_repository()),
            nfc_service: NfcService::new(config.clone(), nfc_scanner),
            identifier_service: IdentifierService::new(
                identifier_repository,
                key_repository.clone(),
                certificate_repository,
                organisation_repository.clone(),
                did_service,
                certificate_service,
                config.clone(),
                providers.session_provider.clone(),
                data_provider.get_tx_manager(),
            ),
            wallet_unit_service: WalletUnitService::new(
                organisation_repository,
                data_provider.get_holder_wallet_unit_repository(),
                data_provider.get_history_repository(),
                key_repository,
                key_provider,
                key_algorithm_provider,
                Arc::new(HTTPWalletProviderClient::new(client)),
                Arc::new(OSInfoProviderImpl),
                Arc::new(DefaultClock),
                providers.core_base_url,
                config,
                providers.session_provider.clone(),
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
