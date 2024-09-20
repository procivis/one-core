use std::collections::HashMap;
use std::sync::Arc;

use config::core_config::{
    CoreConfig, DatatypeConfig, FormatConfig, KeyAlgorithmConfig, KeyStorageConfig,
};
use config::ConfigError;
use one_crypto::CryptoProvider;
use one_providers::credential_formatter::imp::json_ld::context::caching_loader::JsonLdCachingLoader;
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::did::provider::DidMethodProvider;
use one_providers::exchange_protocol::imp::provider::ExchangeProtocolProviderImpl;
use one_providers::exchange_protocol::provider::ExchangeProtocol;
use one_providers::http_client::imp::reqwest_client::ReqwestClient;
use one_providers::http_client::HttpClient;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use one_providers::key_storage::provider::KeyProvider;
use one_providers::revocation::provider::RevocationMethodProvider;
use provider::bluetooth_low_energy::low_level::ble_central::BleCentral;
use provider::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use provider::exchange_protocol::provider::ExchangeProtocolProviderCoreImpl;
use provider::task::provider::TaskProviderImpl;
use provider::task::tasks_from_config;
use provider::trust_management::provider::TrustManagementProviderImpl;
use repository::DataRepository;
use service::backup::BackupService;
use service::config::ConfigService;
use service::credential::CredentialService;
use service::did::DidService;
use service::jsonld::JsonLdService;
use service::organisation::OrganisationService;
use service::proof::ProofService;
use service::proof_schema::ProofSchemaService;
use service::ssi_holder::SSIHolderService;
use service::ssi_issuer::SSIIssuerService;
use service::ssi_verifier::SSIVerifierService;
use service::task::TaskService;
use service::trust_anchor::TrustAnchorService;
use service::trust_entity::TrustEntityService;
use service::vc_api::VCAPIService;
use util::ble_resource::BleWaiter;

use crate::config::core_config::{DidConfig, RevocationConfig};

pub mod config;
pub mod provider;

pub mod model;
pub mod repository;
pub mod service;

pub mod common_mapper;
mod common_validator;
pub mod util;

use crate::provider::did_method::mdl::DidMdlValidator;
use crate::provider::exchange_protocol::exchange_protocol_providers_from_config;
use crate::service::credential_schema::CredentialSchemaService;
use crate::service::history::HistoryService;
use crate::service::key::KeyService;
use crate::service::oidc::OIDCService;
use crate::service::revocation_list::RevocationListService;

pub type DidMethodCreator = Box<
    dyn FnOnce(
        &mut DidConfig,
        &OneCoreBuilderProviders,
    ) -> (Arc<dyn DidMethodProvider>, Option<Arc<dyn DidMdlValidator>>),
>;

pub type KeyAlgorithmCreator = Box<
    dyn FnOnce(&mut KeyAlgorithmConfig, &OneCoreBuilderProviders) -> Arc<dyn KeyAlgorithmProvider>,
>;

pub type KeyStorageCreator =
    Box<dyn FnOnce(&mut KeyStorageConfig, &OneCoreBuilderProviders) -> Arc<dyn KeyProvider>>;

pub type FormatterProviderCreator = Box<
    dyn FnOnce(
        &mut FormatConfig,
        &DatatypeConfig,
        &OneCoreBuilderProviders,
    ) -> Arc<dyn CredentialFormatterProvider>,
>;

pub type DataProviderCreator = Box<dyn FnOnce() -> Arc<dyn DataRepository>>;

pub type RevocationMethodCreator = Box<
    dyn FnOnce(
        &mut RevocationConfig,
        &OneCoreBuilderProviders,
    ) -> Arc<dyn RevocationMethodProvider>,
>;

pub struct OneCore {
    pub exchange_protocols: HashMap<String, Arc<dyn ExchangeProtocol>>,
    pub organisation_service: OrganisationService,
    pub backup_service: BackupService,
    pub trust_anchor_service: TrustAnchorService,
    pub trust_entity_service: TrustEntityService,
    pub did_service: DidService,
    pub credential_service: CredentialService,
    pub credential_schema_service: CredentialSchemaService,
    pub history_service: HistoryService,
    pub key_service: KeyService,
    pub proof_schema_service: ProofSchemaService,
    pub proof_service: ProofService,
    pub config_service: ConfigService,
    pub ssi_verifier_service: SSIVerifierService,
    pub revocation_list_service: RevocationListService,
    pub oidc_service: OIDCService,
    pub ssi_issuer_service: SSIIssuerService,
    pub ssi_holder_service: SSIHolderService,
    pub task_service: TaskService,
    pub jsonld_service: JsonLdService,
    pub config: Arc<CoreConfig>,
    pub vc_api_service: VCAPIService,
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
    data_provider_creator: Option<DataProviderCreator>,
    jsonld_caching_loader: Option<JsonLdCachingLoader>,
    client: Option<Arc<dyn HttpClient>>,
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
    ) -> Self {
        let key_algorithm_provider =
            key_algorithm_creator(&mut self.core_config.key_algorithm, &self.providers);
        self.providers.key_algorithm_provider = Some(key_algorithm_provider);
        self
    }

    pub fn with_key_storage_provider(mut self, key_storage_creator: KeyStorageCreator) -> Self {
        let key_storage_provider =
            key_storage_creator(&mut self.core_config.key_storage, &self.providers);
        self.providers.key_storage_provider = Some(key_storage_provider);
        self
    }

    pub fn with_did_method_provider(mut self, did_met_provider: DidMethodCreator) -> Self {
        let (did_method_provider, did_mdl_validator) =
            did_met_provider(&mut self.core_config.did, &self.providers);
        self.providers.did_method_provider = Some(did_method_provider);
        self.providers.did_mdl_validator = did_mdl_validator;
        self
    }

    pub fn with_revocation_method_provider(
        mut self,
        revocation_met_provider: RevocationMethodCreator,
    ) -> Self {
        let revocation_method_provider =
            revocation_met_provider(&mut self.core_config.revocation, &self.providers);
        self.providers.revocation_method_provider = Some(revocation_method_provider);
        self
    }

    pub fn with_formatter_provider(
        mut self,
        key_storage_creator: FormatterProviderCreator,
    ) -> Self {
        let formatter_provider = key_storage_creator(
            &mut self.core_config.format,
            &self.core_config.datatype,
            &self.providers,
        );
        self.providers.formatter_provider = Some(formatter_provider);
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

    pub fn build(self) -> Result<OneCore, ConfigError> {
        OneCore::new(
            self.data_provider_creator
                .expect("Data provider is required"),
            self.core_config,
            self.ble_peripheral,
            self.ble_central,
            self.providers,
            self.jsonld_caching_loader,
            self.client.unwrap_or(Arc::new(ReqwestClient::default())),
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
        providers: OneCoreBuilderProviders,
        jsonld_caching_loader: Option<JsonLdCachingLoader>,
        client: Arc<dyn HttpClient>,
    ) -> Result<OneCore, ConfigError> {
        // For now we will just put them here.
        // We will introduce a builder later.

        let ble_waiter = match (ble_peripheral, ble_central) {
            (Some(ble_peripheral), Some(ble_central)) => {
                Some(BleWaiter::new(ble_central, ble_peripheral))
            }
            _ => None,
        };

        let did_mdl_validator = providers
            .did_mdl_validator
            .as_ref()
            .expect("Did method validator is required")
            .clone();

        let did_method_provider = providers
            .did_method_provider
            .as_ref()
            .expect("Did method provider is required")
            .clone();

        let key_algorithm_provider = providers
            .key_algorithm_provider
            .as_ref()
            .expect("Key algorithm provider is required")
            .clone();

        let crypto = providers
            .crypto
            .as_ref()
            .expect("Crypto provider is required")
            .clone();

        let key_provider = providers
            .key_storage_provider
            .as_ref()
            .expect("Key provider is required")
            .clone();

        let revocation_method_provider = providers
            .revocation_method_provider
            .as_ref()
            .expect("Revocation method provider is required")
            .clone();

        let jsonld_caching_loader = jsonld_caching_loader.expect("Caching loader is required");

        let data_provider = data_provider_creator();

        let formatter_provider = providers
            .formatter_provider
            .as_ref()
            .expect("Formatter provider is required")
            .clone();

        let task_providers = tasks_from_config(
            &core_config.task,
            data_provider.get_credential_repository(),
            data_provider.get_history_repository(),
            revocation_method_provider.to_owned(),
            data_provider.get_revocation_list_repository(),
            data_provider.get_validity_credential_repository(),
            formatter_provider.to_owned(),
            key_provider.to_owned(),
            data_provider.get_proof_repository(),
            providers.core_base_url.clone(),
        )?;
        let task_provider = Arc::new(TaskProviderImpl::new(task_providers));

        let trust_managers = crate::provider::trust_management::provider::from_config(
            &mut core_config.trust_management,
        )?;
        let trust_management_provider = Arc::new(TrustManagementProviderImpl::new(trust_managers));

        let config = Arc::new(core_config);

        let exchange_protocols = exchange_protocol_providers_from_config(
            config.clone(),
            providers.core_base_url.clone(),
            data_provider.clone(),
            formatter_provider.clone(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
            revocation_method_provider.clone(),
            did_method_provider.clone(),
            ble_waiter.clone(),
            client.clone(),
        )?;

        let protocol_provider = Arc::new(ExchangeProtocolProviderCoreImpl::new(
            Arc::new(ExchangeProtocolProviderImpl::new(
                exchange_protocols.to_owned(),
            )),
            formatter_provider.clone(),
            data_provider.get_credential_repository(),
            revocation_method_provider.clone(),
            key_provider.clone(),
            data_provider.get_history_repository(),
            did_method_provider.clone(),
            data_provider.get_revocation_list_repository(),
            data_provider.get_validity_credential_repository(),
            config.clone(),
            providers.core_base_url.clone(),
        ));

        Ok(OneCore {
            exchange_protocols,
            trust_anchor_service: TrustAnchorService::new(
                data_provider.get_trust_anchor_repository(),
                data_provider.get_trust_entity_repository(),
                data_provider.get_history_repository(),
                data_provider.get_organisation_repository(),
                providers.core_base_url.clone(),
                config.clone(),
            ),
            trust_entity_service: TrustEntityService::new(
                data_provider.get_trust_anchor_repository(),
                data_provider.get_trust_entity_repository(),
                data_provider.get_history_repository(),
                trust_management_provider,
            ),
            backup_service: BackupService::new(
                data_provider.get_backup_repository(),
                data_provider.get_history_repository(),
                data_provider.get_organisation_repository(),
                config.clone(),
            ),
            organisation_service: OrganisationService::new(
                data_provider.get_organisation_repository(),
                data_provider.get_history_repository(),
            ),
            credential_service: CredentialService::new(
                data_provider.get_credential_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_did_repository(),
                data_provider.get_history_repository(),
                data_provider.get_interaction_repository(),
                data_provider.get_revocation_list_repository(),
                revocation_method_provider.clone(),
                formatter_provider.clone(),
                protocol_provider.clone(),
                key_provider.clone(),
                config.clone(),
                data_provider.get_validity_credential_repository(),
                providers.core_base_url.clone(),
                client.clone(),
            ),
            did_service: DidService::new(
                data_provider.get_did_repository(),
                data_provider.get_history_repository(),
                data_provider.get_key_repository(),
                data_provider.get_organisation_repository(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                config.clone(),
            ),
            revocation_list_service: RevocationListService::new(
                providers.core_base_url.clone(),
                data_provider.get_credential_repository(),
                data_provider.get_validity_credential_repository(),
                data_provider.get_revocation_list_repository(),
                crypto.clone(),
                did_method_provider.clone(),
                formatter_provider.clone(),
                key_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider.clone(),
                config.clone(),
            ),
            oidc_service: OIDCService::new(
                providers.core_base_url.clone(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_history_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_key_repository(),
                key_provider.clone(),
                data_provider.get_interaction_repository(),
                config.clone(),
                protocol_provider.clone(),
                data_provider.get_did_repository(),
                formatter_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider.clone(),
            ),
            credential_schema_service: CredentialSchemaService::new(
                providers.core_base_url.clone(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_history_repository(),
                data_provider.get_organisation_repository(),
                formatter_provider.clone(),
                config.clone(),
            ),
            history_service: HistoryService::new(data_provider.get_history_repository()),
            key_service: KeyService::new(
                data_provider.get_key_repository(),
                data_provider.get_history_repository(),
                data_provider.get_organisation_repository(),
                did_mdl_validator,
                key_provider.clone(),
                config.clone(),
                key_algorithm_provider.clone(),
            ),
            proof_schema_service: ProofSchemaService::new(
                data_provider.get_proof_schema_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_organisation_repository(),
                data_provider.get_history_repository(),
                formatter_provider.clone(),
                config.clone(),
                providers.core_base_url.clone(),
            ),
            proof_service: ProofService::new(
                data_provider.get_proof_repository(),
                key_algorithm_provider.clone(),
                data_provider.get_proof_schema_repository(),
                data_provider.get_did_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_history_repository(),
                data_provider.get_interaction_repository(),
                formatter_provider.clone(),
                revocation_method_provider.clone(),
                protocol_provider.clone(),
                did_method_provider.clone(),
                ble_waiter,
                config.clone(),
                providers.core_base_url.clone(),
            ),
            ssi_verifier_service: SSIVerifierService::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_did_repository(),
                formatter_provider.clone(),
                did_method_provider.clone(),
                revocation_method_provider.clone(),
                key_algorithm_provider.clone(),
                data_provider.get_history_repository(),
                config.clone(),
            ),
            ssi_issuer_service: SSIIssuerService::new(
                data_provider.get_credential_schema_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_did_repository(),
                protocol_provider.clone(),
                config.clone(),
                providers.core_base_url.clone(),
                data_provider.get_history_repository(),
            ),
            // TODO - config based
            vc_api_service: VCAPIService::new(
                formatter_provider.clone(),
                key_provider.clone(),
                data_provider.get_did_repository(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                data_provider.get_revocation_list_repository(),
                providers.core_base_url,
            ),
            ssi_holder_service: SSIHolderService::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_organisation_repository(),
                data_provider.get_interaction_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_did_repository(),
                data_provider.get_history_repository(),
                key_provider,
                formatter_provider,
                protocol_provider,
                did_method_provider,
                config.clone(),
                client.clone(),
            ),
            task_service: TaskService::new(task_provider),
            config_service: ConfigService::new(config.clone()),
            jsonld_service: JsonLdService::new(jsonld_caching_loader, client),
            config,
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
