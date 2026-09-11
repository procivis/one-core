extern crate core;

use std::sync::{Arc, Once};

use one_crypto::initialize_crypto_provider;

use crate::config::ConfigValidationError;
use crate::config::core_config::CoreConfig;
use crate::error::ErrorCodeMixinExt;
use crate::proto::bluetooth_low_energy::ble_resource::BleWaiter;
use crate::proto::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::proto::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::proto::certificate_validator::{
    CertificateValidator, certificate_validator_from_config,
};
use crate::proto::credential_schema::importer::CredentialSchemaImporterProto;
use crate::proto::credential_schema::parser::CredentialSchemaImportParserImpl;
use crate::proto::credential_schema::url_importer::CredentialSchemaUrlImporterProto;
use crate::proto::credential_validity_manager::CredentialValidityManagerImpl;
use crate::proto::csc::CscClientImpl;
use crate::proto::csr_creator::CsrCreatorImpl;
use crate::proto::ecosystem_sync::EcosystemSyncProto;
use crate::proto::history_decorator::decorator::decorate_data_provider as decorate_history;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::identifier_creator::creator::IdentifierCreatorProto;
use crate::proto::mqtt_client::rumqttc_client::RumqttcClient;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::nfc::scanner::NfcScanner;
use crate::proto::notification_decorator::decorator::decorate_data_provider as decorate_notification;
use crate::proto::notification_scheduler::NotificationSchedulerImpl;
use crate::proto::notification_sender::NotificationSenderImpl;
use crate::proto::openid4vp_proof_validator::validator::OpenId4VpProofValidatorProto;
use crate::proto::os_provider::OSInfoProviderImpl;
use crate::proto::proof_schema::importer::ProofSchemaImporterProto;
use crate::proto::schema_import::SchemaImporterProto;
use crate::proto::session_provider::SessionProvider;
use crate::proto::trust_collection::manager::TrustCollectionManagerImpl;
use crate::proto::trust_list_subscription_sync::{
    TrustListSubscriptionSync, TrustListSubscriptionSyncImpl,
};
use crate::proto::verifier_provider_client::http_client::HTTPVerifierProviderClient;
use crate::proto::wallet_instance::HolderWalletUnitProtoImpl;
use crate::proto::wallet_provider_client::http_client::HTTPWalletProviderClient;
use crate::proto::wrp_validator::validator::WRPValidatorImpl;
use crate::proto::xades::XAdES;
use crate::provider::blob_storage::provider::blob_storage_provider_from_config;
use crate::provider::caching_loader::json_ld_context::{
    ContextCache, initialize_jsonld_cache_from_config,
};
use crate::provider::caching_loader::openid_metadata::openid_metadata_cache_from_config;
use crate::provider::caching_loader::remote_trust_collection::remote_trust_collection_cache_from_config;
use crate::provider::caching_loader::vct::initialize_vct_type_metadata_cache_from_config;
use crate::provider::caching_loader::wallet_provider_metadata::wallet_provider_metadata_cache_from_config;
use crate::provider::credential_formatter::provider::credential_formatter_provider_from_config;
use crate::provider::data_type::provider::data_type_provider_from_config;
use crate::provider::did_method::provider::did_method_provider_from_config;
use crate::provider::document_signer::provider::document_signer_provider_from_config;
use crate::provider::ecosystem::directory::ecosystem_directory_from_config;
use crate::provider::issuance_protocol::provider::issuance_protocol_provider_from_config;
use crate::provider::key_algorithm::provider::{
    KeyAlgorithmProvider, key_algorithm_provider_from_config,
};
use crate::provider::key_security_level::provider::key_security_level_provider_from_config;
use crate::provider::key_storage::provider::key_provider_from_config;
use crate::provider::key_storage::secure_element::NativeKeyStorage;
use crate::provider::presentation_formatter::provider::get_presentation_formatter_provider;
use crate::provider::revocation::provider::revocation_method_provider_from_config;
use crate::provider::signer::provider::signer_provider_from_config;
use crate::provider::task::provider::task_provider_from_config;
use crate::provider::transaction_data::provider::transaction_data_provider_from_config;
use crate::provider::trust_list_publisher::provider::trust_list_publisher_provider_from_config;
use crate::provider::trust_list_subscriber::provider::trust_list_subscriber_provider_from_config;
use crate::provider::verification_protocol::provider::verification_protocol_provider_from_config;
use crate::provider::verifier::provider::verifier_provider_from_config;
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
use crate::service::instance::InstanceService;
use crate::service::jsonld::JsonLdService;
use crate::service::key::KeyService;
use crate::service::managed_instance::ManagedInstanceService;
use crate::service::nfc::NfcService;
use crate::service::oid4vci_final1_0::OID4VCIFinal1_0Service;
use crate::service::oid4vci_final1_0::resolver::initialize_issuer_metadata_cache_from_config;
use crate::service::oid4vp_final1_0::OID4VPFinal1_0Service;
use crate::service::oid4vp_final1_0_swiyu::OID4VPFinal1_0SwiyuService;
use crate::service::organisation::OrganisationService;
use crate::service::proof::ProofService;
use crate::service::proof_schema::ProofSchemaService;
use crate::service::qes::QesService;
use crate::service::revocation_list::RevocationListService;
use crate::service::signature::SignatureService;
use crate::service::ssi_holder::SSIHolderService;
use crate::service::ssi_issuer::SSIIssuerService;
use crate::service::statistics::StatisticsService;
use crate::service::task::TaskService;
use crate::service::trust_collection::TrustCollectionService;
use crate::service::trust_list_publication::TrustListPublicationService;
use crate::service::vc_api::VCAPIService;
use crate::service::verifier_provider::VerifierProviderService;

pub mod clock;
pub mod config;
pub mod error;
pub mod mapper;
pub mod model;
pub mod proto;
pub mod provider;
pub mod repository;
pub mod service;
pub mod util;
pub mod validator;

pub struct OneCore {
    pub organisation_service: OrganisationService,
    pub backup_service: BackupService,
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
    pub oid4vci_final1_0_service: OID4VCIFinal1_0Service,
    pub oid4vp_final1_0_service: OID4VPFinal1_0Service,
    pub oid4vp_final1_0_swiyu_service: OID4VPFinal1_0SwiyuService,
    pub ssi_issuer_service: SSIIssuerService,
    pub ssi_holder_service: SSIHolderService,
    pub wallet_provider_service: ManagedInstanceService,
    pub qes_service: QesService,
    pub task_service: TaskService,
    pub jsonld_service: JsonLdService,
    pub config: Arc<CoreConfig>,
    pub vc_api_service: VCAPIService,
    pub cache_service: CacheService,
    pub instance_service: InstanceService,
    pub signature_service: SignatureService,
    pub nfc_service: NfcService,
    pub statistics_service: StatisticsService,
    pub verifier_provider_service: VerifierProviderService,
    pub trust_list_publication_service: TrustListPublicationService,
    pub trust_collection_service: TrustCollectionService,
}

#[derive(Debug, thiserror::Error)]
pub enum OneCoreInitializationError {
    #[error("Config validation error: `{0}`")]
    Config(#[from] ConfigValidationError),

    #[error("Other error: `{0}`")]
    Other(#[from] anyhow::Error),
}

impl OneCore {
    #[expect(clippy::too_many_arguments)]
    pub async fn new(
        mut config: CoreConfig,
        core_base_url: Option<String>,
        session_provider: Arc<dyn SessionProvider>,

        // mandatory dependencies
        data_provider: Arc<dyn DataRepository>,

        // optional dependencies
        ble_peripheral: Option<Arc<dyn BlePeripheral>>,
        ble_central: Option<Arc<dyn BleCentral>>,
        nfc_hce: Option<Arc<dyn NfcHce>>,
        nfc_scanner: Option<Arc<dyn NfcScanner>>,
        native_secure_element: Option<Arc<dyn NativeKeyStorage>>,
        remote_secure_element: Option<Arc<dyn NativeKeyStorage>>,
    ) -> Result<OneCore, OneCoreInitializationError> {
        initialize_rustls()?;

        let ble_waiter = match (ble_peripheral, ble_central) {
            (Some(ble_peripheral), Some(ble_central)) => {
                Some(BleWaiter::new(ble_central, ble_peripheral))
            }
            _ => None,
        };

        let client = Arc::new(
            ReqwestClient::new(config.global_settings.http_client.to_owned()).map_err(|err| {
                OneCoreInitializationError::Config(err.error_while("creating HTTP client").into())
            })?,
        );

        let mqtt_client = Arc::new(RumqttcClient::default());

        let crypto = initialize_crypto_provider();

        // data_provider variable gets replaced with the decorated variant, so that it cannot be misued later
        let data_provider = decorate_history(
            data_provider,
            session_provider.clone(),
            core_base_url.clone(),
        );

        let notification_sender = Arc::new(NotificationSenderImpl::new(
            data_provider.get_history_repository(),
            data_provider.get_notification_repository(),
            data_provider.get_tx_manager(),
            client.clone(),
            session_provider.clone(),
        ));
        let notification_scheduler = Arc::new(NotificationSchedulerImpl::new(
            data_provider.get_notification_repository(),
            notification_sender.clone(),
            Arc::new(config.clone()),
        ));

        let data_provider = decorate_notification(
            data_provider,
            notification_scheduler.clone(),
            Arc::new(config.clone()),
        );

        let key_algorithm_provider = key_algorithm_provider_from_config(&mut config)?;
        let certificate_validator = certificate_validator_from_config(
            &config.global_settings,
            &config.cache_entities,
            key_algorithm_provider.clone(),
            client.clone(),
            data_provider.get_remote_entity_cache_repository(),
        )
        .map_err(|err| {
            OneCoreInitializationError::Config(
                err.error_while("creating certificate validator").into(),
            )
        })?;
        let csc_client = Arc::new(CscClientImpl::new(client.clone()));
        let key_provider = key_provider_from_config(
            &mut config,
            key_algorithm_provider.clone(),
            crypto.clone(),
            client.clone(),
            csc_client.clone(),
            certificate_validator.clone(),
            native_secure_element,
            remote_secure_element,
        )?;

        let did_method_provider = did_method_provider_from_config(
            &mut config,
            core_base_url.clone(),
            key_algorithm_provider.clone(),
            key_provider.clone(),
            client.clone(),
            data_provider.get_remote_entity_cache_repository(),
        )?;

        let transaction_data_provider =
            transaction_data_provider_from_config(&mut config, crypto.clone())?;

        let json_ld_cache = initialize_jsonld_cache_from_config(
            &config,
            data_provider.get_remote_entity_cache_repository(),
        );

        let vct_type_metadata_cache = initialize_vct_type_metadata_cache_from_config(
            &config,
            data_provider.get_remote_entity_cache_repository(),
            client.clone(),
        )
        .await?;

        let data_type_provider = data_type_provider_from_config(&mut config)?;

        let credential_formatter_provider = credential_formatter_provider_from_config(
            &mut config,
            core_base_url.clone().map(Into::into),
            key_algorithm_provider.clone(),
            client.clone(),
            data_type_provider.clone(),
            crypto.clone(),
            json_ld_cache.clone(),
            did_method_provider.clone(),
            vct_type_metadata_cache.clone(),
            certificate_validator.clone(),
        )?;

        let revocation_method_provider = revocation_method_provider_from_config(
            &mut config,
            core_base_url.clone(),
            credential_formatter_provider.clone(),
            key_provider.clone(),
            certificate_validator.clone(),
            key_algorithm_provider.clone(),
            did_method_provider.clone(),
            data_provider.get_tx_manager(),
            data_provider.get_revocation_list_repository(),
            data_provider.get_remote_entity_cache_repository(),
            data_provider.get_managed_instance_repository(),
            data_provider.get_identifier_repository(),
            client.clone(),
        )?;

        let credential_schema_import_parser = Arc::new(CredentialSchemaImportParserImpl::new(
            Arc::new(config.clone()),
            core_base_url.clone(),
            credential_formatter_provider.clone(),
            revocation_method_provider.clone(),
        ));

        let credential_schema_importer = Arc::new(CredentialSchemaImporterProto::new(
            data_provider.get_credential_schema_repository(),
            config.global_settings.default_language.clone(),
        ));

        let wallet_provider_metadata_cache = Arc::new(wallet_provider_metadata_cache_from_config(
            client.clone(),
            data_provider.get_remote_entity_cache_repository(),
            &config,
        ));
        let wallet_unit_client = Arc::new(HTTPWalletProviderClient::new(
            client.clone(),
            wallet_provider_metadata_cache,
        ));
        let verifier_provider_client = Arc::new(HTTPVerifierProviderClient::new(client.clone()));
        let wallet_unit_proto = Arc::new(HolderWalletUnitProtoImpl::new(
            key_provider.clone(),
            key_algorithm_provider.clone(),
            wallet_unit_client.clone(),
            revocation_method_provider.clone(),
            data_provider.get_instance_repository(),
            certificate_validator.clone(),
        ));

        let csr_creator = Arc::new(CsrCreatorImpl::new(
            key_provider.clone(),
            key_algorithm_provider.clone(),
        ));

        let signer_provider = signer_provider_from_config(
            core_base_url.clone(),
            &mut config,
            key_provider.clone(),
            key_algorithm_provider.clone(),
            revocation_method_provider.clone(),
            data_provider.get_revocation_list_repository(),
            session_provider.clone(),
            did_method_provider.clone(),
        )?;

        let verifier_provider = verifier_provider_from_config(&config)?;

        let document_signer_provider =
            document_signer_provider_from_config(&mut config, csc_client)?;

        let blob_storage_provider =
            blob_storage_provider_from_config(&mut config, data_provider.get_blob_repository())?;

        let identifier_creator = Arc::new(IdentifierCreatorProto::new(
            did_method_provider.clone(),
            data_provider.get_did_repository(),
            data_provider.get_certificate_repository(),
            certificate_validator.clone(),
            data_provider.get_key_repository(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
            data_provider.get_identifier_repository(),
            signer_provider.clone(),
            blob_storage_provider.clone(),
            csr_creator.clone(),
            Arc::new(config.clone()),
            data_provider.get_tx_manager(),
        ));

        let xades_proto = Arc::new(XAdES::new(crypto.clone(), certificate_validator.clone()));

        let presentation_formatter_provider = get_presentation_formatter_provider(
            key_algorithm_provider.clone(),
            client.clone(),
            core_base_url.clone(),
            crypto.clone(),
            json_ld_cache.clone(),
            certificate_validator.clone(),
        );

        let trust_list_publisher_provider = trust_list_publisher_provider_from_config(
            &mut config,
            key_provider.clone(),
            key_algorithm_provider.clone(),
            xades_proto.clone(),
            data_provider.get_trust_list_publication_repository(),
            data_provider.get_trust_entry_repository(),
            data_provider.get_organisation_repository(),
        )?;

        let trust_list_subscriber_provider = trust_list_subscriber_provider_from_config(
            &mut config,
            client.clone(),
            did_method_provider.clone(),
            key_algorithm_provider.clone(),
            certificate_validator.clone(),
            xades_proto,
            data_provider.get_remote_entity_cache_repository(),
        )?;

        let wrp_validator = Arc::new(WRPValidatorImpl::new(
            data_provider.get_trust_collection_repository(),
            data_provider.get_trust_list_subscription_repository(),
            trust_list_subscriber_provider.clone(),
            did_method_provider.clone(),
            key_algorithm_provider.clone(),
            certificate_validator.clone(),
            client.clone(),
            revocation_method_provider.clone(),
        ));

        let trust_collection_manager = Arc::new(TrustCollectionManagerImpl::new(
            data_provider.get_trust_collection_repository(),
            data_provider.get_organisation_repository(),
            data_provider.get_tx_manager(),
        ));
        let key_security_level_provider = key_security_level_provider_from_config(&mut config)?;

        let openid_metadata_cache = openid_metadata_cache_from_config(
            &config,
            data_provider.get_remote_entity_cache_repository(),
            client.clone(),
        );

        let issuance_provider = issuance_protocol_provider_from_config(
            &mut config,
            core_base_url.clone(),
            data_provider.get_credential_repository(),
            data_provider.get_key_repository(),
            credential_formatter_provider.clone(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
            key_security_level_provider.clone(),
            revocation_method_provider.clone(),
            did_method_provider.clone(),
            certificate_validator.clone(),
            identifier_creator.clone(),
            client.clone(),
            openid_metadata_cache.clone(),
            blob_storage_provider.clone(),
            credential_schema_importer.clone(),
            wallet_unit_proto.clone(),
            data_provider.get_instance_repository(),
            data_provider.get_history_repository(),
            session_provider.clone(),
            data_provider.get_credential_schema_repository(),
            data_provider.get_interaction_repository(),
            data_provider.get_identifier_repository(),
            data_provider.get_did_repository(),
            data_provider.get_tx_manager(),
        )?;

        let credential_validity_manager = Arc::new(CredentialValidityManagerImpl::new(
            data_provider.get_credential_repository(),
            issuance_provider.clone(),
            revocation_method_provider.clone(),
            credential_formatter_provider.clone(),
            blob_storage_provider.clone(),
            session_provider.clone(),
            data_provider.get_tx_manager(),
            Arc::new(config.clone()),
        ));

        let ecosystem_provider = ecosystem_directory_from_config(
            &mut config,
            data_provider.get_history_repository(),
            data_provider.get_interaction_repository(),
            wrp_validator.clone(),
            blob_storage_provider.clone(),
            session_provider.clone(),
            credential_formatter_provider.clone(),
            data_provider.get_credential_repository(),
            data_provider.get_credential_schema_repository(),
            data_provider.get_proof_schema_repository(),
            wallet_unit_proto.clone(),
            credential_validity_manager.clone(),
        )?;

        let verification_provider = verification_protocol_provider_from_config(
            &mut config,
            core_base_url.clone(),
            data_provider.get_credential_repository(),
            data_provider.get_credential_schema_repository(),
            data_provider.get_interaction_repository(),
            data_provider.get_proof_repository(),
            credential_formatter_provider.clone(),
            presentation_formatter_provider.clone(),
            key_provider.clone(),
            certificate_validator.clone(),
            key_algorithm_provider.clone(),
            did_method_provider.clone(),
            identifier_creator.clone(),
            ble_waiter.clone(),
            client.clone(),
            Some(mqtt_client),
            nfc_hce.clone(),
            wrp_validator.clone(),
            ecosystem_provider.clone(),
            transaction_data_provider.clone(),
        )?;

        let config = Arc::new(config);

        let credential_schema_url_importer = Arc::new(CredentialSchemaUrlImporterProto::new(
            client.clone(),
            credential_schema_import_parser.clone(),
            credential_schema_importer.clone(),
        ));

        let proof_schema_importer = Arc::new(ProofSchemaImporterProto::new(
            data_provider.get_proof_schema_repository(),
            data_provider.get_credential_schema_repository(),
            credential_schema_url_importer.clone(),
            client.clone(),
            config.clone(),
        ));

        let schema_importer = Arc::new(SchemaImporterProto::new(
            credential_schema_url_importer,
            proof_schema_importer.clone(),
        ));

        let remote_trust_collection_cache = Arc::new(remote_trust_collection_cache_from_config(
            client.clone(),
            data_provider.get_remote_entity_cache_repository(),
            &config,
        ));
        let trust_list_subscription_sync: Arc<dyn TrustListSubscriptionSync> =
            Arc::new(TrustListSubscriptionSyncImpl::new(
                remote_trust_collection_cache,
                data_provider.get_trust_list_subscription_repository(),
                data_provider.get_tx_manager(),
            ));

        let ecosystem_sync = Arc::new(EcosystemSyncProto::new(
            data_provider.get_instance_repository(),
            wallet_unit_client.clone(),
            verifier_provider_client.clone(),
            trust_collection_manager.clone(),
            data_provider.get_trust_collection_repository(),
            trust_list_subscription_sync.clone(),
            schema_importer.clone(),
        ));

        let task_provider = task_provider_from_config(
            &config,
            data_provider.get_claim_repository(),
            data_provider.get_credential_repository(),
            data_provider.get_history_repository(),
            data_provider.get_proof_repository(),
            data_provider.get_certificate_repository(),
            data_provider.get_identifier_repository(),
            data_provider.get_interaction_repository(),
            data_provider.get_notification_repository(),
            data_provider.get_trust_list_subscription_repository(),
            data_provider.get_instance_repository(),
            credential_validity_manager.clone(),
            certificate_validator.clone(),
            blob_storage_provider.clone(),
            session_provider.clone(),
            notification_sender.clone(),
            trust_list_subscriber_provider.clone(),
            ecosystem_sync.clone(),
            ecosystem_provider.clone(),
        )?;

        let openid4vp_proof_validator = Arc::new(OpenId4VpProofValidatorProto::new(
            did_method_provider.clone(),
            credential_formatter_provider.clone(),
            presentation_formatter_provider.clone(),
            key_algorithm_provider.clone(),
            revocation_method_provider.clone(),
            certificate_validator.clone(),
            transaction_data_provider.clone(),
        ));

        let credential_issuer_metadata_cache = initialize_issuer_metadata_cache_from_config(
            &config,
            data_provider.get_remote_entity_cache_repository(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
        )?;
        Ok(OneCore {
            backup_service: BackupService::new(
                data_provider.get_backup_repository(),
                data_provider.get_history_repository(),
                data_provider.get_organisation_repository(),
                data_provider.get_credential_repository(),
                credential_formatter_provider.clone(),
                config.clone(),
            ),
            organisation_service: OrganisationService::new(
                data_provider.get_organisation_repository(),
                data_provider.get_identifier_repository(),
                data_provider.get_instance_repository(),
                wallet_unit_client.clone(),
                verifier_provider_client.clone(),
                trust_list_subscription_sync.clone(),
                data_provider.get_trust_collection_repository(),
                data_provider.get_trust_list_subscription_repository(),
                ecosystem_sync,
                config.clone(),
            ),
            credential_service: CredentialService::new(
                data_provider.get_credential_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_identifier_repository(),
                data_provider.get_interaction_repository(),
                credential_formatter_provider.clone(),
                issuance_provider.clone(),
                config.clone(),
                blob_storage_provider.clone(),
                session_provider.clone(),
                credential_validity_manager,
                notification_scheduler.clone(),
                data_provider.get_tx_manager(),
                ecosystem_provider.clone(),
                data_provider.get_history_repository(),
            ),
            did_service: DidService::new(
                data_provider.get_did_repository(),
                data_provider.get_identifier_repository(),
                data_provider.get_organisation_repository(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                identifier_creator.clone(),
                session_provider.clone(),
            ),
            certificate_service: CertificateService::new(
                data_provider.get_certificate_repository(),
                data_provider.get_identifier_repository(),
                session_provider.clone(),
            ),
            revocation_list_service: RevocationListService::new(
                data_provider.get_revocation_list_repository(),
                revocation_method_provider.clone(),
                config.clone(),
            ),
            oid4vci_final1_0_service: OID4VCIFinal1_0Service::new(
                core_base_url.clone(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_interaction_repository(),
                data_provider.get_identifier_repository(),
                config.clone(),
                issuance_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                key_provider.clone(),
                revocation_method_provider.clone(),
                certificate_validator.clone(),
                blob_storage_provider.clone(),
                data_provider.get_tx_manager(),
                wallet_unit_proto.clone(),
                identifier_creator.clone(),
                credential_issuer_metadata_cache.clone(),
                credential_formatter_provider.clone(),
                ecosystem_provider.clone(),
                data_provider.get_history_repository(),
            ),
            oid4vp_final1_0_service: OID4VPFinal1_0Service::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_interaction_repository(),
                data_provider.get_key_repository(),
                key_provider.clone(),
                config.clone(),
                key_algorithm_provider.clone(),
                blob_storage_provider.clone(),
                identifier_creator.clone(),
                data_provider.get_tx_manager(),
                openid4vp_proof_validator.clone(),
                ecosystem_provider.clone(),
                verification_provider.clone(),
                data_provider.get_history_repository(),
            ),
            oid4vp_final1_0_swiyu_service: OID4VPFinal1_0SwiyuService::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_interaction_repository(),
                data_provider.get_key_repository(),
                key_provider.clone(),
                config.clone(),
                key_algorithm_provider.clone(),
                blob_storage_provider.clone(),
                identifier_creator.clone(),
                data_provider.get_tx_manager(),
                openid4vp_proof_validator.clone(),
                ecosystem_provider.clone(),
                verification_provider.clone(),
                data_provider.get_history_repository(),
            ),
            credential_schema_service: CredentialSchemaService::new(
                core_base_url.clone(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_organisation_repository(),
                credential_formatter_provider.clone(),
                revocation_method_provider.clone(),
                config.clone(),
                session_provider.clone(),
                credential_schema_import_parser,
                credential_schema_importer,
                ecosystem_provider.clone(),
            ),
            history_service: HistoryService::new(
                data_provider.get_history_repository(),
                session_provider.clone(),
            ),
            key_service: KeyService::new(
                data_provider.get_key_repository(),
                data_provider.get_organisation_repository(),
                key_provider.clone(),
                key_algorithm_provider.clone(),
                data_provider.get_history_repository(),
                session_provider.clone(),
                csr_creator.clone(),
            ),
            proof_schema_service: ProofSchemaService::new(
                data_provider.get_proof_schema_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_organisation_repository(),
                credential_formatter_provider.clone(),
                config.clone(),
                core_base_url.clone(),
                session_provider.clone(),
                proof_schema_importer,
                ecosystem_provider.clone(),
            ),
            proof_service: ProofService::new(
                data_provider.get_proof_repository(),
                key_provider.clone(),
                key_algorithm_provider.clone(),
                data_provider.get_proof_schema_repository(),
                data_provider.get_identifier_repository(),
                data_provider.get_claim_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_history_repository(),
                data_provider.get_interaction_repository(),
                credential_formatter_provider.clone(),
                presentation_formatter_provider.clone(),
                verification_provider.clone(),
                did_method_provider.clone(),
                ble_waiter,
                config.clone(),
                data_provider.get_organisation_repository(),
                certificate_validator.clone(),
                blob_storage_provider.clone(),
                nfc_hce,
                session_provider.clone(),
                identifier_creator.clone(),
                data_provider.get_tx_manager(),
                openid4vp_proof_validator,
                notification_scheduler,
                transaction_data_provider,
                ecosystem_provider.clone(),
            ),
            ssi_issuer_service: SSIIssuerService::new(
                data_provider.get_credential_schema_repository(),
                data_provider.get_identifier_repository(),
                issuance_provider.clone(),
                key_algorithm_provider.clone(),
                config.clone(),
                core_base_url.clone(),
            ),
            // TODO - config based
            vc_api_service: VCAPIService::new(
                credential_formatter_provider.clone(),
                presentation_formatter_provider,
                key_provider.clone(),
                data_provider.get_did_repository(),
                data_provider.get_identifier_repository(),
                did_method_provider,
                key_algorithm_provider.clone(),
                data_provider.get_revocation_list_repository(),
                certificate_validator.clone(),
                ContextCache::new(json_ld_cache.clone(), client.clone()),
                core_base_url.clone(),
            ),
            ssi_holder_service: SSIHolderService::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_organisation_repository(),
                data_provider.get_interaction_repository(),
                data_provider.get_identifier_repository(),
                key_algorithm_provider.clone(),
                key_security_level_provider,
                credential_formatter_provider,
                issuance_provider,
                verification_provider,
                config.clone(),
                client.clone(),
                blob_storage_provider.clone(),
                session_provider.clone(),
                identifier_creator.clone(),
                data_provider.get_tx_manager(),
                ecosystem_provider.clone(),
                data_provider.get_history_repository(),
            ),
            wallet_provider_service: ManagedInstanceService::new(
                data_provider.get_organisation_repository(),
                data_provider.get_managed_instance_repository(),
                data_provider.get_identifier_repository(),
                data_provider.get_history_repository(),
                data_provider.get_trust_collection_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_tx_manager(),
                key_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider,
                signer_provider.clone(),
                certificate_validator,
                client.clone(),
                session_provider.clone(),
                document_signer_provider.clone(),
                verifier_provider.clone(),
                config.clone(),
                core_base_url.clone(),
            ),
            qes_service: QesService::new(
                document_signer_provider,
                data_provider.get_history_repository(),
                session_provider.clone(),
            ),
            task_service: TaskService::new(task_provider),
            config_service: ConfigService::new(config.clone()),
            jsonld_service: JsonLdService::new(json_ld_cache, client.clone()),
            config: config.clone(),
            cache_service: CacheService::new(data_provider.get_remote_entity_cache_repository()),
            nfc_service: NfcService::new(config.clone(), nfc_scanner),
            identifier_service: IdentifierService::new(
                data_provider.get_identifier_repository(),
                data_provider.get_certificate_repository(),
                data_provider.get_did_repository(),
                data_provider.get_key_repository(),
                data_provider.get_organisation_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_proof_schema_repository(),
                data_provider.get_trust_collection_repository(),
                data_provider.get_trust_list_subscription_repository(),
                data_provider.get_identifier_trust_information_repository(),
                data_provider.get_localized_text_repository(),
                blob_storage_provider.clone(),
                identifier_creator.clone(),
                config.clone(),
                session_provider.clone(),
                trust_list_subscriber_provider.clone(),
                data_provider.get_tx_manager(),
                wrp_validator,
                ecosystem_provider.clone(),
            ),
            instance_service: InstanceService::new(
                data_provider.get_organisation_repository(),
                data_provider.get_instance_repository(),
                data_provider.get_history_repository(),
                data_provider.get_key_repository(),
                key_provider,
                key_algorithm_provider,
                wallet_unit_client,
                verifier_provider_client,
                wallet_unit_proto,
                Arc::new(OSInfoProviderImpl),
                trust_collection_manager,
                core_base_url,
                config.clone(),
                session_provider.clone(),
                schema_importer,
                csr_creator,
                identifier_creator,
            ),
            signature_service: SignatureService::new(
                signer_provider,
                data_provider.get_revocation_list_repository(),
                data_provider.get_identifier_repository(),
                data_provider.get_history_repository(),
                blob_storage_provider.clone(),
                session_provider.clone(),
            ),
            statistics_service: StatisticsService::new(
                data_provider.get_history_repository(),
                data_provider.get_organisation_repository(),
                session_provider.clone(),
            ),
            verifier_provider_service: VerifierProviderService::new(
                verifier_provider,
                data_provider.get_trust_collection_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_proof_schema_repository(),
                data_provider.get_organisation_repository(),
                config.clone(),
            ),
            trust_list_publication_service: TrustListPublicationService::new(
                data_provider.get_identifier_repository(),
                data_provider.get_trust_list_publication_repository(),
                data_provider.get_trust_entry_repository(),
                session_provider.clone(),
                trust_list_publisher_provider,
            ),
            trust_collection_service: TrustCollectionService::new(
                data_provider.get_organisation_repository(),
                data_provider.get_trust_collection_repository(),
                data_provider.get_trust_list_subscription_repository(),
                trust_list_subscriber_provider,
                session_provider,
                ecosystem_provider,
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

/// call rustls initialization only once
static RUSTLS_INITIALIZATION: Once = Once::new();
fn initialize_rustls() -> Result<(), OneCoreInitializationError> {
    let mut result: Option<anyhow::Error> = None;

    RUSTLS_INITIALIZATION.call_once(|| {
        if rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .is_err()
        {
            tracing::error!("Rustls initialization failure");
            result = Some(anyhow::anyhow!("Failed to install rustls crypto provider"));
        }
    });

    result.map_or(Ok(()), |e| Err(e.into()))
}
