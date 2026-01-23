use std::sync::Arc;

use one_crypto::initialize_crypto_provider;

use crate::config::ConfigValidationError;
use crate::config::core_config::CoreConfig;
use crate::proto::bluetooth_low_energy::ble_resource::BleWaiter;
use crate::proto::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::proto::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::proto::certificate_validator::{
    CertificateValidator, certificate_validator_from_config,
};
use crate::proto::clock::DefaultClock;
use crate::proto::credential_schema::importer::CredentialSchemaImporterProto;
use crate::proto::credential_schema::parser::CredentialSchemaImportParserImpl;
use crate::proto::history_decorator::decorated_data_provider::decorate_data_provider;
use crate::proto::http_client::HttpClient;
use crate::proto::identifier_creator::creator::IdentifierCreatorProto;
use crate::proto::mqtt_client::rumqttc_client::RumqttcClient;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::nfc::scanner::NfcScanner;
use crate::proto::openid4vp_proof_validator::validator::OpenId4VpProofValidatorProto;
use crate::proto::os_provider::OSInfoProviderImpl;
use crate::proto::session_provider::SessionProvider;
use crate::proto::wallet_unit::HolderWalletUnitProtoImpl;
use crate::provider::blob_storage_provider::blob_storage_provider_from_config;
use crate::provider::caching_loader::json_ld_context::{
    ContextCache, initialize_jsonld_cache_from_config,
};
use crate::provider::caching_loader::openid_metadata::openid_metadata_cache_from_config;
use crate::provider::caching_loader::vct::initialize_vct_type_metadata_cache_from_config;
use crate::provider::credential_formatter::provider::credential_formatter_provider_from_config;
use crate::provider::data_type::provider::data_type_provider_from_config;
use crate::provider::did_method::provider::did_method_provider_from_config;
use crate::provider::issuance_protocol::provider::issuance_protocol_provider_from_config;
use crate::provider::key_algorithm::provider::{
    KeyAlgorithmProvider, key_algorithm_provider_from_config,
};
use crate::provider::key_security_level::provider::key_security_level_provider_from_config;
use crate::provider::key_storage::provider::{KeyProvider, key_provider_from_config};
use crate::provider::key_storage::secure_element::NativeKeyStorage;
use crate::provider::presentation_formatter::provider::get_presentation_formatter_provider;
use crate::provider::revocation::provider::revocation_method_provider_from_config;
use crate::provider::signer::provider::signer_provider_from_config;
use crate::provider::task::provider::task_provider_from_config;
use crate::provider::trust_management::provider::trust_management_provider_from_config;
use crate::provider::verification_protocol::provider::verification_protocol_provider_from_config;
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
use crate::service::signature::SignatureService;
use crate::service::ssi_holder::SSIHolderService;
use crate::service::ssi_issuer::SSIIssuerService;
use crate::service::task::TaskService;
use crate::service::trust_anchor::TrustAnchorService;
use crate::service::trust_entity::TrustEntityService;
use crate::service::vc_api::VCAPIService;
use crate::service::wallet_provider::WalletProviderService;
use crate::service::wallet_unit::WalletUnitService;

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
    pub signature_service: SignatureService,
    pub nfc_service: NfcService,
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
        client: Arc<dyn HttpClient>,

        // optional dependencies
        ble_peripheral: Option<Arc<dyn BlePeripheral>>,
        ble_central: Option<Arc<dyn BleCentral>>,
        nfc_hce: Option<Arc<dyn NfcHce>>,
        nfc_scanner: Option<Arc<dyn NfcScanner>>,
        native_secure_element: Option<Arc<dyn NativeKeyStorage>>,
        remote_secure_element: Option<Arc<dyn NativeKeyStorage>>,
    ) -> Result<OneCore, OneCoreInitializationError> {
        let ble_waiter = match (ble_peripheral, ble_central) {
            (Some(ble_peripheral), Some(ble_central)) => {
                Some(BleWaiter::new(ble_central, ble_peripheral))
            }
            _ => None,
        };

        let mqtt_client = Arc::new(RumqttcClient::default());

        let clock = Arc::new(DefaultClock);

        let crypto = initialize_crypto_provider();

        // data_provider variable gets replaced with the decorated variant, so that it cannot be misued later
        let data_provider = decorate_data_provider(
            data_provider,
            session_provider.clone(),
            core_base_url.clone(),
        );

        let key_algorithm_provider = key_algorithm_provider_from_config(&mut config)?;

        let key_provider = key_provider_from_config(
            &mut config,
            key_algorithm_provider.clone(),
            crypto.clone(),
            client.clone(),
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

        let certificate_validator = certificate_validator_from_config(
            &config,
            key_algorithm_provider.clone(),
            client.clone(),
            data_provider.get_remote_entity_cache_repository(),
        );

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
            data_provider.get_validity_credential_repository(),
            data_provider.get_tx_manager(),
            data_provider.get_revocation_list_repository(),
            data_provider.get_remote_entity_cache_repository(),
            data_provider.get_wallet_unit_repository(),
            data_provider.get_identifier_repository(),
            client.clone(),
        )?;

        let credential_schema_import_parser = Arc::new(CredentialSchemaImportParserImpl::new(
            Arc::new(config.clone()),
            credential_formatter_provider.clone(),
            revocation_method_provider.clone(),
        ));

        let credential_schema_importer = Arc::new(CredentialSchemaImporterProto::new(
            credential_formatter_provider.clone(),
            data_provider.get_credential_schema_repository(),
        ));

        let wallet_unit_proto = Arc::new(HolderWalletUnitProtoImpl::new(
            key_provider.clone(),
            key_algorithm_provider.clone(),
            Arc::new(HTTPWalletProviderClient::new(client.clone())),
            revocation_method_provider.clone(),
            data_provider.get_holder_wallet_unit_repository(),
        ));

        let identifier_creator = Arc::new(IdentifierCreatorProto::new(
            did_method_provider.clone(),
            data_provider.get_did_repository(),
            data_provider.get_certificate_repository(),
            certificate_validator.clone(),
            data_provider.get_key_repository(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
            data_provider.get_identifier_repository(),
            Arc::new(config.clone()),
            data_provider.get_tx_manager(),
        ));

        let presentation_formatter_provider = get_presentation_formatter_provider(
            key_algorithm_provider.clone(),
            client.clone(),
            core_base_url.clone(),
            crypto.clone(),
            json_ld_cache.clone(),
            certificate_validator.clone(),
        );

        let trust_management_provider = trust_management_provider_from_config(
            &mut config,
            client.clone(),
            data_provider.get_remote_entity_cache_repository(),
        )?;

        let blob_storage_provider = blob_storage_provider_from_config(
            &config.blob_storage,
            data_provider.get_blob_repository(),
        );

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
            data_provider.get_validity_credential_repository(),
            credential_formatter_provider.clone(),
            vct_type_metadata_cache,
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
            credential_schema_import_parser.clone(),
            wallet_unit_proto.clone(),
        )?;

        let verification_provider = verification_protocol_provider_from_config(
            &mut config,
            core_base_url.clone(),
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
            openid_metadata_cache,
            Some(mqtt_client),
            nfc_hce.clone(),
        )?;

        let signer_provider = signer_provider_from_config(
            &mut config,
            clock.clone(),
            key_provider.clone(),
            key_algorithm_provider.clone(),
            revocation_method_provider.clone(),
            data_provider.get_revocation_list_repository(),
            session_provider.clone(),
        )?;

        let config = Arc::new(config);

        let credential_service = CredentialService::new(
            data_provider.get_credential_repository(),
            data_provider.get_credential_schema_repository(),
            data_provider.get_identifier_repository(),
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
            session_provider.clone(),
        );

        let task_provider = task_provider_from_config(
            &config,
            data_provider.get_claim_repository(),
            data_provider.get_credential_repository(),
            data_provider.get_history_repository(),
            data_provider.get_proof_repository(),
            data_provider.get_certificate_repository(),
            data_provider.get_identifier_repository(),
            data_provider.get_interaction_repository(),
            credential_service.clone(),
            certificate_validator.clone(),
            blob_storage_provider.clone(),
            session_provider.clone(),
        )?;

        let openid4vp_proof_validator = Arc::new(OpenId4VpProofValidatorProto::new(
            config.clone(),
            did_method_provider.clone(),
            credential_formatter_provider.clone(),
            presentation_formatter_provider.clone(),
            key_algorithm_provider.clone(),
            revocation_method_provider.clone(),
            certificate_validator.clone(),
        ));

        Ok(OneCore {
            trust_anchor_service: TrustAnchorService::new(
                data_provider.get_trust_anchor_repository(),
                data_provider.get_trust_entity_repository(),
                core_base_url.clone(),
                config.clone(),
            ),
            trust_entity_service: TrustEntityService::new(
                data_provider.get_trust_anchor_repository(),
                data_provider.get_trust_entity_repository(),
                data_provider.get_did_repository(),
                data_provider.get_identifier_repository(),
                data_provider.get_organisation_repository(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                trust_management_provider,
                key_provider.clone(),
                client.clone(),
                certificate_validator.clone(),
                identifier_creator.clone(),
                config.clone(),
            ),
            backup_service: BackupService::new(
                data_provider.get_backup_repository(),
                data_provider.get_history_repository(),
                data_provider.get_organisation_repository(),
                config.clone(),
            ),
            organisation_service: OrganisationService::new(
                data_provider.get_organisation_repository(),
                data_provider.get_identifier_repository(),
                config.clone(),
            ),
            credential_service,
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
                session_provider.clone(),
            ),
            revocation_list_service: RevocationListService::new(
                core_base_url.clone(),
                data_provider.get_credential_repository(),
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
                core_base_url.clone(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_interaction_repository(),
                config.clone(),
                issuance_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                credential_formatter_provider.clone(),
                revocation_method_provider.clone(),
                certificate_validator.clone(),
                identifier_creator.clone(),
                data_provider.get_tx_manager(),
            ),
            oid4vci_final1_0_service: OID4VCIFinal1_0Service::new(
                core_base_url.clone(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_interaction_repository(),
                config.clone(),
                issuance_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                credential_formatter_provider.clone(),
                revocation_method_provider.clone(),
                certificate_validator.clone(),
                blob_storage_provider.clone(),
                data_provider.get_tx_manager(),
                wallet_unit_proto.clone(),
                identifier_creator.clone(),
            ),
            oid4vci_draft13_swiyu_service: OID4VCIDraft13SwiyuService::new(
                core_base_url.clone(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_interaction_repository(),
                config.clone(),
                issuance_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                credential_formatter_provider.clone(),
                revocation_method_provider.clone(),
                certificate_validator.clone(),
                identifier_creator.clone(),
                data_provider.get_tx_manager(),
            ),
            oid4vp_draft20_service: OID4VPDraft20Service::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_key_repository(),
                key_provider.clone(),
                config.clone(),
                key_algorithm_provider.clone(),
                data_provider.get_validity_credential_repository(),
                blob_storage_provider.clone(),
                identifier_creator.clone(),
                data_provider.get_tx_manager(),
                openid4vp_proof_validator.clone(),
            ),
            oid4vp_draft25_service: OID4VPDraft25Service::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_key_repository(),
                key_provider.clone(),
                config.clone(),
                key_algorithm_provider.clone(),
                data_provider.get_validity_credential_repository(),
                blob_storage_provider.clone(),
                identifier_creator.clone(),
                data_provider.get_tx_manager(),
                openid4vp_proof_validator.clone(),
            ),
            oid4vp_final1_0_service: OID4VPFinal1_0Service::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_key_repository(),
                key_provider.clone(),
                config.clone(),
                key_algorithm_provider.clone(),
                data_provider.get_validity_credential_repository(),
                blob_storage_provider.clone(),
                identifier_creator.clone(),
                data_provider.get_tx_manager(),
                openid4vp_proof_validator.clone(),
            ),
            credential_schema_service: CredentialSchemaService::new(
                core_base_url.clone(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_organisation_repository(),
                credential_formatter_provider.clone(),
                revocation_method_provider.clone(),
                config.clone(),
                session_provider.clone(),
                credential_schema_import_parser.clone(),
                credential_schema_importer.clone(),
            ),
            history_service: HistoryService::new(
                data_provider.get_history_repository(),
                session_provider.clone(),
            ),
            key_service: KeyService::new(
                data_provider.get_key_repository(),
                data_provider.get_organisation_repository(),
                key_provider.clone(),
                config.clone(),
                key_algorithm_provider.clone(),
                data_provider.get_history_repository(),
                session_provider.clone(),
            ),
            proof_schema_service: ProofSchemaService::new(
                data_provider.get_proof_schema_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_organisation_repository(),
                credential_formatter_provider.clone(),
                config.clone(),
                core_base_url.clone(),
                client.clone(),
                session_provider.clone(),
                credential_schema_import_parser,
                credential_schema_importer,
            ),
            proof_service: ProofService::new(
                data_provider.get_proof_repository(),
                key_algorithm_provider.clone(),
                data_provider.get_proof_schema_repository(),
                data_provider.get_identifier_repository(),
                data_provider.get_claim_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_history_repository(),
                data_provider.get_interaction_repository(),
                credential_formatter_provider.clone(),
                presentation_formatter_provider.clone(),
                revocation_method_provider.clone(),
                verification_provider.clone(),
                did_method_provider.clone(),
                ble_waiter,
                config.clone(),
                data_provider.get_organisation_repository(),
                data_provider.get_validity_credential_repository(),
                certificate_validator.clone(),
                blob_storage_provider.clone(),
                nfc_hce,
                session_provider.clone(),
                identifier_creator.clone(),
                data_provider.get_tx_manager(),
                openid4vp_proof_validator,
            ),
            ssi_issuer_service: SSIIssuerService::new(
                data_provider.get_credential_schema_repository(),
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
                data_provider.get_credential_schema_repository(),
                data_provider.get_validity_credential_repository(),
                data_provider.get_identifier_repository(),
                key_provider.clone(),
                key_algorithm_provider.clone(),
                key_security_level_provider,
                credential_formatter_provider,
                issuance_provider,
                verification_provider,
                config.clone(),
                client.clone(),
                blob_storage_provider,
                session_provider.clone(),
                identifier_creator.clone(),
            ),
            wallet_provider_service: WalletProviderService::new(
                data_provider.get_organisation_repository(),
                data_provider.get_wallet_unit_repository(),
                data_provider.get_identifier_repository(),
                data_provider.get_history_repository(),
                data_provider.get_tx_manager(),
                key_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider,
                certificate_validator,
                clock,
                session_provider.clone(),
                config.clone(),
                core_base_url.clone(),
            ),
            task_service: TaskService::new(task_provider),
            config_service: ConfigService::new(config.clone()),
            jsonld_service: JsonLdService::new(json_ld_cache, client.clone()),
            config: config.clone(),
            cache_service: CacheService::new(data_provider.get_remote_entity_cache_repository()),
            nfc_service: NfcService::new(config.clone(), nfc_scanner),
            identifier_service: IdentifierService::new(
                data_provider.get_identifier_repository(),
                data_provider.get_key_repository(),
                data_provider.get_organisation_repository(),
                identifier_creator,
                config.clone(),
                session_provider.clone(),
            ),
            wallet_unit_service: WalletUnitService::new(
                data_provider.get_organisation_repository(),
                data_provider.get_holder_wallet_unit_repository(),
                data_provider.get_history_repository(),
                data_provider.get_key_repository(),
                key_provider,
                key_algorithm_provider,
                Arc::new(HTTPWalletProviderClient::new(client)),
                wallet_unit_proto,
                Arc::new(OSInfoProviderImpl),
                Arc::new(DefaultClock),
                core_base_url,
                config,
                session_provider.clone(),
            ),
            signature_service: SignatureService::new(
                signer_provider,
                data_provider.get_revocation_list_repository(),
                data_provider.get_identifier_repository(),
                data_provider.get_history_repository(),
                session_provider,
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
