use std::collections::HashMap;
use std::sync::Arc;

use crate::provider::key_storage::key_providers_from_config;
use crate::provider::key_storage::provider::KeyProviderImpl;
use crate::provider::key_storage::KeyStorage;
use config::core_config::{CoreConfig, ExchangeType};
use config::ConfigError;
use crypto::hasher::sha256::SHA256;
use crypto::hasher::Hasher;
use crypto::signer::eddsa::EDDSASigner;
use crypto::signer::Signer;
use crypto::{CryptoProvider, CryptoProviderImpl};
use provider::credential_formatter::provider::CredentialFormatterProviderImpl;
use provider::key_storage::secure_element::NativeKeyStorage;
use provider::transport_protocol::{
    procivis_temp::ProcivisTemp, provider::TransportProtocolProviderImpl, TransportProtocol,
};
use repository::DataRepository;
use service::{
    config::ConfigService, credential::CredentialService, did::DidService,
    organisation::OrganisationService, proof::ProofService, proof_schema::ProofSchemaService,
    ssi_holder::SSIHolderService, ssi_issuer::SSIIssuerService, ssi_verifier::SSIVerifierService,
};

pub mod config;
pub mod provider;

pub mod crypto;

pub mod model;
pub mod repository;
pub mod service;

pub mod common_mapper;
mod common_validator;
pub mod util;

use crate::crypto::signer::es256::ES256Signer;
use crate::provider::credential_formatter::provider::credential_formatters_from_config;
use crate::provider::did_method::provider::DidMethodProviderImpl;
use crate::provider::did_method::{did_method_providers_from_config, DidMethod};
use crate::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use crate::provider::key_algorithm::{key_algorithms_from_config, KeyAlgorithm};
use crate::provider::revocation::none::NoneRevocation;
use crate::provider::revocation::provider::RevocationMethodProviderImpl;
use crate::provider::revocation::status_list_2021::StatusList2021;
use crate::provider::revocation::RevocationMethod;
use crate::provider::transport_protocol::openid4vc::OpenID4VC;
use crate::service::credential_schema::CredentialSchemaService;
use crate::service::key::KeyService;
use crate::service::oidc::OIDCService;
use crate::service::revocation_list::RevocationListService;

// Clone just for now. Later it should be removed.
#[derive(Clone)]
pub struct OneCore {
    pub did_methods: HashMap<String, Arc<dyn DidMethod + Send + Sync>>,
    pub key_algorithms: HashMap<String, Arc<dyn KeyAlgorithm + Send + Sync>>,
    pub key_providers: HashMap<String, Arc<dyn KeyStorage + Send + Sync>>,
    pub transport_protocols: Vec<(String, Arc<dyn TransportProtocol + Send + Sync>)>,
    pub revocation_methods: Vec<(String, Arc<dyn RevocationMethod + Send + Sync>)>,
    pub organisation_service: OrganisationService,
    pub did_service: DidService,
    pub credential_service: CredentialService,
    pub credential_schema_service: CredentialSchemaService,
    pub key_service: KeyService,
    pub proof_schema_service: ProofSchemaService,
    pub proof_service: ProofService,
    pub config_service: ConfigService,
    pub ssi_verifier_service: SSIVerifierService,
    pub revocation_list_service: RevocationListService,
    pub oidc_service: OIDCService,
    pub ssi_issuer_service: SSIIssuerService,
    pub ssi_holder_service: SSIHolderService,
    pub config: Arc<CoreConfig>,
    pub crypto: Arc<dyn CryptoProvider + Send + Sync>,
}

impl OneCore {
    pub fn new(
        data_provider: Arc<dyn DataRepository>,
        core_config: CoreConfig,
        core_base_url: Option<String>,
        secure_element_key_storage: Option<Arc<dyn NativeKeyStorage>>,
    ) -> Result<OneCore, ConfigError> {
        // For now we will just put them here.
        // We will introduce a builder later.

        let hashers: Vec<(String, Arc<dyn Hasher + Send + Sync>)> =
            vec![("sha-256".to_string(), Arc::new(SHA256 {}))];

        let signers: Vec<(String, Arc<dyn Signer + Send + Sync>)> = vec![
            ("Ed25519".to_string(), Arc::new(EDDSASigner {})),
            ("ES256".to_string(), Arc::new(ES256Signer {})),
        ];

        let crypto = Arc::new(CryptoProviderImpl::new(
            HashMap::from_iter(hashers),
            HashMap::from_iter(signers),
        ));

        let credential_formatters =
            credential_formatters_from_config(&core_config.format, crypto.clone())?;
        let formatter_provider =
            Arc::new(CredentialFormatterProviderImpl::new(credential_formatters));

        let key_algorithms = key_algorithms_from_config(&core_config.key_algorithm)?;
        let key_algorithm_provider = Arc::new(KeyAlgorithmProviderImpl::new(
            key_algorithms.to_owned(),
            crypto.clone(),
        ));
        let key_providers = key_providers_from_config(
            &core_config.key_storage,
            crypto.clone(),
            key_algorithm_provider.clone(),
            secure_element_key_storage,
        )?;
        let key_provider = Arc::new(KeyProviderImpl::new(key_providers.to_owned()));

        let did_methods = did_method_providers_from_config(
            &core_config.did,
            key_algorithm_provider.clone(),
            &core_config.key_algorithm,
            core_base_url.clone(),
        )?;
        let did_method_provider = Arc::new(DidMethodProviderImpl::new(did_methods.to_owned()));

        let config = Arc::new(core_config);

        let revocation_methods: Vec<(String, Arc<dyn RevocationMethod + Send + Sync>)> = vec![
            ("NONE".to_string(), Arc::new(NoneRevocation {})),
            (
                "STATUSLIST2021".to_string(),
                Arc::new(StatusList2021 {
                    core_base_url: core_base_url.clone(),
                    credential_repository: data_provider.get_credential_repository(),
                    revocation_list_repository: data_provider.get_revocation_list_repository(),
                    key_provider: key_provider.clone(),
                    key_algorithm_provider: key_algorithm_provider.clone(),
                    did_method_provider: did_method_provider.clone(),
                    client: reqwest::Client::new(),
                }),
            ),
        ];
        let revocation_method_provider = Arc::new(RevocationMethodProviderImpl::new(
            revocation_methods.to_owned(),
        ));

        let transport_protocols: Vec<(String, Arc<dyn TransportProtocol + Send + Sync>)> = vec![
            (
                "PROCIVIS_TEMPORARY".to_string(),
                Arc::new(ProcivisTemp::new(
                    core_base_url.clone(),
                    data_provider.get_credential_repository(),
                    data_provider.get_proof_repository(),
                    data_provider.get_interaction_repository(),
                    data_provider.get_credential_schema_repository(),
                    data_provider.get_did_repository(),
                    formatter_provider.clone(),
                    key_provider.clone(),
                )),
            ),
            (
                "OPENID4VC".to_string(),
                Arc::new(OpenID4VC::new(
                    core_base_url.clone(),
                    data_provider.get_credential_repository(),
                    data_provider.get_credential_schema_repository(),
                    data_provider.get_did_repository(),
                    data_provider.get_proof_repository(),
                    data_provider.get_interaction_repository(),
                    formatter_provider.clone(),
                    revocation_method_provider.clone(),
                    key_provider.clone(),
                    crypto.clone(),
                    config.exchange.get(ExchangeType::OpenId4Vc)?,
                )),
            ),
        ];

        let protocol_provider = Arc::new(TransportProtocolProviderImpl::new(
            transport_protocols.to_owned(),
            formatter_provider.clone(),
            data_provider.get_credential_repository(),
            revocation_method_provider.clone(),
            key_provider.clone(),
            config.clone(),
        ));

        Ok(OneCore {
            did_methods,
            key_algorithms,
            key_providers,
            transport_protocols,
            revocation_methods,
            organisation_service: OrganisationService::new(
                data_provider.get_organisation_repository(),
            ),
            credential_service: CredentialService::new(
                data_provider.get_credential_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_did_repository(),
                revocation_method_provider.clone(),
                formatter_provider.clone(),
                protocol_provider.clone(),
                config.clone(),
            ),
            did_service: DidService::new(
                data_provider.get_did_repository(),
                data_provider.get_key_repository(),
                data_provider.get_organisation_repository(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                config.clone(),
            ),
            revocation_list_service: RevocationListService::new(
                data_provider.get_revocation_list_repository(),
            ),
            oidc_service: OIDCService::new(
                core_base_url,
                data_provider.get_credential_schema_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_interaction_repository(),
                data_provider.get_claim_repository(),
                config.clone(),
                protocol_provider.clone(),
                data_provider.get_did_repository(),
                formatter_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                revocation_method_provider.clone(),
            ),
            credential_schema_service: CredentialSchemaService::new(
                data_provider.get_credential_schema_repository(),
                data_provider.get_organisation_repository(),
                config.clone(),
            ),
            key_service: KeyService::new(
                data_provider.get_key_repository(),
                data_provider.get_organisation_repository(),
                key_provider,
                config.clone(),
            ),
            proof_schema_service: ProofSchemaService::new(
                data_provider.get_proof_schema_repository(),
                data_provider.get_claim_schema_repository(),
                data_provider.get_organisation_repository(),
            ),
            proof_service: ProofService::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_proof_schema_repository(),
                data_provider.get_did_repository(),
                data_provider.get_interaction_repository(),
                protocol_provider.clone(),
                config.clone(),
            ),
            ssi_verifier_service: SSIVerifierService::new(
                data_provider.get_claim_schema_repository(),
                data_provider.get_claim_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_did_repository(),
                formatter_provider.clone(),
                did_method_provider,
                revocation_method_provider,
                key_algorithm_provider,
            ),
            ssi_issuer_service: SSIIssuerService::new(
                data_provider.get_credential_repository(),
                data_provider.get_did_repository(),
                protocol_provider.clone(),
            ),
            ssi_holder_service: SSIHolderService::new(
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_did_repository(),
                formatter_provider,
                protocol_provider,
            ),
            config_service: ConfigService::new(config.clone()),
            crypto,
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
