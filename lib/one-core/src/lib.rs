#![cfg_attr(feature = "strict", deny(warnings))]

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::ConfigParseError;
use credential_formatter::jwt_formatter::JWTFormatter;
use credential_formatter::provider::CredentialFormatterProviderImpl;
use credential_formatter::sdjwt::SDJWTFormatter;
use credential_formatter::CredentialFormatter;
use crypto::hasher::sha256::SHA256;
use crypto::hasher::Hasher;
use crypto::signer::eddsa::EDDSASigner;
use crypto::signer::Signer;
use crypto::Crypto;
use repository::DataRepository;
use service::{
    config::ConfigService, credential::CredentialService, did::DidService,
    organisation::OrganisationService, proof::ProofService, proof_schema::ProofSchemaService,
    ssi_holder::SSIHolderService, ssi_issuer::SSIIssuerService, ssi_verifier::SSIVerifierService,
};
use transport_protocol::{
    procivis_temp::ProcivisTemp, provider::TransportProtocolProviderImpl, TransportProtocol,
};

pub mod config;
pub mod credential_formatter;
pub mod key_storage;
pub mod revocation;
pub mod transport_protocol;

pub mod crypto;

pub mod model;
pub mod repository;
pub mod service;

pub mod bitstring;
pub mod common_mapper;

use crate::config::data_structure::{CoreConfig, UnparsedConfig};
use crate::key_storage::provider::KeyProviderImpl;
use crate::key_storage::{key_providers_from_config, KeyStorage};
use crate::revocation::none::NoneRevocation;
use crate::revocation::provider::RevocationMethodProviderImpl;
use crate::revocation::statuslist2021::StatusList2021;
use crate::revocation::RevocationMethod;
use crate::service::credential_schema::CredentialSchemaService;
use crate::service::key::KeyService;
use crate::service::revocation_list::RevocationListService;

// Clone just for now. Later it should be removed.
#[derive(Clone)]
pub struct OneCore {
    pub key_providers: HashMap<String, Arc<dyn KeyStorage + Send + Sync>>,
    pub transport_protocols: Vec<(String, Arc<dyn TransportProtocol + Send + Sync>)>,
    pub credential_formatters: Vec<(String, Arc<dyn CredentialFormatter + Send + Sync>)>,
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
    pub ssi_issuer_service: SSIIssuerService,
    pub ssi_holder_service: SSIHolderService,
    pub config: Arc<CoreConfig>,
    pub crypto: Crypto,
}

impl OneCore {
    pub fn new(
        data_provider: Arc<dyn DataRepository>,
        unparsed_config: UnparsedConfig,
        core_base_url: Option<String>,
    ) -> Result<OneCore, ConfigParseError> {
        // For now we will just put them here.
        // We will introduce a builder later.

        let hashers: Vec<(String, Arc<dyn Hasher + Send + Sync>)> =
            vec![("sha-256".to_string(), Arc::new(SHA256 {}))];

        let signers: Vec<(String, Arc<dyn Signer + Send + Sync>)> =
            vec![("Ed25519".to_string(), Arc::new(EDDSASigner {}))];

        let crypto = Crypto {
            hashers: HashMap::from_iter(hashers),
            signers: HashMap::from_iter(signers),
        };

        let transport_protocols: Vec<(String, Arc<dyn TransportProtocol + Send + Sync>)> = vec![(
            "PROCIVIS_TEMPORARY".to_string(),
            Arc::new(ProcivisTemp::default()),
        )];
        let jwt_formatter = Arc::new(JWTFormatter {});
        let sdjwt_formatter = Arc::new(SDJWTFormatter {
            crypto: crypto.clone(),
        });
        let credential_formatters: Vec<(String, Arc<dyn CredentialFormatter + Send + Sync>)> = vec![
            ("JWT".to_string(), jwt_formatter),
            ("SDJWT".to_string(), sdjwt_formatter),
        ];
        let revocation_methods: Vec<(String, Arc<dyn RevocationMethod + Send + Sync>)> = vec![
            ("NONE".to_string(), Arc::new(NoneRevocation {})),
            (
                "STATUSLIST2021".to_string(),
                Arc::new(StatusList2021 {
                    core_base_url,
                    credential_repository: data_provider.get_credential_repository(),
                    revocation_list_repository: data_provider.get_revocation_list_repository(),
                }),
            ),
        ];

        let config = config::config_provider::parse_config(
            unparsed_config,
            &transport_protocols
                .iter()
                .map(|i| i.0.to_owned())
                .collect::<Vec<String>>(),
            &credential_formatters
                .iter()
                .map(|i| i.0.to_owned())
                .collect::<Vec<String>>(),
        )?;

        let key_providers = key_providers_from_config(&config.key_storage)?;

        let formatter_provider = Arc::new(CredentialFormatterProviderImpl::new(
            credential_formatters.to_owned(),
        ));
        let key_provider = Arc::new(KeyProviderImpl::new(key_providers.to_owned()));
        let protocol_provider = Arc::new(TransportProtocolProviderImpl::new(
            transport_protocols.to_owned(),
        ));
        let revocation_method_provider = Arc::new(RevocationMethodProviderImpl::new(
            revocation_methods.to_owned(),
        ));

        let config = Arc::new(config);

        Ok(OneCore {
            key_providers,
            transport_protocols,
            credential_formatters,
            revocation_methods,
            organisation_service: OrganisationService::new(
                data_provider.get_organisation_repository(),
            ),
            credential_service: CredentialService::new(
                data_provider.get_credential_repository(),
                data_provider.get_credential_schema_repository(),
                data_provider.get_did_repository(),
                revocation_method_provider.clone(),
                config.clone(),
            ),
            did_service: DidService::new(
                data_provider.get_did_repository(),
                data_provider.get_organisation_repository(),
                data_provider.get_key_repository(),
                key_provider.clone(),
                config.clone(),
            ),
            revocation_list_service: RevocationListService::new(
                data_provider.get_revocation_list_repository(),
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
            ),
            ssi_verifier_service: SSIVerifierService::new(
                data_provider.get_claim_schema_repository(),
                data_provider.get_claim_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_did_repository(),
                formatter_provider.clone(),
            ),
            ssi_issuer_service: SSIIssuerService::new(
                data_provider.get_credential_repository(),
                data_provider.get_did_repository(),
                formatter_provider.clone(),
                revocation_method_provider,
            ),
            ssi_holder_service: SSIHolderService::new(
                data_provider.get_credential_schema_repository(),
                data_provider.get_credential_repository(),
                data_provider.get_proof_repository(),
                data_provider.get_did_repository(),
                data_provider.get_interaction_repository(),
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
