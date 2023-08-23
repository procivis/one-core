#![cfg_attr(feature = "strict", deny(warnings))]

use std::sync::Arc;

use crate::config::ConfigParseError;
use credential_formatter::jwt_formatter::JWTFormatter;
use credential_formatter::CredentialFormatter;
use error::OneCoreError;
use repository::{
    data_provider::DataProvider, organisation_repository::OrganisationRepository, DataRepository,
};
use service::organisation::OrganisationService;
use signature_provider::SignatureProvider;
use transport_protocol::procivis_temp::ProcivisTemp;
use transport_protocol::TransportProtocol;

pub mod config;
pub mod credential_formatter;
pub mod data_model;
pub mod error;
pub mod handle_invitation;
pub mod holder_reject_proof_request;
pub mod holder_submit_proof;
pub mod issuer_connect;
pub mod signature_provider;
pub mod transport_protocol;
pub mod verifier_connect;
pub mod verifier_reject_proof_request;
pub mod verifier_submit;

pub mod model;
pub mod repository;
pub mod service;

mod local_did_helpers;

use crate::config::data_structure::{CoreConfig, UnparsedConfig};

// Clone just for now. Later it should be removed.
#[derive(Clone)]
pub struct OneCore {
    //data_repository: Arc<dyn DataRepository>,
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    // FIXME: data_layer will be removed
    pub data_layer: Arc<dyn DataProvider + Send + Sync>,
    pub transport_protocols: Vec<(String, Arc<dyn TransportProtocol + Send + Sync>)>,
    pub signature_providers: Vec<(String, Arc<dyn SignatureProvider + Send + Sync>)>,
    pub credential_formatters: Vec<(String, Arc<dyn CredentialFormatter + Send + Sync>)>,
    pub organisation_service: OrganisationService,
    pub config: CoreConfig,
}

impl OneCore {
    pub fn new(
        data_provider: Arc<dyn DataRepository>,
        unparsed_config: UnparsedConfig,
    ) -> Result<OneCore, ConfigParseError> {
        // For now we will just put them here.
        // We will introduce a builder later.

        let transport_protocols: Vec<(String, Arc<dyn TransportProtocol + Send + Sync>)> = vec![(
            "PROCIVIS_TEMPORARY".to_string(),
            Arc::new(ProcivisTemp::default()),
        )];
        let credential_formatters: Vec<(String, Arc<dyn CredentialFormatter + Send + Sync>)> =
            vec![("JWT".to_string(), Arc::new(JWTFormatter {}))];
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

        Ok(OneCore {
            //data_repository: data_provider.clone(),
            organisation_repository: data_provider.get_organisation_repository(),
            data_layer: data_provider.get_data_provider(),
            transport_protocols,
            signature_providers: vec![],
            credential_formatters,
            organisation_service: OrganisationService::new(
                data_provider.get_organisation_repository(),
            ),
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

    fn get_transport_protocol(
        &self,
        protocol: &str,
    ) -> Result<Arc<dyn TransportProtocol + Send + Sync>, OneCoreError> {
        self.transport_protocols
            .iter()
            .find(|(key, _)| key == protocol)
            .map(|(_, transport)| transport.clone())
            .ok_or(OneCoreError::SSIError(
                error::SSIError::UnsupportedTransportProtocol,
            ))
    }

    fn get_formatter(
        &self,
        format: &str,
    ) -> Result<Arc<dyn CredentialFormatter + Send + Sync>, OneCoreError> {
        self.credential_formatters
            .iter()
            .find(|(key, _)| key == format)
            .map(|(_, formatter)| formatter.clone())
            .ok_or(OneCoreError::SSIError(
                error::SSIError::UnsupportedCredentialFormat,
            ))
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
