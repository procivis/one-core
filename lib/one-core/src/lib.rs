#![cfg_attr(feature = "strict", deny(warnings))]

use std::sync::Arc;

use crate::config::ConfigParseError;
use credential_formatter::jwt_formatter::JWTFormatter;
use credential_formatter::CredentialFormatter;
use data_layer::DataLayer;
use error::OneCoreError;
use signature_provider::SignatureProvider;
use transport_protocol::procivis_temp::ProcivisTemp;
use transport_protocol::TransportProtocol;

pub mod config;
pub mod credential_formatter;
pub mod data_layer;
pub mod data_model;
pub mod error;
pub mod handle_invitation;
pub mod issuer_connect;
pub mod signature_provider;
pub mod transport_protocol;
pub mod verifier_connect;
pub mod verifier_reject_proof_request;
//pub mod verifier_submit;

use crate::config::data_structure::{CoreConfig, UnparsedConfig};

// Clone just for now. Later it should be removed.
#[derive(Clone)]
pub struct OneCore {
    pub data_layer: DataLayer,
    pub transport_protocols: Vec<(String, Arc<dyn TransportProtocol + Send + Sync>)>,
    pub signature_providers: Vec<(String, Arc<dyn SignatureProvider + Send + Sync>)>,
    pub credential_formatters: Vec<(String, Arc<dyn CredentialFormatter + Send + Sync>)>,
    pub config: CoreConfig,
}

impl OneCore {
    pub async fn new(
        database_url: &str,
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
            data_layer: DataLayer::create(database_url).await,
            transport_protocols,
            signature_providers: vec![],
            credential_formatters,
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
