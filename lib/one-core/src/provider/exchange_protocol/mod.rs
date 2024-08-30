use std::collections::HashMap;
use std::sync::Arc;

use one_providers::common_models::interaction::OpenInteraction;
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::did::provider::DidMethodProvider;
use one_providers::exchange_protocol::imp::provider::ExchangeProtocolWrapper;
use one_providers::exchange_protocol::openid4vc::imp::OpenID4VCHTTP;
use one_providers::exchange_protocol::openid4vc::{
    ExchangeProtocolError, ExchangeProtocolImpl, StorageAccess,
};
use one_providers::exchange_protocol::provider::ExchangeProtocol;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use one_providers::key_storage::provider::KeyProvider;
use one_providers::revocation::provider::RevocationMethodProvider;
use openid4vc::openidvc_ble::OpenID4VCBLE;
use procivis_temp::ProcivisTemp;
use serde::de::Deserialize;
use url::Url;

use crate::config::core_config::{CoreConfig, ExchangeType};
use crate::config::ConfigValidationError;
use crate::provider::exchange_protocol::iso_mdl::IsoMdl;
use crate::provider::exchange_protocol::openid4vc::OpenID4VC;
use crate::provider::exchange_protocol::scan_to_verify::ScanToVerify;
use crate::repository::DataRepository;
use crate::util::ble_resource::BleWaiter;

pub mod dto;
pub mod iso_mdl;
mod mapper;
pub mod openid4vc;
pub mod procivis_temp;
pub(crate) mod provider;
pub mod scan_to_verify;

#[cfg(test)]
mod test;

pub(super) fn get_base_url_from_interaction(
    interaction: Option<&OpenInteraction>,
) -> Result<Url, ExchangeProtocolError> {
    interaction
        .ok_or(ExchangeProtocolError::Failed(
            "interaction is None".to_string(),
        ))?
        .host
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "interaction host is missing".to_string(),
        ))
        .cloned()
}

pub fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    data: Option<&Vec<u8>>,
) -> Result<DataDTO, ExchangeProtocolError> {
    let data = data.ok_or(ExchangeProtocolError::Failed(
        "interaction data is missing".to_string(),
    ))?;
    serde_json::from_slice(data).map_err(ExchangeProtocolError::JsonError)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn exchange_protocol_providers_from_config(
    config: Arc<CoreConfig>,
    core_base_url: Option<String>,
    data_provider: Arc<dyn DataRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    ble: Option<BleWaiter>,
) -> Result<HashMap<String, Arc<dyn ExchangeProtocol>>, ConfigValidationError> {
    let mut providers: HashMap<String, Arc<dyn ExchangeProtocol>> = HashMap::new();

    for (name, fields) in config.exchange.iter() {
        match fields.r#type {
            ExchangeType::ProcivisTemporary => {
                let protocol = Arc::new(ExchangeProtocolWrapper::new(ProcivisTemp::new(
                    core_base_url.clone(),
                    formatter_provider.clone(),
                    key_provider.clone(),
                    config.clone(),
                )));

                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::ScanToVerify => {
                let protocol = Arc::new(ExchangeProtocolWrapper::new(ScanToVerify::new(
                    formatter_provider.clone(),
                    key_algorithm_provider.clone(),
                    did_method_provider.clone(),
                )));

                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::OpenId4Vc => {
                let params = config.exchange.get(name)?;
                let ble = OpenID4VCBLE::new(
                    data_provider.get_proof_repository(),
                    data_provider.get_interaction_repository(),
                    formatter_provider.clone(),
                    key_provider.clone(),
                    ble.clone(),
                    config.clone(),
                );
                let http = OpenID4VCHTTP::new(
                    core_base_url.clone(),
                    formatter_provider.clone(),
                    revocation_method_provider.clone(),
                    key_provider.clone(),
                    key_algorithm_provider.clone(),
                    params,
                );
                let protocol = Arc::new(OpenID4VC::new(http, ble));
                providers.insert(name.to_string(), protocol);
            }
            ExchangeType::IsoMdl => {
                let protocol = Arc::new(ExchangeProtocolWrapper::new(IsoMdl::new(config.clone())));

                providers.insert(name.to_string(), protocol);
            }
        }
    }

    Ok(providers)
}
