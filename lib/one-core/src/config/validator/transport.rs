use std::collections::BTreeSet;

use crate::config::core_config::{Fields, TransportConfig, TransportType};
use crate::provider::exchange_protocol::provider::ExchangeProtocol;
use crate::service::error::ValidationError;

pub enum SelectedTransportType {
    Single(String),
    Multiple(Vec<String>),
}

pub fn get_available_transport_type(
    config: &TransportConfig,
) -> Result<(&str, TransportType), ValidationError> {
    config
        .get_first_enabled()
        .map(|(ty, fields)| (ty, fields.r#type))
        .ok_or(ValidationError::MissingDefaultTransport)
}

pub fn validate_and_select_transport_type(
    transport: &Option<Vec<String>>,
    config: &TransportConfig,
    exchange_protocol: &dyn ExchangeProtocol,
) -> Result<SelectedTransportType, ValidationError> {
    let capabilities = exchange_protocol.get_capabilities().supported_transports;
    let check_transport_capabilities = |transport| {
        if !capabilities.iter().any(|t| t == transport) {
            return Err(ValidationError::TransportNotAllowedForExchange);
        }

        Ok(())
    };

    match transport.as_deref() {
        // transport not provided in request, we select the first in order from the config
        None | Some([]) => {
            let (selected_transport, _) = get_available_transport_type(config)?;
            check_transport_capabilities(selected_transport)?;

            Ok(SelectedTransportType::Single(selected_transport.to_owned()))
        }
        Some([transport]) => {
            validate_transport_type(transport, config)?;
            check_transport_capabilities(transport)?;

            Ok(SelectedTransportType::Single(transport.to_owned()))
        }
        // for multiple transports in request we allow only [MQTT, BLE] combinations
        Some(multiple_transports) => {
            let allowed_combination =
                BTreeSet::from_iter([TransportType::Ble, TransportType::Mqtt]);

            let mut requested_combination = BTreeSet::new();
            let mut selected_transports = Vec::with_capacity(multiple_transports.len());

            for transport in multiple_transports {
                let fields = validate_transport_type(transport, config)?;
                check_transport_capabilities(transport)?;

                requested_combination.insert(fields.r#type);
                selected_transports.push(transport.to_owned());
            }

            if requested_combination != allowed_combination {
                return Err(ValidationError::TransportsCombinationNotAllowed);
            }

            Ok(SelectedTransportType::Multiple(selected_transports))
        }
    }
}

fn validate_transport_type<'a>(
    transport: &str,
    config: &'a TransportConfig,
) -> Result<&'a Fields<TransportType>, ValidationError> {
    config
        .get_if_enabled(transport)
        .map_err(|err| ValidationError::InvalidTransportType {
            value: transport.into(),
            source: err.into(),
        })
}
