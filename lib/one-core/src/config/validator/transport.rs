use std::collections::{BTreeMap, BTreeSet};

use crate::config::core_config::{Fields, TransportConfig, TransportType};
use crate::provider::exchange_protocol::provider::ExchangeProtocol;
use crate::service::error::ValidationError;

pub enum SelectedTransportType {
    Single(String),
    Multiple(Vec<String>),
}

pub fn get_first_available_transport_type(
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
            let (selected_transport, _) = get_first_available_transport_type(config)?;
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
            let mut selected_transports = BTreeMap::new();

            for transport in multiple_transports {
                let fields = validate_transport_type(transport, config)?;
                check_transport_capabilities(transport)?;

                requested_combination.insert(fields.r#type);

                let order = fields.order.unwrap_or_default();
                selected_transports.insert(order, transport.to_owned());
            }

            if requested_combination != allowed_combination {
                return Err(ValidationError::TransportsCombinationNotAllowed);
            }

            let selected_transports = selected_transports.into_values().collect();

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

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use super::validate_and_select_transport_type;
    use crate::config::core_config::{CoreConfig, Fields, TransportType};
    use crate::config::validator::transport::SelectedTransportType;
    use crate::provider::exchange_protocol::dto::{ExchangeProtocolCapabilities, Operation};
    use crate::provider::exchange_protocol::{MockExchangeProtocol, MockExchangeProtocolImpl};
    use crate::service::error::ValidationError;

    #[test]
    fn test_selects_first_in_order_transport_from_config_if_transport_is_none() {
        let config = config(&["BLE", "MQTT"]);

        let mut exchange_protocol = MockExchangeProtocolImpl::default();
        exchange_protocol
            .expect_get_capabilities()
            .returning(|| ExchangeProtocolCapabilities {
                supported_transports: vec!["BLE".into(), "MQTT".into()],
                operations: vec![Operation::ISSUANCE, Operation::VERIFICATION],
            });

        let exchange_protocol = MockExchangeProtocol::new(exchange_protocol);

        let selected =
            validate_and_select_transport_type(&None, &config.transport, &exchange_protocol)
                .unwrap();

        assert!(matches!(selected,
            SelectedTransportType::Single(transport) if transport == "BLE"
        ))
    }

    #[test]
    fn test_selects_one_transport() {
        let config = config(&["MQTT"]);

        let mut exchange_protocol = MockExchangeProtocolImpl::default();
        exchange_protocol
            .expect_get_capabilities()
            .returning(|| ExchangeProtocolCapabilities {
                supported_transports: vec!["MQTT".into()],
                operations: vec![Operation::ISSUANCE, Operation::VERIFICATION],
            });

        let exchange_protocol = MockExchangeProtocol::new(exchange_protocol);

        let selected = validate_and_select_transport_type(
            &Some(vec!["MQTT".into()]),
            &config.transport,
            &exchange_protocol,
        )
        .unwrap();

        assert!(matches!(selected,
            SelectedTransportType::Single(transport) if transport == "MQTT"
        ))
    }

    #[test]
    fn test_selects_multiple_transports() {
        let config = config(&["BLE", "MQTT"]);

        let mut exchange_protocol = MockExchangeProtocolImpl::default();
        exchange_protocol
            .expect_get_capabilities()
            .returning(|| ExchangeProtocolCapabilities {
                supported_transports: vec!["BLE".into(), "MQTT".into()],
                operations: vec![Operation::ISSUANCE, Operation::VERIFICATION],
            });

        let exchange_protocol = MockExchangeProtocol::new(exchange_protocol);

        let selected = validate_and_select_transport_type(
            &Some(vec!["MQTT".into(), "BLE".into()]),
            &config.transport,
            &exchange_protocol,
        )
        .unwrap();

        assert2::let_assert!(SelectedTransportType::Multiple(transports) = selected);
        let transports = BTreeSet::from_iter(transports);

        assert_eq!(maplit::btreeset!["BLE".into(), "MQTT".into()], transports);
    }

    #[test]
    fn test_fails_if_capability_is_missing() {
        let config = config(&["MQTT"]);

        let mut exchange_protocol = MockExchangeProtocolImpl::default();
        exchange_protocol
            .expect_get_capabilities()
            .returning(|| ExchangeProtocolCapabilities {
                supported_transports: vec![],
                operations: vec![Operation::ISSUANCE, Operation::VERIFICATION],
            });

        let exchange_protocol = MockExchangeProtocol::new(exchange_protocol);

        let selected = validate_and_select_transport_type(
            &Some(vec!["MQTT".into()]),
            &config.transport,
            &exchange_protocol,
        );

        assert!(matches!(
            selected,
            Err(ValidationError::TransportNotAllowedForExchange)
        ));
    }

    #[test]
    fn test_fails_when_transport_combination_is_not_allowed() {
        let config = config(&["BLE", "MQTT", "HTTP"]);

        let mut exchange_protocol = MockExchangeProtocolImpl::default();
        exchange_protocol
            .expect_get_capabilities()
            .returning(|| ExchangeProtocolCapabilities {
                supported_transports: vec!["BLE".into(), "MQTT".into(), "HTTP".into()],
                operations: vec![Operation::ISSUANCE, Operation::VERIFICATION],
            });

        let exchange_protocol = MockExchangeProtocol::new(exchange_protocol);

        let selected = validate_and_select_transport_type(
            &Some(vec!["MQTT".into(), "BLE".into(), "HTTP".into()]),
            &config.transport,
            &exchange_protocol,
        );

        assert!(matches!(
            selected,
            Err(ValidationError::TransportsCombinationNotAllowed)
        ));
    }

    fn config(transports: &[&str]) -> CoreConfig {
        let mut config = CoreConfig::default();

        for (order, transport) in transports.iter().enumerate() {
            config.transport.insert(
                transport.to_string(),
                Fields {
                    r#type: TransportType::try_from(*transport).unwrap(),
                    display: "".into(),
                    order: Some(order as u64),
                    disabled: Some(false),
                    capabilities: None,
                    params: None,
                },
            );
        }

        config
    }
}
