use std::collections::BTreeSet;

use itertools::Itertools;

use crate::config::core_config::{Fields, TransportConfig, TransportType};
use crate::provider::verification_protocol::dto::VerificationProtocolCapabilities;
use crate::service::error::ValidationError;

pub(crate) enum SelectedTransportType {
    Single(String),
    Multiple(Vec<String>),
}

pub(crate) fn get_first_available_transport<'config>(
    config: &'config TransportConfig,
    supported_options: &[TransportType],
) -> Result<(&'config str, TransportType), ValidationError> {
    config
        .iter()
        .filter(|(_, fields)| fields.enabled())
        .filter(|(_, fields)| supported_options.contains(&fields.r#type))
        .sorted_by_key(|(_, fields)| fields.order)
        .next()
        .map(|(ty, fields)| (ty, fields.r#type))
        .ok_or(ValidationError::MissingDefaultTransport)
}

pub(crate) fn validate_and_select_transport_type(
    transport: &Option<Vec<String>>,
    config: &TransportConfig,
    exchange_protocol_capabilities: &VerificationProtocolCapabilities,
) -> Result<SelectedTransportType, ValidationError> {
    let check_transport_capabilities = |transport| {
        let r#type = config
            .get_fields(transport)
            .map_err(|e| ValidationError::InvalidTransportType {
                value: transport.into(),
                source: e.into(),
            })?
            .r#type;

        if !exchange_protocol_capabilities
            .supported_transports
            .contains(&r#type)
        {
            return Err(ValidationError::TransportNotAllowedForExchange);
        }

        Ok(())
    };

    match transport.as_deref() {
        // transport not provided in request, we select the first in order from the config
        None | Some([]) => {
            let (selected_transport, _) = get_first_available_transport(
                config,
                &exchange_protocol_capabilities.supported_transports,
            )?;

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
            for transport in multiple_transports {
                let fields = validate_transport_type(transport, config)?;
                check_transport_capabilities(transport)?;

                requested_combination.insert(fields.r#type);
            }

            if requested_combination != allowed_combination {
                return Err(ValidationError::TransportsCombinationNotAllowed);
            }

            Ok(SelectedTransportType::Multiple(
                multiple_transports.to_vec(),
            ))
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

    use similar_asserts::assert_eq;

    use super::validate_and_select_transport_type;
    use crate::config::core_config::{CoreConfig, Fields, TransportType};
    use crate::config::validator::transport::SelectedTransportType;
    use crate::provider::verification_protocol::dto::VerificationProtocolCapabilities;
    use crate::service::error::ValidationError;

    #[test]
    fn test_selects_first_in_order_transport_from_config_if_transport_is_none() {
        let config = config(&["BLE", "MQTT"]);
        let capabilities = VerificationProtocolCapabilities {
            supported_transports: vec![TransportType::Ble, TransportType::Mqtt],
            did_methods: vec![],
            verifier_identifier_types: vec![],
        };

        let selected =
            validate_and_select_transport_type(&None, &config.transport, &capabilities).unwrap();

        assert!(matches!(selected,
            SelectedTransportType::Single(transport) if transport == "BLE"
        ))
    }

    #[test]
    fn test_selects_one_transport() {
        let config = config(&["MQTT"]);
        let capabilities = VerificationProtocolCapabilities {
            supported_transports: vec![TransportType::Mqtt],
            did_methods: vec![],
            verifier_identifier_types: vec![],
        };

        let selected = validate_and_select_transport_type(
            &Some(vec!["MQTT".into()]),
            &config.transport,
            &capabilities,
        )
        .unwrap();

        assert!(matches!(selected,
            SelectedTransportType::Single(transport) if transport == "MQTT"
        ))
    }

    #[test]
    fn test_selects_multiple_transports() {
        let config = config(&["BLE", "MQTT"]);
        let capabilities = VerificationProtocolCapabilities {
            supported_transports: vec![TransportType::Ble, TransportType::Mqtt],
            did_methods: vec![],
            verifier_identifier_types: vec![],
        };

        let selected = validate_and_select_transport_type(
            &Some(vec!["MQTT".into(), "BLE".into()]),
            &config.transport,
            &capabilities,
        )
        .unwrap();

        assert2::let_assert!(SelectedTransportType::Multiple(transports) = selected);
        let transports = BTreeSet::from_iter(transports);

        assert_eq!(maplit::btreeset!["BLE".into(), "MQTT".into()], transports);
    }

    #[test]
    fn test_fails_if_capability_is_missing() {
        let config = config(&["MQTT"]);
        let capabilities = VerificationProtocolCapabilities {
            supported_transports: vec![],
            did_methods: vec![],
            verifier_identifier_types: vec![],
        };

        let selected = validate_and_select_transport_type(
            &Some(vec!["MQTT".into()]),
            &config.transport,
            &capabilities,
        );

        assert!(matches!(
            selected,
            Err(ValidationError::TransportNotAllowedForExchange)
        ));
    }

    #[test]
    fn test_fails_when_transport_combination_is_not_allowed() {
        let config = config(&["BLE", "MQTT", "HTTP"]);
        let capabilities = VerificationProtocolCapabilities {
            supported_transports: vec![
                TransportType::Ble,
                TransportType::Mqtt,
                TransportType::Http,
            ],
            did_methods: vec![],
            verifier_identifier_types: vec![],
        };

        let selected = validate_and_select_transport_type(
            &Some(vec!["MQTT".into(), "BLE".into(), "HTTP".into()]),
            &config.transport,
            &capabilities,
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
                    enabled: Some(true),
                    capabilities: None,
                    params: None,
                },
            );
        }

        config
    }
}
