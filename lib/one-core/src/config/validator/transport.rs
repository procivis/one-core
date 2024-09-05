use crate::config::core_config::TransportConfig;
use crate::service::error::ValidationError;

pub fn get_available_transport_type(config: &TransportConfig) -> Result<&str, ValidationError> {
    config
        .iter()
        .find(|(_, obj)| !obj.disabled.unwrap_or(false))
        .map(|(key, _)| key)
        .ok_or(ValidationError::MissingDefaultTransport)
}
