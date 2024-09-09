use crate::config::core_config::{TransportConfig, TransportType};
use crate::service::error::ValidationError;

pub fn get_available_transport_type(
    config: &TransportConfig,
) -> Result<(&str, TransportType), ValidationError> {
    config
        .iter()
        .find(|(_, obj)| !obj.disabled.unwrap_or(false))
        .map(|(key, content)| (key, content.r#type))
        .ok_or(ValidationError::MissingDefaultTransport)
}
