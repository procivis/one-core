use crate::config::{
    config_provider::{process_and_validate_config, ConfigProvider},
    data_structure::CoreConfig,
    ConfigParseError,
};

pub struct JsonConfigProvider {}

impl ConfigProvider for JsonConfigProvider {
    fn parse_config(
        &self,
        value: &str,
        transport_protocols: &[String],
        credential_formatters: &[String],
    ) -> Result<CoreConfig, ConfigParseError> {
        let config: CoreConfig =
            serde_json::from_str(value).map_err(ConfigParseError::JsonError)?;
        let config =
            process_and_validate_config(config, transport_protocols, credential_formatters)?;
        Ok(config)
    }
}
