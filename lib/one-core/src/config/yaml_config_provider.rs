use serde::de::Error;

use crate::config::{
    config_provider::{process_and_validate_config, ConfigProvider},
    data_structure::CoreConfig,
    ConfigParseError,
};

pub struct YamlConfigProvider {}

impl ConfigProvider for YamlConfigProvider {
    fn parse_config(
        &self,
        value: &str,
        transport_protocols: &[String],
        credential_formatters: &[String],
    ) -> Result<CoreConfig, ConfigParseError> {
        let config: CoreConfig = serde_yaml::from_str(value)
            .map_err(|e| serde_json::Error::custom(e.to_string()))
            .map_err(ConfigParseError::JsonError)?;
        let config =
            process_and_validate_config(config, transport_protocols, credential_formatters)?;
        Ok(config)
    }
}
