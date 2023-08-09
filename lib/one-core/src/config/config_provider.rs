use crate::config::validate_types::validate_types;
use crate::config::{
    data_structure::{ConfigKind, CoreConfig, UnparsedConfig},
    process_config_object::*,
    ConfigParseError,
    {json_config_provider::JsonConfigProvider, yaml_config_provider::YamlConfigProvider},
};

pub trait ConfigProvider {
    fn parse_config(
        &self,
        value: &str,
        transport_protocols: &[String],
        credential_formatters: &[String],
    ) -> Result<CoreConfig, ConfigParseError>;
}

pub fn parse_config(
    unparsed_config: UnparsedConfig,
    transport_protocols: &[String],
    credential_formatters: &[String],
) -> Result<CoreConfig, ConfigParseError> {
    match unparsed_config.kind {
        ConfigKind::Json => JsonConfigProvider {}.parse_config(
            &unparsed_config.content,
            transport_protocols,
            credential_formatters,
        ),
        ConfigKind::Yaml => YamlConfigProvider {}.parse_config(
            &unparsed_config.content,
            transport_protocols,
            credential_formatters,
        ),
    }
}

pub(super) fn process_and_validate_config(
    mut config: CoreConfig,
    transport_protocols: &[String],
    credential_formatters: &[String],
) -> Result<CoreConfig, ConfigParseError> {
    config.format =
        postprocess_format_entities(config.format).map_err(ConfigParseError::JsonError)?;
    config.exchange =
        postprocess_exchange_entities(config.exchange).map_err(ConfigParseError::JsonError)?;
    config.did = postprocess_did_entities(config.did).map_err(ConfigParseError::JsonError)?;
    config.datatype =
        postprocess_datatype_entities(config.datatype).map_err(ConfigParseError::JsonError)?;

    validate_types(&config.format, credential_formatters)?;
    validate_types(&config.exchange, transport_protocols)?;

    Ok(config)
}
