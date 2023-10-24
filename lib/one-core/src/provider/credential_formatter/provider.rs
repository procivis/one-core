use super::CredentialFormatter;
use crate::config::data_structure::{FormatEntity, FormatJwtParams, FormatParams, ParamsEnum};
use crate::config::ConfigParseError;
use crate::crypto::Crypto;
use crate::provider::credential_formatter::jwt_formatter::JWTFormatter;
use crate::provider::credential_formatter::sdjwt_formatter::SDJWTFormatter;
use crate::service::error::ServiceError;
use std::{collections::HashMap, sync::Arc};

pub(crate) trait CredentialFormatterProvider {
    fn get_formatter(
        &self,
        formatter_id: &str,
    ) -> Result<Arc<dyn CredentialFormatter + Send + Sync>, ServiceError>;
}

pub(crate) struct CredentialFormatterProviderImpl {
    formatters: HashMap<String, Arc<dyn CredentialFormatter + Send + Sync>>,
}

impl CredentialFormatterProviderImpl {
    pub fn new(formatters: HashMap<String, Arc<dyn CredentialFormatter + Send + Sync>>) -> Self {
        Self { formatters }
    }
}

impl CredentialFormatterProvider for CredentialFormatterProviderImpl {
    fn get_formatter(
        &self,
        format: &str,
    ) -> Result<Arc<dyn CredentialFormatter + Send + Sync>, ServiceError> {
        Ok(self
            .formatters
            .get(format)
            .ok_or(ServiceError::NotFound)?
            .clone())
    }
}

pub(crate) fn credential_formatters_from_config(
    format_config: &HashMap<String, FormatEntity>,
    crypto: Crypto,
) -> Result<HashMap<String, Arc<dyn CredentialFormatter + Send + Sync>>, ConfigParseError> {
    format_config
        .iter()
        .map(|(name, entity)| formatter_from_entity(name, entity, crypto.clone()))
        .collect::<Result<HashMap<String, _>, _>>()
}

fn formatter_from_entity(
    name: &String,
    entity: &FormatEntity,
    crypto: Crypto,
) -> Result<(String, Arc<dyn CredentialFormatter + Send + Sync>), ConfigParseError> {
    match entity.r#type.as_str() {
        "JWT" => {
            let params = match &entity.params {
                None => Ok(FormatJwtParams::default()),
                Some(value) => match value {
                    ParamsEnum::Parsed(FormatParams::Jwt(value)) => Ok(value.to_owned()),
                    _ => Err(ConfigParseError::InvalidType(
                        name.to_owned(),
                        String::new(),
                    )),
                },
            }?;
            Ok((name.to_owned(), Arc::new(JWTFormatter { params })))
        }
        "SDJWT" => {
            let params = match &entity.params {
                None => Ok(FormatJwtParams::default()),
                Some(value) => match value {
                    ParamsEnum::Parsed(FormatParams::Jwt(value)) => Ok(value.to_owned()),
                    _ => Err(ConfigParseError::InvalidType(
                        name.to_owned(),
                        String::new(),
                    )),
                },
            }?;
            Ok((name.to_owned(), Arc::new(SDJWTFormatter { crypto, params })))
        }
        _ => Err(ConfigParseError::InvalidType(
            entity.r#type.to_owned(),
            String::new(),
        )),
    }
}
