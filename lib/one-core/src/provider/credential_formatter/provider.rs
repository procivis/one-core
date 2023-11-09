use super::CredentialFormatter;
use crate::config::data_structure::{FormatEntity, FormatJwtParams, FormatParams, ParamsEnum};
use crate::config::ConfigParseError;
use crate::crypto::CryptoProvider;
use crate::provider::credential_formatter::json_ld_formatter::JsonLdFormatter;
use crate::provider::credential_formatter::jwt_formatter::JWTFormatter;
use crate::provider::credential_formatter::mdoc_formatter::MdocFormatter;
use crate::provider::credential_formatter::sdjwt_formatter::SDJWTFormatter;
use crate::service::error::ServiceError;
use std::{collections::HashMap, sync::Arc};

#[cfg_attr(test, mockall::automock)]
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
    crypto: Arc<dyn CryptoProvider + Send + Sync>,
) -> Result<HashMap<String, Arc<dyn CredentialFormatter + Send + Sync>>, ConfigParseError> {
    format_config
        .iter()
        .map(|(name, entity)| formatter_from_entity(name, entity, crypto.clone()))
        .collect::<Result<HashMap<String, _>, _>>()
}

fn get_jwt_params(
    entity: &FormatEntity,
    name: &String,
) -> Result<FormatJwtParams, ConfigParseError> {
    match &entity.params {
        None => Ok(FormatJwtParams::default()),
        Some(value) => match value {
            ParamsEnum::Parsed(FormatParams::Jwt(value)) => Ok(value.to_owned()),
            _ => Err(ConfigParseError::InvalidType(
                name.to_owned(),
                String::new(),
            )),
        },
    }
}

fn formatter_from_entity(
    name: &String,
    entity: &FormatEntity,
    crypto: Arc<dyn CryptoProvider + Send + Sync>,
) -> Result<(String, Arc<dyn CredentialFormatter + Send + Sync>), ConfigParseError> {
    match entity.r#type.as_str() {
        "MDOC" => {
            let params = get_jwt_params(entity, name)?;
            Ok((name.to_owned(), Arc::new(MdocFormatter { params })))
        }
        "JSON_LD" => {
            let params = get_jwt_params(entity, name)?;
            Ok((name.to_owned(), Arc::new(JsonLdFormatter { params })))
        }
        "JWT" => {
            let params = get_jwt_params(entity, name)?;
            Ok((name.to_owned(), Arc::new(JWTFormatter { params })))
        }
        "SDJWT" => {
            let params = get_jwt_params(entity, name)?;
            Ok((name.to_owned(), Arc::new(SDJWTFormatter { crypto, params })))
        }
        _ => Err(ConfigParseError::InvalidType(
            entity.r#type.to_owned(),
            String::new(),
        )),
    }
}
