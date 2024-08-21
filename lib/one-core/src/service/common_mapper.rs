use crate::config::core_config::ConfigBlock;
use crate::model::credential_schema::CredentialSchema;
use crate::repository::error::DataLayerError;
use std::collections::HashMap;
use uuid::Uuid;

pub fn core_type_to_open_core_type(
    value: &ConfigBlock<crate::config::core_config::DatatypeType>,
) -> HashMap<String, one_providers::exchange_protocol::openid4vc::model::DatatypeType> {
    value
        .iter()
        .map(|(k, v)| {
            let v = match v.r#type {
                crate::config::core_config::DatatypeType::String => {
                    one_providers::exchange_protocol::openid4vc::model::DatatypeType::String
                }
                crate::config::core_config::DatatypeType::Number => {
                    one_providers::exchange_protocol::openid4vc::model::DatatypeType::Number
                }
                crate::config::core_config::DatatypeType::Date => {
                    one_providers::exchange_protocol::openid4vc::model::DatatypeType::Date
                }
                crate::config::core_config::DatatypeType::File => {
                    one_providers::exchange_protocol::openid4vc::model::DatatypeType::File
                }
                crate::config::core_config::DatatypeType::Object => {
                    one_providers::exchange_protocol::openid4vc::model::DatatypeType::Object
                }
                crate::config::core_config::DatatypeType::Array => {
                    one_providers::exchange_protocol::openid4vc::model::DatatypeType::Array
                }
                crate::config::core_config::DatatypeType::Boolean => {
                    one_providers::exchange_protocol::openid4vc::model::DatatypeType::Boolean
                }
            };
            (k.to_owned(), v)
        })
        .collect()
}

pub(crate) async fn regenerate_credential_schema_uuids(
    mut credential_schema: CredentialSchema,
) -> Result<CredentialSchema, DataLayerError> {
    credential_schema.id = Uuid::new_v4().into();
    let mut claim_schemas = credential_schema.claim_schemas.get().await?;
    claim_schemas.iter_mut().for_each(|schema| {
        schema.schema.id = Uuid::new_v4().into();
    });
    credential_schema.claim_schemas = claim_schemas.into();

    Ok(credential_schema)
}
