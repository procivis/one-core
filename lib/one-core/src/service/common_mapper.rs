use std::collections::HashMap;

use uuid::Uuid;

use crate::config::core_config::ConfigBlock;
use crate::model::credential_schema::CredentialSchema;

pub fn core_type_to_open_core_type(
    value: &ConfigBlock<crate::config::core_config::DatatypeType>,
) -> HashMap<String, crate::provider::exchange_protocol::openid4vc::model::DatatypeType> {
    value
        .iter()
        .map(|(k, v)| {
            let v = match v.r#type {
                crate::config::core_config::DatatypeType::String => {
                    crate::provider::exchange_protocol::openid4vc::model::DatatypeType::String
                }
                crate::config::core_config::DatatypeType::Number => {
                    crate::provider::exchange_protocol::openid4vc::model::DatatypeType::Number
                }
                crate::config::core_config::DatatypeType::Date => {
                    crate::provider::exchange_protocol::openid4vc::model::DatatypeType::Date
                }
                crate::config::core_config::DatatypeType::File => {
                    crate::provider::exchange_protocol::openid4vc::model::DatatypeType::File
                }
                crate::config::core_config::DatatypeType::Object => {
                    crate::provider::exchange_protocol::openid4vc::model::DatatypeType::Object
                }
                crate::config::core_config::DatatypeType::Array => {
                    crate::provider::exchange_protocol::openid4vc::model::DatatypeType::Array
                }
                crate::config::core_config::DatatypeType::Boolean => {
                    crate::provider::exchange_protocol::openid4vc::model::DatatypeType::Boolean
                }
            };
            (k.to_owned(), v)
        })
        .collect()
}

pub(crate) fn regenerate_credential_schema_uuids(
    mut credential_schema: CredentialSchema,
) -> CredentialSchema {
    credential_schema.id = Uuid::new_v4().into();
    if let Some(claim_schemas) = credential_schema.claim_schemas.as_mut() {
        claim_schemas.iter_mut().for_each(|schema| {
            schema.schema.id = Uuid::new_v4().into();
        })
    }

    credential_schema
}
