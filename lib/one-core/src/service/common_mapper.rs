use std::collections::HashMap;

use crate::config::core_config::ConfigBlock;

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
