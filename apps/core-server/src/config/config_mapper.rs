use serde_json::Value;
use std::collections::HashMap;

use crate::dto::response::config::ConfigDTO;
use one_core::config::data_structure::{AccessModifier, Param};

impl TryFrom<one_core::config::data_structure::CoreConfig> for ConfigDTO {
    type Error = serde_json::Error;

    fn try_from(config: one_core::config::data_structure::CoreConfig) -> Result<Self, Self::Error> {
        let value = serde_json::to_value(config)?;
        let mut dto: ConfigDTO = serde_json::from_value(value)?;

        dto.format = filter_config_entities(dto.format);
        dto.exchange = filter_config_entities(dto.exchange);
        dto.revocation = filter_config_entities(dto.revocation);
        dto.did = filter_config_entities(dto.did);
        dto.datatype = filter_config_entities(dto.datatype);

        Ok(dto)
    }
}

fn filter_config_entities(map: HashMap<String, Value>) -> HashMap<String, Value> {
    map.into_iter()
        .map(|(k, v)| (k, filter_config_entity(v)))
        .collect()
}

fn filter_config_entity(mut value: Value) -> Value {
    let params = value.get("params");
    match params {
        None => value,
        Some(unpacked) => {
            value["params"] = unpack_and_filter_json_values(unpacked.to_owned());
            value
        }
    }
}

fn unpack_and_filter_json_values(params: serde_json::Value) -> serde_json::Value {
    match params.as_object() {
        None => params,
        Some(value) => {
            let parsed: HashMap<String, Value> = value
                .into_iter()
                .filter_map(|(k, v)| {
                    Some((k.to_owned(), unpack_and_filter_json_value(v.to_owned())?))
                })
                .collect();
            serde_json::to_value(parsed).ok().unwrap_or(params)
        }
    }
}

fn unpack_and_filter_json_value(param: serde_json::Value) -> Option<serde_json::Value> {
    let deserialized: Param<serde_json::Value> = serde_json::from_value(param).ok()?;
    match deserialized.access {
        AccessModifier::Public => Some(deserialized.value),
        AccessModifier::Private => None,
    }
}
