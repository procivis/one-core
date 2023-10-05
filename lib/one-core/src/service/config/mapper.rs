use super::dto::ConfigDTO;
use crate::config::data_structure::{AccessModifier, CoreConfig, Param};
use serde_json::Value;
use std::collections::HashMap;

impl TryFrom<&CoreConfig> for ConfigDTO {
    type Error = serde_json::Error;

    fn try_from(config: &CoreConfig) -> Result<Self, Self::Error> {
        let value = serde_json::to_value(config)?;
        let mut dto: ConfigDTO = serde_json::from_value(value)?;

        dto.format = filter_config_entities(dto.format);
        dto.exchange = filter_config_entities(dto.exchange);
        dto.revocation = filter_config_entities(dto.revocation);
        dto.did = filter_config_entities(dto.did);
        dto.datatype = filter_config_entities(dto.datatype);
        dto.key = filter_config_entities(dto.key);

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

fn unpack_and_filter_json_values(params: Value) -> Value {
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

fn unpack_and_filter_json_value(param: Value) -> Option<Value> {
    let deserialized: Param<Value> = serde_json::from_value(param).ok()?;
    match deserialized.access {
        AccessModifier::Public => Some(deserialized.value),
        AccessModifier::Private => None,
    }
}
