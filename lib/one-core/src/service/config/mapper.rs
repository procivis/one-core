use std::collections::HashMap;

use serde_json::Value;

use super::dto::ConfigDTO;
use crate::config::core_config::CoreConfig;

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
        dto.key_algorithm = filter_config_entities(dto.key_algorithm);
        dto.key_storage = filter_config_entities(dto.key_storage);
        dto.trust_management = filter_config_entities(dto.trust_management);
        dto.cache_entities = filter_config_entities(dto.cache_entities);
        dto.transport = filter_config_entities(dto.transport);

        Ok(dto)
    }
}

fn filter_config_entities(map: HashMap<String, Value>) -> HashMap<String, Value> {
    map.into_iter()
        .map(|(k, v)| (k, filter_config_entity(v)))
        .collect()
}

fn filter_config_entity(mut value: Value) -> Value {
    if let Some(params) = value["params"].as_object_mut() {
        _ = params.remove("private");
        let public_params = params
            .remove("public")
            .and_then(|v| v.as_object().cloned())
            .into_iter()
            .flatten();

        params.extend(public_params);
    }

    value
}
