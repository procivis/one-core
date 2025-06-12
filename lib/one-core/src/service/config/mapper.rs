use serde_json::{Map, Value};

use super::dto::ConfigDTO;
use crate::config::core_config::CoreConfig;

impl TryFrom<&CoreConfig> for ConfigDTO {
    type Error = serde_json::Error;

    fn try_from(config: &CoreConfig) -> Result<Self, Self::Error> {
        let mut value = serde_json::to_value(config)?;
        filter_config_entries(&mut value);
        serde_json::from_value(value)
    }
}

fn filter_config_entries(config: &mut Value) {
    if let Some(config) = config.as_object_mut() {
        for (_, entities) in config.iter_mut() {
            if let Some(entities) = entities.as_object_mut() {
                for (_, entity) in entities.iter_mut() {
                    if let Some(entity) = entity.as_object_mut() {
                        filter_entity_params(entity);
                    }
                }
            }
        }
    }
}

/// hides private params, and lifts public params
fn filter_entity_params(entity: &mut Map<String, Value>) {
    if entity.contains_key("params") {
        if let Some(params) = entity["params"].as_object_mut() {
            params.remove("private");
            let public_params = params
                .remove("public")
                .and_then(|v| v.as_object().cloned())
                .into_iter()
                .flatten();

            params.extend(public_params);
        }
    }
}
