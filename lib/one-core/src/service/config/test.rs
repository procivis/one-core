use serde_json::{json, Value};

use crate::config::core_config::{CoreConfig, DatatypeType, Fields, Params};
use crate::service::config::dto::ConfigDTO;

#[test]
fn convert_internal_structure_to_dto() {
    let mut config = CoreConfig::default();

    config.datatype.insert(
        "STRING".to_string(),
        Fields {
            r#type: DatatypeType::String,
            display: Value::String("display".to_string()),
            order: None,
            enabled: None,
            capabilities: None,
            params: Some(Params {
                public: Some(json!({
                    "autocomplete": false
                })),
                private: Some(json!({
                    "other": false
                })),
            }),
        },
    );

    let output = ConfigDTO::try_from(&config).unwrap();
    let output = serde_json::to_value(&output).unwrap();

    assert_eq!(
        json!({
          "format": {},
          "exchange": {},
          "revocation": {},
          "did": {},
          "datatype": {
            "STRING": {
              "display": "display",
              "params": {
                "autocomplete": false
              },
              "type": "STRING"
            }
          },
          "transport": {},
          "keyAlgorithm": {},
          "keyStorage": {},
          "trustManagement": {},
          "cacheEntities": {},
        }),
        output
    );
}

#[test]
fn do_not_serialize_private_parameters() {
    let mut config = CoreConfig::default();

    config.datatype.insert(
        "STRING".to_string(),
        Fields {
            r#type: DatatypeType::String,
            display: Value::String("display".to_string()),
            order: None,
            enabled: None,
            capabilities: None,
            params: Some(Params {
                public: None,
                private: Some(json!({
                    "autocomplete": false
                })),
            }),
        },
    );

    let output = ConfigDTO::try_from(&config).unwrap();
    let output = serde_json::to_value(&output).unwrap();

    assert_eq!(
        json!({
          "format": {},
          "exchange": {},
          "transport": {},
          "revocation": {},
          "did": {},
          "datatype": {
            "STRING": {
              "display": "display",
              "params": {},
              "type": "STRING"
            }
          },
          "keyAlgorithm": {},
          "keyStorage": {},
          "trustManagement": {},
          "cacheEntities": {},
        }),
        output
    );
}
