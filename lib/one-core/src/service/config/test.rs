use serde_json::{json, Value};

use crate::{
    config::core_config::{CoreConfig, DatatypeType, Fields, Params},
    service::config::dto::ConfigDTO,
};

#[test]
fn convert_internal_structure_to_dto() {
    let mut config = CoreConfig::default();

    config.datatype.insert(
        "STRING".to_string(),
        Fields {
            r#type: DatatypeType::String,
            display: Value::String("display".to_string()),
            order: None,
            disabled: None,
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
    let text_output = serde_json::to_string_pretty(&output).unwrap();

    assert_eq!(
        r#"{
  "format": {},
  "exchange": {},
  "revocation": {},
  "did": {},
  "datatype": {
    "STRING": {
      "disabled": null,
      "display": "display",
      "order": null,
      "params": {
        "autocomplete": false
      },
      "type": "STRING"
    }
  },
  "keyAlgorithm": {},
  "keyStorage": {}
}"#,
        text_output
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
            disabled: None,
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
    let text_output = serde_json::to_string_pretty(&output).unwrap();

    assert_eq!(
        r#"{
  "format": {},
  "exchange": {},
  "revocation": {},
  "did": {},
  "datatype": {
    "STRING": {
      "disabled": null,
      "display": "display",
      "order": null,
      "params": {},
      "type": "STRING"
    }
  },
  "keyAlgorithm": {},
  "keyStorage": {}
}"#,
        text_output
    );
}
