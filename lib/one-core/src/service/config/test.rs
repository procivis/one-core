use serde_json::json;
use similar_asserts::assert_eq;

use crate::config::core_config::{CoreConfig, DatatypeType, Fields, Params};
use crate::service::config::dto::ConfigDTO;

#[test]
fn convert_internal_structure_to_dto() {
    let mut config = CoreConfig::default();

    config.datatype.insert(
        "STRING".to_string(),
        Fields {
            r#type: DatatypeType::String,
            display: "display".into(),
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
          "identifier": {},
          "issuanceProtocol": {},
          "verificationProtocol": {},
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
          "holderKeyStorage": {},
          "keyStorage": {},
          "trustManagement": {},
          "blobStorage": {},
          "cacheEntities": {},
          "task": {},
          "walletProvider": {},
          "credentialIssuer": {}
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
            display: "display".into(),
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
          "identifier": {},
          "issuanceProtocol": {},
          "verificationProtocol": {},
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
          "holderKeyStorage": {},
          "keyStorage": {},
          "trustManagement": {},
          "blobStorage": {},
          "cacheEntities": {},
          "task": {},
          "walletProvider": {},
          "credentialIssuer": {}
        }),
        output
    );
}
