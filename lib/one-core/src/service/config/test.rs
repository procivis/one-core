use crate::{
    config::data_structure::{
        AccessModifier, CoreConfig, DatatypeEntity, DatatypeParams, DatatypeStringParams,
        DatatypeType, Param, ParamsEnum, TranslatableString,
    },
    service::config::dto::ConfigDTO,
};
use std::collections::HashMap;

#[test]
fn convert_internal_structure_to_dto() {
    let config = CoreConfig {
        format: Default::default(),
        exchange: Default::default(),
        transport: Default::default(),
        revocation: Default::default(),
        did: Default::default(),
        datatype: HashMap::from([(
            "test".to_string(),
            DatatypeEntity {
                r#type: DatatypeType::String,
                display: TranslatableString::Key("display".to_string()),
                order: None,
                params: Some(ParamsEnum::Parsed(DatatypeParams::String(
                    DatatypeStringParams {
                        autocomplete: Some(Param::<bool> {
                            access: AccessModifier::Public,
                            value: false,
                        }),
                        placeholder: None,
                        error: None,
                        pattern: None,
                    },
                ))),
            },
        )]),
        key_storage: Default::default(),
    };
    let output = ConfigDTO::try_from(&config).unwrap();
    let text_output = serde_json::to_string_pretty(&output).unwrap();

    assert_eq!(
        r#"{
  "format": {},
  "exchange": {},
  "transport": {},
  "revocation": {},
  "did": {},
  "datatype": {
    "test": {
      "display": "display",
      "order": null,
      "params": {
        "autocomplete": false
      },
      "type": "STRING"
    }
  },
  "key": {}
}"#,
        text_output
    );
}

#[test]
fn do_not_serialize_private_parameters() {
    let config = CoreConfig {
        format: Default::default(),
        exchange: Default::default(),
        transport: Default::default(),
        revocation: Default::default(),
        did: Default::default(),
        datatype: HashMap::from([(
            "test".to_string(),
            DatatypeEntity {
                r#type: DatatypeType::String,
                display: TranslatableString::Key("display".to_string()),
                order: None,
                params: Some(ParamsEnum::Parsed(DatatypeParams::String(
                    DatatypeStringParams {
                        autocomplete: Some(Param::<bool> {
                            access: AccessModifier::Private,
                            value: false,
                        }),
                        placeholder: None,
                        error: None,
                        pattern: None,
                    },
                ))),
            },
        )]),
        key_storage: Default::default(),
    };

    let output = ConfigDTO::try_from(&config).unwrap();
    let text_output = serde_json::to_string_pretty(&output).unwrap();

    assert_eq!(
        r#"{
  "format": {},
  "exchange": {},
  "transport": {},
  "revocation": {},
  "did": {},
  "datatype": {
    "test": {
      "display": "display",
      "order": null,
      "params": {},
      "type": "STRING"
    }
  },
  "key": {}
}"#,
        text_output
    );
}
