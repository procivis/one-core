use crate::config::data_structure::{
    AccessModifier, CoreConfig, DatatypeEntity, DatatypeType, DidEntity, ExchangeEntity,
    FormatEntity, KeyAlgorithmEntity, KeyAlgorithmParams, KeyStorageEntity, Param, ParamsEnum,
    RevocationEntity, TranslatableString,
};
use std::collections::HashMap;

pub fn generic_config() -> CoreConfig {
    CoreConfig {
        format: HashMap::from([(
            "JWT".to_string(),
            FormatEntity {
                r#type: "JWT".to_string(),
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: None,
            },
        )]),
        exchange: HashMap::from([(
            "PROCIVIS_TEMPORARY".to_string(),
            ExchangeEntity {
                r#type: "PROCIVIS_TEMPORARY".to_string(),
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: None,
            },
        )]),
        transport: Default::default(),
        revocation: HashMap::from([
            (
                "NONE".to_string(),
                RevocationEntity {
                    r#type: "NONE".to_string(),
                    display: TranslatableString::Key("Display".to_string()),
                    order: None,
                    params: None,
                },
            ),
            (
                "STATUSLIST2021".to_string(),
                RevocationEntity {
                    r#type: "STATUSLIST2021".to_string(),
                    display: TranslatableString::Key("Display".to_string()),
                    order: None,
                    params: None,
                },
            ),
        ]),
        did: HashMap::from([(
            "KEY".to_string(),
            DidEntity {
                r#type: "KEY".to_string(),
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: None,
            },
        )]),
        datatype: HashMap::from([
            (
                "STRING".to_string(),
                DatatypeEntity {
                    r#type: DatatypeType::String,
                    display: TranslatableString::Key("Display".to_string()),
                    order: None,
                    params: None,
                },
            ),
            (
                "NUMBER".to_string(),
                DatatypeEntity {
                    r#type: DatatypeType::Number,
                    display: TranslatableString::Key("Display".to_string()),
                    order: None,
                    params: None,
                },
            ),
        ]),
        key_algorithm: HashMap::from([(
            "EDDSA".to_string(),
            KeyAlgorithmEntity {
                r#type: "EDDSA".to_string(),
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: Some(ParamsEnum::Parsed(KeyAlgorithmParams {
                    algorithm: Param {
                        access: AccessModifier::Public,
                        value: "Ed25519".to_string(),
                    },
                })),
            },
        )]),
        key_storage: HashMap::from([
            (
                "INTERNAL".to_string(),
                KeyStorageEntity {
                    r#type: "INTERNAL".to_string(),
                    display: TranslatableString::Key("Display".to_string()),
                    order: None,
                    params: None,
                },
            ),
            (
                "MEIN_AZURE_KEYVAULT".to_string(),
                KeyStorageEntity {
                    r#type: "HSM_AZURE".to_string(),
                    display: TranslatableString::Key("Display".to_string()),
                    order: None,
                    params: None,
                },
            ),
            (
                "MOCK".to_string(),
                KeyStorageEntity {
                    r#type: "MOCK".to_string(),
                    display: TranslatableString::Key("Display".to_string()),
                    order: None,
                    params: None,
                },
            ),
        ]),
    }
}
