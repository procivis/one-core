use crate::config::data_structure::{
    CoreConfig, DatatypeEntity, DatatypeType, DidEntity, DidType, ExchangeEntity, FormatEntity,
    KeyStorageEntity, RevocationEntity, TranslatableString,
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
                r#type: DidType::Key,
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
        ]),
    }
}
