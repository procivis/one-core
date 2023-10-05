use std::collections::HashMap;

use serde::de::Error;

use crate::config::data_structure::{
    AccessModifier, DatatypeDateParams, DatatypeEntity, DatatypeEnumParams, DatatypeNumberParams,
    DatatypeParams, DatatypeStringParams, DatatypeType, DidEntity, DidKeyParams, DidParams,
    DidType, ExchangeEntity, FormatEntity, KeyStorageEntity, KeyStorageHsmAzureParams, KeyStorageInternalParams,
    KeyStorageParams, ParamsEnum, RevocationEntity, TransportEntity,
};

fn convert_param_to_param_map(
    param: serde_json::Value,
    access: AccessModifier,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut new_value = serde_json::Value::default();
    new_value["access"] = serde_json::to_value(access)?;
    new_value["value"] = param;

    Ok(new_value)
}

fn convert_params_to_param_map(
    params: serde_json::Value,
    access: AccessModifier,
) -> Result<serde_json::Value, serde_json::Error> {
    if params.is_null() {
        return Ok(params);
    }

    let object = params
        .as_object()
        .ok_or(serde_json::Error::custom("json is not an object"))?
        .to_owned();

    let result: Result<HashMap<String, serde_json::Value>, serde_json::Error> = object
        .into_iter()
        .map(|(key, value)| Ok((key, convert_param_to_param_map(value, access)?)))
        .collect();
    serde_json::to_value(result?)
}

pub(super) fn merge_public_and_private(
    public: serde_json::Value,
    private: serde_json::Value,
) -> Result<serde_json::Value, serde_json::Error> {
    let public = convert_params_to_param_map(public, AccessModifier::Public)?;
    let private = convert_params_to_param_map(private, AccessModifier::Private)?;

    if public.is_null() {
        return Ok(private);
    }
    if private.is_null() {
        return Ok(public);
    }

    let mut public = public
        .as_object()
        .ok_or(serde_json::Error::custom(
            "`public` is not an object".to_string(),
        ))?
        .to_owned();
    let private = private
        .as_object()
        .ok_or(serde_json::Error::custom(
            "`private` is not an object".to_string(),
        ))?
        .to_owned();

    public.extend(private);

    Ok(public.into())
}

fn postprocess_format_entity(entity: FormatEntity) -> Result<FormatEntity, serde_json::Error> {
    let parsed_params = match entity.params {
        None => None,
        Some(value) => match value {
            ParamsEnum::Unparsed(value) => {
                let public = value["public"].to_owned();
                let private = value["private"].to_owned();
                Some(ParamsEnum::Parsed(merge_public_and_private(
                    public, private,
                )?))
            }
            ParamsEnum::Parsed(value) => Some(ParamsEnum::Parsed(value)),
        },
    };

    Ok(FormatEntity {
        r#type: entity.r#type,
        display: entity.display,
        order: entity.order,
        params: parsed_params,
    })
}

fn postprocess_exchange_entity(
    entity: ExchangeEntity,
) -> Result<ExchangeEntity, serde_json::Error> {
    let parsed_params = match entity.params {
        None => None,
        Some(value) => match value {
            ParamsEnum::Unparsed(value) => {
                let public = value["public"].to_owned();
                let private = value["private"].to_owned();
                Some(ParamsEnum::Parsed(merge_public_and_private(
                    public, private,
                )?))
            }
            ParamsEnum::Parsed(value) => Some(ParamsEnum::Parsed(value)),
        },
    };

    Ok(ExchangeEntity {
        r#type: entity.r#type,
        display: entity.display,
        order: entity.order,
        params: parsed_params,
    })
}

fn postprocess_transport_entity(
    entity: TransportEntity,
) -> Result<TransportEntity, serde_json::Error> {
    let parsed_params = match entity.params {
        None => None,
        Some(value) => match value {
            ParamsEnum::Unparsed(value) => {
                let public = value["public"].to_owned();
                let private = value["private"].to_owned();
                Some(ParamsEnum::Parsed(merge_public_and_private(
                    public, private,
                )?))
            }
            ParamsEnum::Parsed(value) => Some(ParamsEnum::Parsed(value)),
        },
    };

    Ok(TransportEntity {
        r#type: entity.r#type,
        display: entity.display,
        order: entity.order,
        params: parsed_params,
    })
}

fn postprocess_revocation_entity(
    entity: RevocationEntity,
) -> Result<RevocationEntity, serde_json::Error> {
    let parsed_params = match entity.params {
        None => None,
        Some(value) => match value {
            ParamsEnum::Unparsed(value) => {
                let public = value["public"].to_owned();
                let private = value["private"].to_owned();
                Some(ParamsEnum::Parsed(merge_public_and_private(
                    public, private,
                )?))
            }
            ParamsEnum::Parsed(value) => Some(ParamsEnum::Parsed(value)),
        },
    };

    Ok(RevocationEntity {
        r#type: entity.r#type,
        display: entity.display,
        order: entity.order,
        params: parsed_params,
    })
}

fn postprocess_did_entity(entity: DidEntity) -> Result<DidEntity, serde_json::Error> {
    let parsed_params = match entity.params {
        None => None,
        Some(value) => match value {
            ParamsEnum::Unparsed(value) => match entity.r#type {
                DidType::Key => {
                    let public = value["public"].to_owned();
                    let private = value["private"].to_owned();
                    let merged = merge_public_and_private(public, private)?;

                    let params: DidKeyParams = serde_json::from_value(merged)?;
                    Some(ParamsEnum::Parsed(DidParams::Key(params)))
                }
            },
            ParamsEnum::Parsed(value) => Some(ParamsEnum::Parsed(value)),
        },
    };

    Ok(DidEntity {
        r#type: entity.r#type,
        display: entity.display,
        order: entity.order,
        params: parsed_params,
    })
}

fn postprocess_datatype_entity(
    entity: DatatypeEntity,
) -> Result<DatatypeEntity, serde_json::Error> {
    let parsed_params = match entity.params {
        None => None,
        Some(value) => match value {
            ParamsEnum::Unparsed(value) => {
                let public = value["public"].to_owned();
                let private = value["private"].to_owned();
                let merged = merge_public_and_private(public, private)?;

                match entity.r#type {
                    DatatypeType::String => {
                        let params: DatatypeStringParams = serde_json::from_value(merged)?;
                        Some(ParamsEnum::Parsed(DatatypeParams::String(params)))
                    }
                    DatatypeType::Number => {
                        let params: DatatypeNumberParams = serde_json::from_value(merged)?;
                        Some(ParamsEnum::Parsed(DatatypeParams::Number(params)))
                    }
                    DatatypeType::Date => {
                        let params: DatatypeDateParams = serde_json::from_value(merged)?;
                        Some(ParamsEnum::Parsed(DatatypeParams::Date(params)))
                    }
                    DatatypeType::Enum => {
                        let params: DatatypeEnumParams = serde_json::from_value(merged)?;
                        Some(ParamsEnum::Parsed(DatatypeParams::Enum(params)))
                    }
                }
            }
            ParamsEnum::Parsed(value) => Some(ParamsEnum::Parsed(value)),
        },
    };

    Ok(DatatypeEntity {
        r#type: entity.r#type,
        display: entity.display,
        order: entity.order,
        params: parsed_params,
    })
}

fn postprocess_key_entity(entity: KeyStorageEntity) -> Result<KeyStorageEntity, serde_json::Error> {
    let parsed_params = match entity.params {
        None => None,
        Some(value) => match value {
            ParamsEnum::Unparsed(value) => {
                let public = value["public"].to_owned();
                let private = value["private"].to_owned();
                let merged = merge_public_and_private(public, private)?;

                match entity.r#type.as_str() {
                    "INTERNAL" => {
                        let params: KeyStorageInternalParams = serde_json::from_value(merged)?;
                        Some(ParamsEnum::Parsed(KeyStorageParams::Internal(params)))
                    }
                    "HSM_AZURE" => {
                        let params: KeyStorageHsmAzureParams = serde_json::from_value(merged)?;
                        Some(ParamsEnum::Parsed(KeyStorageParams::HsmAzure(params)))
                    }
                    _ => Some(ParamsEnum::Parsed(KeyStorageParams::Unknown(merged))),
                }
            }
            ParamsEnum::Parsed(value) => Some(ParamsEnum::Parsed(value)),
        },
    };

    Ok(KeyStorageEntity {
        r#type: entity.r#type,
        display: entity.display,
        order: entity.order,
        params: parsed_params,
    })
}

pub fn postprocess_format_entities(
    entities: HashMap<String, FormatEntity>,
) -> Result<HashMap<String, FormatEntity>, serde_json::Error> {
    entities
        .into_iter()
        .map(|(k, v)| Ok((k, postprocess_format_entity(v)?)))
        .collect()
}

pub fn postprocess_exchange_entities(
    entities: HashMap<String, ExchangeEntity>,
) -> Result<HashMap<String, ExchangeEntity>, serde_json::Error> {
    entities
        .into_iter()
        .map(|(k, v)| Ok((k, postprocess_exchange_entity(v)?)))
        .collect()
}

pub fn postprocess_transport_entities(
    entities: HashMap<String, TransportEntity>,
) -> Result<HashMap<String, TransportEntity>, serde_json::Error> {
    entities
        .into_iter()
        .map(|(k, v)| Ok((k, postprocess_transport_entity(v)?)))
        .collect()
}

pub fn postprocess_revocation_entities(
    entities: HashMap<String, RevocationEntity>,
) -> Result<HashMap<String, RevocationEntity>, serde_json::Error> {
    entities
        .into_iter()
        .map(|(k, v)| Ok((k, postprocess_revocation_entity(v)?)))
        .collect()
}

pub fn postprocess_did_entities(
    entities: HashMap<String, DidEntity>,
) -> Result<HashMap<String, DidEntity>, serde_json::Error> {
    entities
        .into_iter()
        .map(|(k, v)| Ok((k, postprocess_did_entity(v)?)))
        .collect()
}

pub fn postprocess_datatype_entities(
    entities: HashMap<String, DatatypeEntity>,
) -> Result<HashMap<String, DatatypeEntity>, serde_json::Error> {
    entities
        .into_iter()
        .map(|(k, v)| Ok((k, postprocess_datatype_entity(v)?)))
        .collect()
}

pub fn postprocess_key_entities(
    entities: HashMap<String, KeyStorageEntity>,
) -> Result<HashMap<String, KeyStorageEntity>, serde_json::Error> {
    entities
        .into_iter()
        .map(|(k, v)| Ok((k, postprocess_key_entity(v)?)))
        .collect()
}
