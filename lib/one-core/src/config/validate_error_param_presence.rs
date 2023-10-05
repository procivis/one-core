use serde::de::Error;

use crate::config::{
    data_structure::{ConfigEntity, CoreConfig, ParamsEnum},
    process_config_object::merge_public_and_private,
    ConfigParseError,
};

fn validate_error_param_presence_in_value_params(
    key: &str,
    params: &serde_json::Value,
) -> Result<(), ConfigParseError> {
    if params.is_null() {
        return Ok(());
    }

    let public = params["public"].to_owned();
    let private = params["private"].to_owned();
    let merged_params = merge_public_and_private(public, private)?;

    let object = merged_params
        .as_object()
        .ok_or(serde_json::Error::custom("json is not an object"))?;
    let has_validation_params = object
        .keys()
        .any(|key| matches!(key.as_str(), "min" | "max" | "pattern"));

    if has_validation_params && !object.contains_key("error") {
        Err(ConfigParseError::MissingErrorMessage(key.to_owned()))
    } else {
        Ok(())
    }
}

fn validate_error_param_presence_generic<TypeEnum, ParamsType>(
    args: (&String, &ConfigEntity<TypeEnum, ParamsType>),
) -> Result<(), ConfigParseError> {
    let (key, entity) = args;
    match &entity.params {
        None => Ok(()),
        Some(value) => match value {
            ParamsEnum::Unparsed(value) => {
                validate_error_param_presence_in_value_params(key, value)
            }
            ParamsEnum::Parsed(_) => Err(ConfigParseError::JsonError(serde_json::Error::custom(
                "error parameter validation should be done on unparsed params",
            ))),
        },
    }
}

pub fn validate_error_param_presence(config: &CoreConfig) -> Result<(), ConfigParseError> {
    config
        .format
        .iter()
        .try_for_each(validate_error_param_presence_generic)?;
    config
        .exchange
        .iter()
        .try_for_each(validate_error_param_presence_generic)?;
    config
        .transport
        .iter()
        .try_for_each(validate_error_param_presence_generic)?;
    config
        .revocation
        .iter()
        .try_for_each(validate_error_param_presence_generic)?;
    config
        .did
        .iter()
        .try_for_each(validate_error_param_presence_generic)?;
    config
        .datatype
        .iter()
        .try_for_each(validate_error_param_presence_generic)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::{
        data_structure::{
            CoreConfig, DatatypeEntity, DatatypeType, FormatEntity, ParamsEnum, TranslatableString,
        },
        validate_error_param_presence::{
            validate_error_param_presence, validate_error_param_presence_in_value_params,
        },
    };
    use std::collections::HashMap;

    #[test]
    fn test_validate_single_value() {
        let correct_value: serde_json::Value = serde_yaml::from_str(
            r#"
public:
  min: 1900-01-01
  max: "NOW"
  error: "datatype.birth_date_error"
private:
  some_irrelevant_arg: 123
"#,
        )
        .unwrap();
        assert!(validate_error_param_presence_in_value_params("whatever", &correct_value).is_ok());

        let missing_error_param: serde_json::Value = serde_yaml::from_str(
            r#"
public:
  min: 1900-01-01
  max: "NOW"
private:
  some_irrelevant_arg: 123
"#,
        )
        .unwrap();
        assert!(
            validate_error_param_presence_in_value_params("whatever", &missing_error_param)
                .is_err()
        );

        let unrelated_params_exist: serde_json::Value = serde_yaml::from_str(
            r#"
public:
  some_irrelevant_arg: 123
"#,
        )
        .unwrap();
        assert!(
            validate_error_param_presence_in_value_params("whatever", &unrelated_params_exist)
                .is_ok()
        );

        let no_params_exist: serde_json::Value = serde_yaml::from_str("").unwrap();
        assert!(
            validate_error_param_presence_in_value_params("whatever", &no_params_exist).is_ok()
        );

        let params_are_null: serde_json::Value = serde_yaml::from_str("null").unwrap();
        assert!(
            validate_error_param_presence_in_value_params("whatever", &params_are_null).is_ok()
        );
    }

    #[test]
    fn test_validate_config() {
        let valid_config = CoreConfig {
            format: HashMap::from([(
                "JWT".to_string(),
                FormatEntity {
                    r#type: "JWT".to_string(),
                    display: TranslatableString::Key("format.jwt".to_string()),
                    order: None,
                    params: None,
                },
            )]),
            exchange: Default::default(),
            transport: Default::default(),
            revocation: Default::default(),
            did: Default::default(),
            datatype: HashMap::from([
                (
                    "EMAIL".to_string(),
                    DatatypeEntity {
                        r#type: DatatypeType::String,
                        display: TranslatableString::Key("datatype.email".to_string()),
                        order: None,
                        params: Some(ParamsEnum::Unparsed(
                            serde_yaml::from_str(
                                r#"
public:
  autocomplete: true
  placeholder: "abc@abc.com"
  error:
    de: "Please provide email like abc@abc.com"
    en: "Please provide email like abc@abc.com"
  pattern: '^[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,4}$'"#,
                            )
                            .unwrap(),
                        )),
                    },
                ),
                (
                    "COUNT".to_string(),
                    DatatypeEntity {
                        r#type: DatatypeType::Number,
                        display: TranslatableString::Key("datatype.count".to_string()),
                        order: None,
                        params: Some(ParamsEnum::Unparsed(
                            serde_yaml::from_str(
                                r#"
public:
  min: 0 # optional
  max: 9999 # optional
  error: "datatype.count_error""#,
                            )
                            .unwrap(),
                        )),
                    },
                ),
            ]),
            key_algorithm: Default::default(),
            key_storage: Default::default(),
        };

        let result = validate_error_param_presence(&valid_config);
        assert!(result.is_ok());

        let invalid_config_missing_error_param = CoreConfig {
            format: Default::default(),
            exchange: Default::default(),
            transport: Default::default(),
            revocation: Default::default(),
            did: Default::default(),
            datatype: HashMap::from([(
                "EMAIL".to_string(),
                DatatypeEntity {
                    r#type: DatatypeType::String,
                    display: TranslatableString::Key("datatype.email".to_string()),
                    order: None,
                    params: Some(ParamsEnum::Unparsed(
                        serde_yaml::from_str(
                            r#"
public:
  autocomplete: true
  placeholder: "abc@abc.com"
  pattern: '^[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,4}$'"#,
                        )
                        .unwrap(),
                    )),
                },
            )]),
            key_algorithm: Default::default(),
            key_storage: Default::default(),
        };

        let result = validate_error_param_presence(&invalid_config_missing_error_param);
        assert!(result.is_err());
    }
}
