use std::collections::HashMap;
use std::num::{ParseFloatError, ParseIntError};

use thiserror::Error;
use time::error::{ComponentRange, Parse, TryFromParsed};
use time::macros::format_description;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime};

use crate::config::{
    data_structure::{
        DatatypeDateParams, DatatypeEntity, DatatypeEnumParams, DatatypeNumberParams,
        DatatypeParams, DatatypeStringParams, DatatypeType, EnumValue, ParamsEnum,
    },
    validator::ConfigValidationError,
};

#[derive(Debug, PartialEq, Error)]
pub enum DatatypeValidationError {
    // string
    #[error("String invalid pattern: `{0}`")]
    StringInvalidPattern(regex::Error),
    #[error("String `{0}` does not match pattern `{1}`")]
    StringNotMatchingPattern(String, String),

    // number
    #[error("Number parse failure: `{0}`")]
    NumberParseFailure(ParseFloatError),
    #[error("Number too small (`{0}` < `{1}`)")]
    NumberTooSmall(f64, f64),
    #[error("Number too big (`{0}` > `{1}`)")]
    NumberTooBig(f64, f64),

    // date
    #[error("Date parse failure: `{0}`")]
    DateParseFailure(time::error::Parse),
    #[error("Date integer parse failure: `{0}`")]
    DateIntegerParseFailure(ParseIntError),
    #[error("Date component out of range: `{0}`")]
    DateComponentOutOfRange(ComponentRange),
    #[error("Date too early: `{0}` < `{1}`")]
    DateTooEarly(String, String),
    #[error("Date too late: `{0}` > `{1}`")]
    DateTooLate(String, String),

    // enum
    #[error("Enum invalid value: `{0}`")]
    EnumInvalidValue(String),
}

pub fn validate_datatypes(
    query_datatypes: &[&String],
    datatypes: &HashMap<String, DatatypeEntity>,
) -> Result<(), ConfigValidationError> {
    match query_datatypes
        .iter()
        .find(|datatype| !datatypes.contains_key(&***datatype))
    {
        None => Ok(()),
        Some(value) => Err(ConfigValidationError::KeyNotFound((*value).to_owned())),
    }
}

fn validate_value_type_and_params_type(
    value_type: DatatypeType,
    params: Option<&DatatypeParams>,
) -> Result<(), ConfigValidationError> {
    match params {
        None => Ok(()),
        Some(params) => match params {
            DatatypeParams::String(_) => {
                if value_type == DatatypeType::String {
                    Ok(())
                } else {
                    Err(ConfigValidationError::MismatchedValueTypeAndParamsType)
                }
            }
            DatatypeParams::Number(_) => {
                if value_type == DatatypeType::Number {
                    Ok(())
                } else {
                    Err(ConfigValidationError::MismatchedValueTypeAndParamsType)
                }
            }
            DatatypeParams::Date(_) => {
                if value_type == DatatypeType::Date {
                    Ok(())
                } else {
                    Err(ConfigValidationError::MismatchedValueTypeAndParamsType)
                }
            }
            DatatypeParams::Enum(_) => {
                if value_type == DatatypeType::Enum {
                    Ok(())
                } else {
                    Err(ConfigValidationError::MismatchedValueTypeAndParamsType)
                }
            }
        },
    }
}

fn validate_string(
    value: &str,
    params: Option<&DatatypeStringParams>,
) -> Result<(), DatatypeValidationError> {
    if let Some(params) = params {
        if let Some(pattern) = &params.pattern {
            let regex = regex::Regex::new(&pattern.value)
                .map_err(DatatypeValidationError::StringInvalidPattern)?;
            if !regex.is_match_at(value, 0) {
                return Err(DatatypeValidationError::StringNotMatchingPattern(
                    value.to_string(),
                    pattern.value.to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_number(
    value: &str,
    params: Option<&DatatypeNumberParams>,
) -> Result<(), DatatypeValidationError> {
    let number = value
        .parse::<f64>()
        .map_err(DatatypeValidationError::NumberParseFailure)?;

    if let Some(params) = params {
        if let Some(param) = &params.min {
            if param.value > number {
                return Err(DatatypeValidationError::NumberTooSmall(number, param.value));
            }
        }
        if let Some(param) = &params.max {
            if param.value < number {
                return Err(DatatypeValidationError::NumberTooBig(number, param.value));
            }
        }
    }

    Ok(())
}

fn parse_min_max_date(value: &str) -> Result<OffsetDateTime, DatatypeValidationError> {
    if value == "NOW" {
        return Ok(OffsetDateTime::now_utc());
    }

    let splits: Vec<&str> = value.split('-').collect();
    if splits.len() != 3 {
        return Err(DatatypeValidationError::DateParseFailure(
            Parse::TryFromParsed(TryFromParsed::InsufficientInformation),
        ));
    }

    let year = splits[0]
        .parse::<i32>()
        .map_err(DatatypeValidationError::DateIntegerParseFailure)?;
    let month = splits[1]
        .parse::<u8>()
        .map_err(DatatypeValidationError::DateIntegerParseFailure)?;
    let day = splits[2]
        .parse::<u8>()
        .map_err(DatatypeValidationError::DateIntegerParseFailure)?;

    let month = Month::try_from(month).map_err(DatatypeValidationError::DateComponentOutOfRange)?;

    let date = Date::from_calendar_date(year, month, day)
        .map_err(DatatypeValidationError::DateComponentOutOfRange)?;
    Ok(date.midnight().assume_utc())
}

fn validate_date(
    value: &str,
    params: Option<&DatatypeDateParams>,
) -> Result<(), DatatypeValidationError> {
    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    let date = match PrimitiveDateTime::parse(value, &format) {
        Ok(date) => Ok(date.assume_utc()),
        Err(error) => Err(DatatypeValidationError::DateParseFailure(error)),
    }?;

    if let Some(params) = params {
        if let Some(min) = &params.min {
            let min_date = parse_min_max_date(&min.value)?;
            if date < min_date {
                return Err(DatatypeValidationError::DateTooEarly(
                    value.to_string(),
                    min.value.to_owned(),
                ));
            }
        }
        if let Some(max) = &params.max {
            let max_date = parse_min_max_date(&max.value)?;
            if date > max_date {
                return Err(DatatypeValidationError::DateTooLate(
                    value.to_string(),
                    max.value.to_owned(),
                ));
            }
        }
    }

    Ok(())
}

fn extract_value(enum_value: &EnumValue) -> &String {
    match &enum_value.value {
        None => &enum_value.key,
        Some(value) => value,
    }
}

fn validate_enum(
    value: &str,
    params: Option<&DatatypeEnumParams>,
) -> Result<(), DatatypeValidationError> {
    if let Some(params) = params {
        if let Some(param) = &params.values {
            let found = param.value.iter().any(|p| {
                let param_value = extract_value(p);
                param_value == value
            });
            return match found {
                true => Ok(()),
                false => Err(DatatypeValidationError::EnumInvalidValue(value.to_string())),
            };
        }
    }

    Ok(())
}

fn match_value(
    value: &str,
    value_type: DatatypeType,
    params: Option<&DatatypeParams>,
) -> Result<(), ConfigValidationError> {
    validate_value_type_and_params_type(value_type.to_owned(), params)?;

    match params {
        None => match value_type {
            DatatypeType::String => Ok(validate_string(value, None)?),
            DatatypeType::Number => Ok(validate_number(value, None)?),
            DatatypeType::Date => Ok(validate_date(value, None)?),
            DatatypeType::Enum => Ok(validate_enum(value, None)?),
        },
        Some(params) => match params {
            DatatypeParams::String(params) => Ok(validate_string(value, Some(params))?),
            DatatypeParams::Number(params) => Ok(validate_number(value, Some(params))?),
            DatatypeParams::Date(params) => Ok(validate_date(value, Some(params))?),
            DatatypeParams::Enum(params) => Ok(validate_enum(value, Some(params))?),
        },
    }
}

pub fn validate_value(
    value: &str,
    datatype: &str,
    datatypes: &HashMap<String, DatatypeEntity>,
) -> Result<(), ConfigValidationError> {
    let (_, entity) = datatypes
        .iter()
        .find(|(key, _)| *key == datatype)
        .ok_or(ConfigValidationError::UnknownType(datatype.to_string()))?;
    match &entity.params {
        None => Ok(match_value(value, entity.r#type.to_owned(), None)?),
        Some(params_enum) => match params_enum {
            ParamsEnum::Unparsed(_) => Err(ConfigValidationError::UnparsedParameterTree),
            ParamsEnum::Parsed(params) => {
                Ok(match_value(value, entity.r#type.to_owned(), Some(params))?)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    use crate::config::data_structure::{
        AccessModifier, DatatypeEntity, DatatypeType, Param, TranslatableString,
    };

    #[test]
    fn test_validate_datatypes() {
        let datatypes: HashMap<String, DatatypeEntity> = HashMap::from([
            (
                "STRING".to_string(),
                DatatypeEntity {
                    r#type: DatatypeType::String,
                    display: TranslatableString::Key("Display".to_string()),
                    disabled: None,
                    order: None,
                    params: None,
                },
            ),
            (
                "NUMBER".to_string(),
                DatatypeEntity {
                    r#type: DatatypeType::Number,
                    disabled: None,
                    display: TranslatableString::Key("Display".to_string()),
                    order: None,
                    params: None,
                },
            ),
        ]);

        let string_and_number_are_fine =
            validate_datatypes(&[&"STRING".to_string(), &"NUMBER".to_string()], &datatypes);
        assert!(string_and_number_are_fine.is_ok());

        let but_undeclared_type_is_not = validate_datatypes(&[&"UNKNOWN".to_string()], &datatypes);
        assert!(but_undeclared_type_is_not.is_err());
    }

    #[test]
    fn test_validate_values_empty_params_always_ok() {
        let datatypes: HashMap<String, DatatypeEntity> = HashMap::from([(
            "STRING".to_string(),
            DatatypeEntity {
                r#type: DatatypeType::String,
                disabled: None,
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: None,
            },
        )]);

        let empty_value = validate_value("", "STRING", &datatypes);
        assert!(empty_value.is_ok());
    }

    #[test]
    fn test_validate_values_string_is_an_email() {
        let datatypes: HashMap<String, DatatypeEntity> = HashMap::from([
            (
                "EMAIL".to_string(),
                DatatypeEntity {
                    r#type: DatatypeType::String,
                    disabled: None,
                    display: TranslatableString::Key("Display".to_string()),
                    order: None,
                    params: Some(ParamsEnum::Parsed(DatatypeParams::String(
                        DatatypeStringParams {
                            autocomplete: None,
                            placeholder: None,
                            error: None,
                            pattern: Some(Param {
                                access: AccessModifier::Public,
                                value: "^[\\w\\-\\.]+@([\\w\\-]+\\.)+[\\w\\-]{2,4}$".to_string(),
                            }),
                        },
                    ))),
                },
            ),
            (
                "EMAIL_INVALID_REGEX".to_string(),
                DatatypeEntity {
                    r#type: DatatypeType::String,
                    disabled: None,
                    display: TranslatableString::Key("Display".to_string()),
                    order: None,
                    params: Some(ParamsEnum::Parsed(DatatypeParams::String(
                        DatatypeStringParams {
                            autocomplete: None,
                            placeholder: None,
                            error: None,
                            pattern: Some(Param {
                                access: AccessModifier::Public,
                                value: "^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$".to_string(),
                            }),
                        },
                    ))),
                },
            ),
        ]);

        let invalid_regex_pattern =
            validate_value("abc@abc.com", "EMAIL_INVALID_REGEX", &datatypes);
        assert!(invalid_regex_pattern.is_err_and(|e| matches!(
            e,
            ConfigValidationError::DatatypeValidationError(
                DatatypeValidationError::StringInvalidPattern(_)
            )
        )));

        let valid_email = validate_value("abc@abc.com", "EMAIL", &datatypes);
        assert!(valid_email.is_ok());

        let invalid_email = validate_value("not an email", "EMAIL", &datatypes);
        assert!(invalid_email.is_err_and(|e| matches!(
            e,
            ConfigValidationError::DatatypeValidationError(
                DatatypeValidationError::StringNotMatchingPattern(_, _)
            )
        )));
    }

    #[test]
    fn test_validate_values_number() {
        let datatypes: HashMap<String, DatatypeEntity> = HashMap::from([(
            "NUMBER".to_string(),
            DatatypeEntity {
                r#type: DatatypeType::Number,
                disabled: None,
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: Some(ParamsEnum::Parsed(DatatypeParams::Number(
                    DatatypeNumberParams {
                        min: Some(Param {
                            access: AccessModifier::Public,
                            value: 10.0,
                        }),
                        max: Some(Param {
                            access: AccessModifier::Public,
                            value: 15.0,
                        }),
                        error: None,
                    },
                ))),
            },
        )]);

        let parse_failure = validate_value("not_a_number", "NUMBER", &datatypes);
        assert!(parse_failure.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidationError(
                DatatypeValidationError::NumberParseFailure(_)
            )
        )));

        let too_small = validate_value("6", "NUMBER", &datatypes);
        assert!(too_small.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidationError(
                DatatypeValidationError::NumberTooSmall(_, _)
            )
        )));

        let too_big = validate_value("23", "NUMBER", &datatypes);
        assert!(too_big.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidationError(DatatypeValidationError::NumberTooBig(
                _,
                _
            ))
        )));

        let fine = validate_value("11", "NUMBER", &datatypes);
        assert!(fine.is_ok());
    }

    #[test]
    fn test_validate_values_date() {
        let datatypes: HashMap<String, DatatypeEntity> = HashMap::from([(
            "DATE".to_string(),
            DatatypeEntity {
                r#type: DatatypeType::Date,
                disabled: None,
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: Some(ParamsEnum::Parsed(DatatypeParams::Date(
                    DatatypeDateParams {
                        min: Some(Param {
                            access: AccessModifier::Public,
                            value: "2022-12-31".to_string(),
                        }),
                        max: Some(Param {
                            access: AccessModifier::Public,
                            value: "2023-01-02".to_string(),
                        }),
                        error: None,
                    },
                ))),
            },
        )]);

        let valid = validate_value("2023-01-01T17:45:00.0123456Z", "DATE", &datatypes);
        assert!(valid.is_ok());

        let too_early = validate_value("2022-01-01T17:45:00.0123456Z", "DATE", &datatypes);
        assert!(too_early.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidationError(DatatypeValidationError::DateTooEarly(
                _,
                _
            ))
        )));

        let too_late = validate_value("2023-01-02T17:45:00.0123456Z", "DATE", &datatypes);
        assert!(too_late.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidationError(DatatypeValidationError::DateTooLate(
                _,
                _
            ))
        )));

        let invalid = validate_value("2023-01-01", "DATE", &datatypes);
        assert!(invalid.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidationError(
                DatatypeValidationError::DateParseFailure(_)
            )
        )));
    }

    #[test]
    fn test_validate_values_enum() {
        let datatypes: HashMap<String, DatatypeEntity> = HashMap::from([(
            "COUNTRY".to_string(),
            DatatypeEntity {
                r#type: DatatypeType::Enum,
                disabled: None,
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: Some(ParamsEnum::Parsed(DatatypeParams::Enum(
                    DatatypeEnumParams {
                        values: Some(Param {
                            access: AccessModifier::Public,
                            value: vec![
                                EnumValue {
                                    key: "AA".to_string(),
                                    value: None,
                                    display: None,
                                },
                                EnumValue {
                                    key: "AB".to_string(),
                                    value: None,
                                    display: None,
                                },
                            ],
                        }),
                        error: None,
                    },
                ))),
            },
        )]);

        let enum_valid_value_one = validate_value("AA", "COUNTRY", &datatypes);
        assert!(enum_valid_value_one.is_ok());

        let enum_valid_value_two = validate_value("AB", "COUNTRY", &datatypes);
        assert!(enum_valid_value_two.is_ok());

        let invalid = validate_value("AC", "COUNTRY", &datatypes);
        assert!(invalid.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidationError(
                DatatypeValidationError::EnumInvalidValue(_)
            )
        )));
    }
}
