use std::num::{ParseFloatError, ParseIntError};

use serde::Deserialize;
use thiserror::Error;
use time::error::{ComponentRange, Parse, TryFromParsed};
use time::macros::format_description;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime};

use crate::config::core_config::{DatatypeConfig, DatatypeType};
use crate::config::ConfigValidationError;

#[derive(Debug, Error)]
pub enum DatatypeValidationError {
    // string
    #[error("String invalid pattern: `{0}`")]
    StringInvalidPattern(regex::Error),
    #[error("String params parsing: `{0}`")]
    StringParamsParsing(serde_json::Error),
    #[error("String `{0}` does not match pattern `{1}`")]
    StringNotMatchingPattern(String, String),

    // number
    #[error("Number params parsing: `{0}`")]
    NumberParamsParsing(serde_json::Error),
    #[error("Number parse failure: `{0}`")]
    NumberParseFailure(ParseFloatError),
    #[error("Number too small (`{0}` < `{1}`)")]
    NumberTooSmall(f64, f64),
    #[error("Number too big (`{0}` > `{1}`)")]
    NumberTooBig(f64, f64),

    // date
    #[error("Date parse failure: `{0}`")]
    DateParseFailure(time::error::Parse),
    #[error("Date params parsing: `{0}`")]
    DateParamsParsing(serde_json::Error),
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
    config: &DatatypeConfig,
) -> Result<(), ConfigValidationError> {
    for datatype in query_datatypes {
        _ = config.get_fields(datatype)?;
    }

    Ok(())
}

pub fn validate_datatype_value(
    value: &str,
    datatype: &str,
    config: &DatatypeConfig,
) -> Result<(), ConfigValidationError> {
    let fields = config.get_fields(datatype)?;

    match fields.r#type {
        DatatypeType::String => validate_string(value, config.get(datatype)?)?,
        DatatypeType::Number => validate_number(value, config.get(datatype)?)?,
        DatatypeType::Date => validate_date(value, config.get(datatype)?)?,
    };

    Ok(())
}

#[derive(Deserialize)]
struct StringParams {
    pattern: Option<String>,
}

fn validate_string(value: &str, params: StringParams) -> Result<(), DatatypeValidationError> {
    if let Some(pattern) = params.pattern {
        // this can be expensive if on the hot path
        let regex =
            regex::Regex::new(&pattern).map_err(DatatypeValidationError::StringInvalidPattern)?;

        if !regex.is_match_at(value, 0) {
            return Err(DatatypeValidationError::StringNotMatchingPattern(
                value.to_string(),
                pattern,
            ));
        }
    }

    Ok(())
}

#[derive(Deserialize)]
struct NumberParams {
    pub min: Option<f64>,
    pub max: Option<f64>,
}

fn validate_number(value: &str, params: NumberParams) -> Result<(), DatatypeValidationError> {
    let number: f64 = value
        .parse()
        .map_err(DatatypeValidationError::NumberParseFailure)?;

    match params.min {
        Some(min) if min > number => {
            return Err(DatatypeValidationError::NumberTooSmall(number, min))
        }
        _ => {}
    };

    match params.max {
        Some(max) if max < number => {
            return Err(DatatypeValidationError::NumberTooBig(number, max))
        }
        _ => {}
    };

    Ok(())
}

#[derive(Deserialize)]
struct DateParams {
    pub min: Option<String>,
    pub max: Option<String>,
}

fn validate_date(value: &str, params: DateParams) -> Result<(), DatatypeValidationError> {
    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    let date = match PrimitiveDateTime::parse(value, &format) {
        Ok(date) => Ok(date.assume_utc()),
        Err(error) => Err(DatatypeValidationError::DateParseFailure(error)),
    }?;

    if let Some(min) = &params.min {
        let min_date = parse_min_max_date(min)?;
        if date < min_date {
            return Err(DatatypeValidationError::DateTooEarly(
                value.to_string(),
                min.to_owned(),
            ));
        }
    }

    if let Some(max) = &params.max {
        let max_date = parse_min_max_date(max)?;
        if date > max_date {
            return Err(DatatypeValidationError::DateTooLate(
                value.to_string(),
                max.to_owned(),
            ));
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

#[cfg(test)]
mod tests {
    use indoc::{formatdoc, indoc};

    use super::*;

    #[test]
    fn test_validate_datatypes() {
        let datatype_config = indoc! {"
                STRING:
                    display: 'datatype.string'
                    type: 'STRING'
                    order: 100
                    params: null
                NUMBER:
                    display: 'datatype.number'
                    type: 'NUMBER'
                    order: 200
                    params: null
            "};
        let datatype_config: DatatypeConfig = serde_yaml::from_str(datatype_config).unwrap();

        let string_and_number_are_fine = validate_datatypes(
            &[&"STRING".to_string(), &"NUMBER".to_string()],
            &datatype_config,
        );
        assert!(string_and_number_are_fine.is_ok());

        let but_undeclared_type_is_not =
            validate_datatypes(&[&"UNKNOWN".to_string()], &datatype_config);
        assert!(but_undeclared_type_is_not.is_err());
    }

    #[test]
    fn test_validate_values_empty_params_always_ok() {
        let datatype_config = indoc! {"
                STRING:
                    display: 'datatype.string'
                    type: 'STRING'
                    order: 100
                    params: null
            "};
        let datatype_config: DatatypeConfig = serde_yaml::from_str(datatype_config).unwrap();

        let empty_value = validate_datatype_value("", "STRING", &datatype_config);
        assert!(empty_value.is_ok());
    }

    #[test]
    fn test_validate_values_string_is_an_email() {
        let valid_regex = "^[\\w\\-\\.]+@([\\w\\-]+\\.)+[\\w\\-]{2,4}$";
        let invalid_regex = "^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$";

        let datatype_config_with = |regex| {
            formatdoc! {"
                EMAIL:
                    display: 'datatype.email'
                    type: 'STRING'
                    order: 110
                    params:
                        public:
                            autocomplete: true 
                            placeholder: 'abc@abc.com' 
                            error: 
                                de: 'Please provide email like abc@abc.com'
                                en: 'Please provide email like abc@abc.com'
                            pattern: '{regex}'
            "}
        };

        let datatype_config: DatatypeConfig =
            serde_yaml::from_str(&datatype_config_with(invalid_regex)).unwrap();

        let invalid_regex_pattern =
            validate_datatype_value("abc@abc.com", "EMAIL", &datatype_config);
        assert!(invalid_regex_pattern.is_err_and(|e| matches!(
            e,
            ConfigValidationError::DatatypeValidation(
                DatatypeValidationError::StringInvalidPattern(_)
            )
        )));

        let datatype_config: DatatypeConfig =
            serde_yaml::from_str(&datatype_config_with(valid_regex)).unwrap();

        let valid_email = validate_datatype_value("abc@abc.com", "EMAIL", &datatype_config);
        assert!(valid_email.is_ok());

        let invalid_email = validate_datatype_value("not an email", "EMAIL", &datatype_config);
        assert!(invalid_email.is_err_and(|e| matches!(
            e,
            ConfigValidationError::DatatypeValidation(
                DatatypeValidationError::StringNotMatchingPattern(_, _)
            )
        )));
    }

    #[test]
    fn test_validate_values_number() {
        let datatype_config = indoc! {"
                NUMBER:
                    display: 'datatype.number'
                    type: 'NUMBER'
                    order: 200
                    params:
                        public:
                            min: 10.0 # optional
                            max: 15.0 # optional
        "};
        let datatype_config: DatatypeConfig = serde_yaml::from_str(datatype_config).unwrap();

        let parse_failure = validate_datatype_value("not_a_number", "NUMBER", &datatype_config);
        assert!(parse_failure.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidation(DatatypeValidationError::NumberParseFailure(
                _
            ))
        )));

        let too_small = validate_datatype_value("6", "NUMBER", &datatype_config);
        assert!(too_small.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidation(DatatypeValidationError::NumberTooSmall(
                _,
                _
            ))
        )));

        let too_big = validate_datatype_value("23", "NUMBER", &datatype_config);
        assert!(too_big.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidation(DatatypeValidationError::NumberTooBig(_, _))
        )));

        let fine = validate_datatype_value("11", "NUMBER", &datatype_config);
        assert!(fine.is_ok());
    }

    #[test]
    fn test_validate_values_date() {
        let datatype_config = indoc! {"
                DATE:
                    display: 'datatype.date'
                    type: 'DATE'
                    order: 300
                    params:
                        public:
                            min: '2022-12-31'
                            max: '2023-01-02'
        "};
        let datatype_config: DatatypeConfig = serde_yaml::from_str(datatype_config).unwrap();

        let valid =
            validate_datatype_value("2023-01-01T17:45:00.0123456Z", "DATE", &datatype_config);
        assert!(valid.is_ok());

        let too_early =
            validate_datatype_value("2022-01-01T17:45:00.0123456Z", "DATE", &datatype_config);
        assert!(too_early.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidation(DatatypeValidationError::DateTooEarly(_, _))
        )));

        let too_late =
            validate_datatype_value("2023-01-02T17:45:00.0123456Z", "DATE", &datatype_config);
        assert!(too_late.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidation(DatatypeValidationError::DateTooLate(_, _))
        )));

        let invalid = validate_datatype_value("2023-01-01", "DATE", &datatype_config);
        assert!(invalid.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidation(DatatypeValidationError::DateParseFailure(_))
        )));
    }
}
