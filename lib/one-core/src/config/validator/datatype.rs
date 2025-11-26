use std::num::{ParseFloatError, ParseIntError};
use std::str::ParseBoolError;

use serde::Deserialize;
use thiserror::Error;
use time::format_description::FormatItem;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};

use crate::config::ConfigValidationError;
use crate::config::core_config::{ConfigExt, DatatypeConfig, DatatypeType};

pub(crate) const DATE_FORMAT: &[FormatItem<'_>] = format_description!("[year]-[month]-[day]");

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

    // boolean
    #[error("Boolean parse failure: `{0}`")]
    BooleanParseFailure(ParseBoolError),

    // date
    #[error("Date parse failure: `{0}`")]
    DateParseFailure(#[from] time::error::Parse),
    #[error("Date params: `{0}`")]
    DateParams(#[from] DateParamsError),
    #[error("Date too early: `{0}` < `{1}`")]
    DateTooEarly(String, String),
    #[error("Date too late: `{0}` > `{1}`")]
    DateTooLate(String, String),

    // file
    #[error("File parse missing schema")]
    FileParseMissingScheme,
    #[error("File parse incorrect schema: `{0}`")]
    FileParseIncorrectSchema(String),
    #[error("File parse missing media part")]
    FileParseMissingMediaPart,
    #[error("File parse missing data part")]
    FileParseMissingDataPart,
    #[error("File parse no media type")]
    FileParseNoMediaType,
    #[error("File unsupported media type: `{0}`")]
    FileUnsupportedMediaType(String),
    #[error("File parse base64 supported only")]
    FileParseNoBase64,
    #[error("File too long")]
    FileTooLong,

    // enum
    #[error("Enum invalid value: `{0}`")]
    EnumInvalidValue(String),

    // object
    #[error("Object value should not be specified in request")]
    ObjectValueShouldNotBeSpecifiedInRequest,

    // array
    #[error("Array value should not be specified in request")]
    ArrayValueShouldNotBeSpecifiedInRequest,
    #[error("Index parse failure: `{0}`")]
    IndexParseFailure(ParseIntError),

    // general
    #[error("Path `{0}` doesn't match claim schema key `{1}`")]
    PathDoesntMatchClaimSchemaKey(String, String),
}

#[derive(Debug, Error)]
pub enum DateParamsError {
    #[error("At least one format must be provided")]
    MissingFormats,
    #[error("The preferred format must be defined inside the formats list")]
    PreferredFormatNotAllowed,
}

pub fn validate_datatypes<'a>(
    query_datatypes: impl Iterator<Item = &'a str>,
    config: &DatatypeConfig,
) -> Result<(), ConfigValidationError> {
    for datatype in query_datatypes {
        config.get_if_enabled(datatype)?;
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
        DatatypeType::SwiyuPicture | DatatypeType::Picture => {
            let params: FileParams = config.get(datatype)?;
            validate_picture(value, params.file_size, params.accept.as_deref())?
        }
        DatatypeType::Object => validate_object(value, config.get(datatype)?)?,
        DatatypeType::Array => validate_array(value, config.get(datatype)?)?,
        DatatypeType::Boolean => validate_boolean(value, config.get(datatype)?)?,
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
#[serde(rename_all = "camelCase")]
struct BooleanParams {}

fn validate_boolean(value: &str, _params: BooleanParams) -> Result<(), DatatypeValidationError> {
    let _: bool = value
        .parse()
        .map_err(DatatypeValidationError::BooleanParseFailure)?;

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
            return Err(DatatypeValidationError::NumberTooSmall(number, min));
        }
        _ => {}
    };

    match params.max {
        Some(max) if max < number => {
            return Err(DatatypeValidationError::NumberTooBig(number, max));
        }
        _ => {}
    };

    Ok(())
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum DateFormat {
    Date,
    Datetime,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DateParams {
    pub formats: Vec<DateFormat>,
    pub preferred_format: Option<DateFormat>,
    pub min: Option<String>,
    pub max: Option<String>,
}

fn validate_date(value: &str, params: DateParams) -> Result<(), DatatypeValidationError> {
    validate_date_params(&params)?;

    let (valid, mut errors): (Vec<_>, Vec<_>) = params
        .formats
        .iter()
        .map(|format| match format {
            DateFormat::Date => {
                let date = Date::parse(value, DATE_FORMAT)?;

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
            DateFormat::Datetime => {
                let datetime = OffsetDateTime::parse(value, &Rfc3339)?;
                if let Some(min) = &params.min {
                    let min_date = parse_min_max_datetime(min)?;
                    if datetime < min_date {
                        return Err(DatatypeValidationError::DateTooEarly(
                            value.to_string(),
                            min.to_owned(),
                        ));
                    }
                }

                if let Some(max) = &params.max {
                    let max_date = parse_min_max_datetime(max)?;
                    if datetime > max_date {
                        return Err(DatatypeValidationError::DateTooLate(
                            value.to_string(),
                            max.to_owned(),
                        ));
                    }
                }

                Ok(())
            }
        })
        .partition(|r| r.is_ok());

    if valid.is_empty()
        && let Some(last_error) = errors.pop()
    {
        return last_error;
    }

    Ok(())
}

fn validate_date_params(params: &DateParams) -> Result<(), DateParamsError> {
    if params.formats.is_empty() {
        return Err(DateParamsError::MissingFormats);
    }

    if params
        .preferred_format
        .as_ref()
        .is_some_and(|f| !params.formats.contains(f))
    {
        return Err(DateParamsError::PreferredFormatNotAllowed);
    }

    Ok(())
}

#[expect(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileParams {
    pub accept: Option<Vec<String>>,
    pub file_size: Option<usize>,
    pub show_as: Option<String>,
    pub encode_as_mdl_portrait: Option<bool>,
}

pub(crate) fn validate_picture(
    value: &str,
    max_size: Option<usize>,
    accept: Option<&[String]>,
) -> Result<(), DatatypeValidationError> {
    let mut parts = value.split(',');

    let media_part = parts
        .next()
        .ok_or(DatatypeValidationError::FileParseMissingMediaPart)?;

    if !media_part.starts_with("data:") {
        let scheme = media_part
            .split(':')
            .next()
            .ok_or(DatatypeValidationError::FileParseMissingScheme)?;

        return Err(DatatypeValidationError::FileParseIncorrectSchema(
            scheme.to_owned(),
        ));
    }

    let content_type = media_part.trim_start_matches("data:");

    if !content_type.contains("base64") {
        return Err(DatatypeValidationError::FileParseNoBase64);
    }

    // Default policy; Accept all if not provided
    if let Some(accept) = accept {
        let media_type = content_type
            .split(';')
            .next()
            .ok_or(DatatypeValidationError::FileParseNoMediaType)?
            .to_owned();

        if !accept.contains(&media_type) {
            return Err(DatatypeValidationError::FileUnsupportedMediaType(
                media_type,
            ));
        }
    }

    let data_part = parts
        .next()
        .ok_or(DatatypeValidationError::FileParseMissingDataPart)?;

    // Default policy; Accept all if not provided
    if let Some(max_file_size) = max_size
        && base64_byte_length(data_part) > max_file_size
    {
        return Err(DatatypeValidationError::FileTooLong);
    }

    Ok(())
}

pub(crate) fn base64_byte_length(data: &str) -> usize {
    let num_bytes = if data.ends_with("==") {
        2
    } else if data.ends_with('=') {
        1
    } else {
        0
    };
    (data.len() * 3 / 4) - num_bytes
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ObjectParams {}

fn validate_object(_value: &str, _params: ObjectParams) -> Result<(), DatatypeValidationError> {
    Err(DatatypeValidationError::ObjectValueShouldNotBeSpecifiedInRequest)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArrayParams {}

fn validate_array(_value: &str, _params: ArrayParams) -> Result<(), DatatypeValidationError> {
    Err(DatatypeValidationError::ArrayValueShouldNotBeSpecifiedInRequest)
}

pub fn parse_min_max_date(value: &str) -> Result<Date, DatatypeValidationError> {
    if value == "NOW" {
        return Ok(OffsetDateTime::now_utc().date());
    }

    Ok(Date::parse(value, DATE_FORMAT)?)
}

pub(crate) fn parse_min_max_datetime(
    value: &str,
) -> Result<OffsetDateTime, DatatypeValidationError> {
    if value == "NOW" {
        return Ok(OffsetDateTime::now_utc());
    }

    if let Ok(date) = Date::parse(value, DATE_FORMAT) {
        return Ok(date.midnight().assume_utc());
    }

    Ok(OffsetDateTime::parse(value, &Rfc3339)?)
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

        let string_and_number_are_fine =
            validate_datatypes(["STRING", "NUMBER"].into_iter(), &datatype_config);
        assert!(string_and_number_are_fine.is_ok());

        let but_undeclared_type_is_not =
            validate_datatypes(["UNKNOWN"].into_iter(), &datatype_config);
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
    fn test_date_validation_single_format() {
        let datatype_config = indoc! {"
                DATE:
                    display: 'datatype.date'
                    type: 'DATE'
                    order: 300
                    params:
                        public:
                            formats: ['date']
                            min: '2022-12-31'
                            max: '2023-01-02'
        "};
        let datatype_config: DatatypeConfig = serde_yaml::from_str(datatype_config).unwrap();

        assert!(validate_datatype_value("2023-01-01", "DATE", &datatype_config).is_ok());

        let too_early = validate_datatype_value("2022-01-01", "DATE", &datatype_config);
        assert2::assert!(let Err(ConfigValidationError::DatatypeValidation(DatatypeValidationError::DateTooEarly(_, _))) = too_early);

        let too_late = validate_datatype_value("2023-01-03", "DATE", &datatype_config);
        assert2::assert!(let Err(ConfigValidationError::DatatypeValidation(DatatypeValidationError::DateTooLate(_, _))) = too_late);

        assert2::assert!(
            let Err( ConfigValidationError::DatatypeValidation(DatatypeValidationError::DateParseFailure(_))) =
            validate_datatype_value("2023-01-01T17:45:00.0123456Z", "DATE", &datatype_config)
        );
    }

    #[test]
    fn test_date_validation_multiple_formats() {
        let datatype_config = indoc! {"
                DATE:
                    display: 'datatype.date'
                    type: 'DATE'
                    order: 300
                    params:
                        public:
                            formats: ['date', 'datetime']
        "};
        let datatype_config: DatatypeConfig = serde_yaml::from_str(datatype_config).unwrap();

        assert!(validate_datatype_value("2023-01-01", "DATE", &datatype_config).is_ok());
        assert!(
            validate_datatype_value("2023-01-01T17:45:00.0123456Z", "DATE", &datatype_config)
                .is_ok()
        );
    }

    #[test]
    fn test_date_params_preferred_format_must_be_in_formats() {
        let datatype_config = indoc! {"
                DATE:
                    display: 'datatype.date'
                    type: 'DATE'
                    order: 300
                    params:
                        public:
                            formats: ['datetime']
                            preferredFormat: 'date'
        "};
        let datatype_config: DatatypeConfig = serde_yaml::from_str(datatype_config).unwrap();

        assert2::assert!(
            let Err( ConfigValidationError::DatatypeValidation(DatatypeValidationError::DateParams(
                DateParamsError::PreferredFormatNotAllowed
            ))) =
            validate_datatype_value("2023-01-01T17:45:00.0123456Z", "DATE", &datatype_config)
        );
    }

    #[test]
    fn test_date_params_formats_must_be_non_empty() {
        let datatype_config = indoc! {"
                    DATE:
                        display: 'datatype.date'
                        type: 'DATE'
                        order: 300
                        params:
                            public:
                                formats: []
            "};
        let datatype_config: DatatypeConfig = serde_yaml::from_str(datatype_config).unwrap();

        assert2::assert!(
            let Err( ConfigValidationError::DatatypeValidation(DatatypeValidationError::DateParams(
                DateParamsError::MissingFormats
            ))) =
            validate_datatype_value("2023-01-01T17:45:00.0123456Z", "DATE", &datatype_config)
        );
    }

    #[test]
    fn test_validate_values_image() {
        let datatype_config = indoc! {r#"
        PICTURE:
            display: "datatype.picture"
            type: "PICTURE"
            order: 400
            params:
                public:
                    accept:
                        - image/jpeg
                        - image/png
                    fileSize: 20
                    showAs: IMAGE
        "#};

        let datatype_config: DatatypeConfig = serde_yaml::from_str(datatype_config).unwrap();

        let valid = validate_datatype_value(
            "data:image/png;base64,dGVzdGNvbnRlbnQ=",
            "PICTURE",
            &datatype_config,
        );

        assert!(valid.is_ok());

        let invalid = validate_datatype_value(
            "data:image/svg+xml;base64,dGVzdGNvbnRlbnQ=",
            "PICTURE",
            &datatype_config,
        );
        assert!(invalid.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidation(
                DatatypeValidationError::FileUnsupportedMediaType(_)
            )
        )));

        let invalid = validate_datatype_value(
            "data:image/png,dGVzdGNvbnRlbnQ=",
            "PICTURE",
            &datatype_config,
        );
        assert!(invalid.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidation(DatatypeValidationError::FileParseNoBase64)
        )));

        let valid_size = validate_datatype_value(
            "data:image/png;base64,dGVzdHRoYXRpc3Rvb29vb2xvbmc=", //20 bytes
            "PICTURE",
            &datatype_config,
        );
        assert!(valid_size.is_ok());

        let invalid_size = validate_datatype_value(
            "data:image/png;base64,dGVzdHRoYXRpc3Rvb29vb29sb25n", //21 bytes
            "PICTURE",
            &datatype_config,
        );
        assert!(invalid_size.is_err_and(|f| matches!(
            f,
            ConfigValidationError::DatatypeValidation(DatatypeValidationError::FileTooLong)
        )));
    }

    #[test]
    fn test_validate_values_file() {
        let datatype_config = indoc! {r#"
        PICTURE:
            display: "datatype.file"
            type: "PICTURE"
            order: 400
            params: null
        "#};

        let datatype_config: DatatypeConfig = serde_yaml::from_str(datatype_config).unwrap();

        let valid = validate_datatype_value(
            "data:image/png;base64,dGVzdGNvbnRlbnQ=",
            "PICTURE",
            &datatype_config,
        );
        assert!(valid.is_ok());

        let valid = validate_datatype_value(
            "data:image/jpeg;base64,dGVzdGNvbnRlbnQ=",
            "PICTURE",
            &datatype_config,
        );
        assert!(valid.is_ok());
    }
}
