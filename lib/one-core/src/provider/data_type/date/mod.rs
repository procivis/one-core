use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::{Date, OffsetDateTime};

use crate::config::ConfigValidationError;
use crate::config::validator::datatype::{DATE_FORMAT, parse_min_max_datetime};
use crate::provider::credential_formatter::mdoc_formatter::{FULL_DATE_TAG, TDATE_TAG};
use crate::provider::data_type::DataType;
use crate::provider::data_type::error::DataTypeError;
use crate::provider::data_type::model::{
    CborType, DataTypeCapabilities, ExtractionResult, JsonType,
};

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub formats: Vec<DateFormat>,
    pub min: Option<String>,
    pub max: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DateFormat {
    Date,
    Datetime,
}

pub struct DateDataType {
    pub min: Option<OffsetDateTime>,
    pub max: Option<OffsetDateTime>,
    pub formats: Vec<DateFormat>,
}

impl DateDataType {
    pub fn new(params: Params) -> Result<Self, ConfigValidationError> {
        let min = params
            .min
            .as_ref()
            .map(|v| parse_min_max_datetime(v))
            .transpose()?;
        let max = params
            .max
            .as_ref()
            .map(|v| parse_min_max_datetime(v))
            .transpose()?;
        Ok(Self {
            min,
            max,
            formats: params.formats,
        })
    }

    fn is_valid_date(&self, value: &str) -> bool {
        for format in self.formats.iter() {
            let parsed_date = match format {
                DateFormat::Date => {
                    let Ok(date) = Date::parse(value, DATE_FORMAT) else {
                        continue;
                    };
                    date.midnight().assume_utc()
                }
                DateFormat::Datetime => {
                    let Ok(datetime) = OffsetDateTime::parse(value, &Rfc3339) else {
                        continue;
                    };
                    datetime
                }
            };
            if let Some(min) = &self.min
                && parsed_date < *min
            {
                return false;
            }
            if let Some(max) = &self.max
                && parsed_date > *max
            {
                return false;
            }
            return true;
        }
        false
    }
}

impl DataType for DateDataType {
    fn extract_json_claim(
        &self,
        value: &serde_json::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        match value {
            serde_json::Value::String(value) if self.is_valid_date(value) => {
                // Reflect back the
                Ok(ExtractionResult::Value(value.clone()))
            }
            _ => Ok(ExtractionResult::NotApplicable),
        }
    }

    fn extract_cbor_claim(
        &self,
        value: &ciborium::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        let text = match value {
            ciborium::Value::Tag(tag, val) if *tag == TDATE_TAG || *tag == FULL_DATE_TAG => {
                val.as_text().ok_or(DataTypeError::UnexpectedValue(format!(
                    "Expected text data for tagged element with tag `{tag}`."
                )))?
            }
            _ => return Ok(ExtractionResult::NotApplicable),
        };
        if self.is_valid_date(text) {
            Ok(ExtractionResult::Value(text.to_string()))
        } else {
            Ok(ExtractionResult::NotApplicable)
        }
    }

    fn get_capabilities(&self) -> DataTypeCapabilities {
        DataTypeCapabilities {
            supported_json_types: vec![JsonType::String],
            supported_cbor_types: vec![CborType::TDate, CborType::FullDate],
        }
    }
}
