use ct_codecs::{Base64, Decoder};
use mime::{IMAGE_JPEG, IMAGE_PNG};
use serde::Deserialize;

use crate::config::ConfigValidationError;
use crate::config::validator::datatype::{DatatypeValidationError, base64_byte_length};
use crate::provider::data_type::DataType;
use crate::provider::data_type::error::DataTypeError;
use crate::provider::data_type::model::{DataTypeCapabilities, ExtractionResult, JsonType};
use crate::provider::data_type::picture_utils::{JPEG_HEADER, JPEG_SUFFIX, PNG_HEADER};

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    accept: Option<Vec<String>>,
    file_size: Option<usize>,
}

pub struct SwiyuPictureDataType {
    params: Params,
}

impl SwiyuPictureDataType {
    pub fn new(params: Params) -> Result<Self, ConfigValidationError> {
        if let Some(accept) = &params.accept {
            for mime_type in accept.iter() {
                if mime_type != IMAGE_JPEG.essence_str() && mime_type != IMAGE_PNG.essence_str() {
                    return Err(DatatypeValidationError::FileUnsupportedMediaType(
                        mime_type.to_string(),
                    )
                    .into());
                }
            }
        }
        Ok(Self { params })
    }

    fn valid_swiyu_picture(&self, value: &str) -> Option<String> {
        if let Some(max_size) = self.params.file_size
            && base64_byte_length(value) > max_size
        {
            return None;
        }
        let Ok(data) = Base64::decode_to_vec(value, None) else {
            return None;
        };
        if data.starts_with(JPEG_HEADER.as_slice()) && data.ends_with(JPEG_SUFFIX.as_slice()) {
            return Some("image/jpeg".to_string());
        }
        if data.starts_with(PNG_HEADER.as_slice()) {
            return Some("image/png".to_string());
        }
        None
    }
}

impl DataType for SwiyuPictureDataType {
    fn extract_json_claim(
        &self,
        value: &serde_json::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        let serde_json::Value::String(value) = value else {
            return Ok(ExtractionResult::NotApplicable);
        };
        let Some(mime_type) = self.valid_swiyu_picture(value) else {
            return Ok(ExtractionResult::NotApplicable);
        };
        Ok(ExtractionResult::Value(format!(
            "data:{mime_type};base64,{value}"
        )))
    }

    fn extract_cbor_claim(
        &self,
        _value: &ciborium::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        Ok(ExtractionResult::NotApplicable)
    }

    fn get_capabilities(&self) -> DataTypeCapabilities {
        DataTypeCapabilities {
            supported_json_types: vec![JsonType::String],
            supported_cbor_types: vec![],
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    // https://github.com/mathiasbynens/small/blob/master/jpeg.jpg
    const BASE64_DATA: &str = "/9j/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k=";
    const FULL_DATA_URL: &str = "data:image/jpeg;base64,/9j/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k=";

    #[test]
    fn extract_json_jpeg() {
        let provider = SwiyuPictureDataType::new(Params {
            accept: None,
            file_size: None,
        })
        .unwrap();

        let result = provider.extract_json_claim(&json!("not matching")).unwrap();
        assert_eq!(result, ExtractionResult::NotApplicable);

        let result = provider
            .extract_json_claim(&json!(BASE64_DATA.to_string()))
            .unwrap();
        assert_eq!(result, ExtractionResult::Value(FULL_DATA_URL.to_string()));
    }
}
