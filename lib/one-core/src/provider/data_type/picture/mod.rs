use ct_codecs::{Base64, Encoder};
use mime::IMAGE_JPEG;
use serde::Deserialize;

use crate::config::validator::datatype::{base64_byte_length, validate_picture};
use crate::provider::data_type::DataType;
use crate::provider::data_type::error::DataTypeError;
use crate::provider::data_type::model::{
    CborType, DataTypeCapabilities, ExtractionResult, JsonType,
};
use crate::provider::data_type::picture_utils::{JPEG_HEADER, JPEG_SUFFIX, JPEG2000_HEADER};

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    accept: Option<Vec<String>>,
    file_size: Option<usize>,
}

pub struct PictureDataType {
    params: Params,
}

impl PictureDataType {
    pub fn new(params: Params) -> Self {
        Self { params }
    }

    fn determine_mdoc_image_mime_type(&self, value: &[u8]) -> Option<String> {
        if let Some(max_size) = self.params.file_size
            && value.len() > max_size
        {
            return None;
        }
        // check byte contents to not confuse them with fingerprints / other binary data
        let mime_type = if value.starts_with(JPEG_HEADER.as_slice())
            && value.ends_with(JPEG_SUFFIX.as_slice())
        {
            IMAGE_JPEG.essence_str()
        } else if value.starts_with(JPEG2000_HEADER.as_slice()) {
            "image/jp2"
        } else {
            return None;
        }
        .to_string();

        if let Some(accept) = &self.params.accept
            && !accept.contains(&mime_type)
        {
            // If the given mime type is not enabled for this provider, then this is not an applicable image.
            return None;
        }
        Some(mime_type)
    }

    fn extract_mdoc_image_from_array(&self, elements: &[ciborium::Value]) -> Option<String> {
        if elements.len() != 2 {
            return None;
        }
        let header = elements[0].as_text()?;
        let mime_type = header
            .strip_prefix("data:")
            .and_then(|h| h.strip_suffix(";base64"))?;
        if let Some(accept) = &self.params.accept
            && !accept.iter().any(|s| s == mime_type)
        {
            return None;
        }
        let data = String::from_utf8_lossy(elements[1].as_bytes()?);
        if let Some(max_size) = self.params.file_size
            && base64_byte_length(&data) > max_size
        {
            return None;
        }
        Some(format!("{header},{data}"))
    }
}

impl DataType for PictureDataType {
    fn extract_json_claim(
        &self,
        value: &serde_json::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        match value {
            serde_json::Value::String(value)
                if validate_picture(
                    value,
                    self.params.file_size,
                    self.params.accept.as_deref(),
                )
                .is_ok() =>
            {
                Ok(ExtractionResult::Value(value.clone()))
            }
            _ => Ok(ExtractionResult::NotApplicable),
        }
    }

    fn extract_cbor_claim(
        &self,
        value: &ciborium::Value,
    ) -> Result<ExtractionResult, DataTypeError> {
        match value {
            ciborium::Value::Bytes(bytes) => {
                let Some(mime_type) = self.determine_mdoc_image_mime_type(bytes) else {
                    return Ok(ExtractionResult::NotApplicable);
                };
                let value = Base64::encode_to_string(bytes).map_err(|err| {
                    DataTypeError::Failed(format!("failed to base64 encode image bytes: {err}"))
                })?;
                Ok(ExtractionResult::Value(format!(
                    "data:{mime_type};base64,{value}"
                )))
            }
            ciborium::Value::Array(elements) => {
                let Some(value) = self.extract_mdoc_image_from_array(elements) else {
                    return Ok(ExtractionResult::NotApplicable);
                };
                Ok(ExtractionResult::Value(value))
            }
            _ => Ok(ExtractionResult::NotApplicable),
        }
    }

    fn get_capabilities(&self) -> DataTypeCapabilities {
        DataTypeCapabilities {
            supported_json_types: vec![JsonType::String],
            supported_cbor_types: vec![CborType::Bytes, CborType::Array],
        }
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    // https://github.com/mathiasbynens/small/blob/master/jpeg.jpg
    const TEST_JPEG: [u8; 107] = hex!(
        "FFD8FFDB 00430003 02020202 02030202 02030303 03040604 04040404 08060605 0609080A 0A090809\
        090A0C0F 0C0A0B0E 0B09090D 110D0E0F 10101110 0A0C1213 1210130F 101010FF C9000B08 00010001\
        01011100 FFCC0006 00101005 FFDA0008 01010000 3F00D2CF 20FFD9"
    );
    const ENCODED_TEST_JPEG: &str = "data:image/jpeg;base64,/9j/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k=";

    // https://github.com/mathiasbynens/small/blob/master/jpeg2.jp2
    const TEST_JPEG_2000: [u8; 212] = hex!(
        "0000000C 6A502020 0D0A870A 00000014 66747970 6A703220 00000000 6A703220 0000002D 6A703268\
        00000016 69686472 00000001 00000001 00030707 00000000 000F636F 6C720100 00000000 10000000\
        006A7032 63FF4FFF 51002F00 00000000 01000000 01000000 00000000 00000000 01000000 01000000\
        00000000 00000307 01010701 01070101 FF5C000D 40404848 50484850 484850FF 52000C00 00000101\
        03040400 01FF6400 0E00014C 545F4A50 325F3232 30FF9000 0A000000 00001D00 01FF93DF 80080780\
        80808080 80808080 8080FFD9"
    );
    const ENCODED_TEST_JPEG_2000: &str = "data:image/jp2;base64,AAAADGpQICANCocKAAAAFGZ0eXBqcDIgAAAAAGpwMiAAAAAtanAyaAAAABZpaGRyAAAAAQAAAAEAAwcHAAAAAAAPY29scgEAAAAAABAAAAAAanAyY/9P/1EALwAAAAAAAQAAAAEAAAAAAAAAAAAAAAEAAAABAAAAAAAAAAAAAwcBAQcBAQcBAf9cAA1AQEhIUEhIUEhIUP9SAAwAAAABAQMEBAAB/2QADgABTFRfSlAyXzIyMP+QAAoAAAAAAB0AAf+T34AIB4CAgICAgICAgICA/9k=";

    #[test]
    fn extract_json_jpeg() {
        let provider = PictureDataType::new(Params {
            accept: None,
            file_size: None,
        });

        let result = provider.extract_json_claim(&json!("not matching")).unwrap();
        assert_eq!(result, ExtractionResult::NotApplicable);

        let result = provider
            .extract_json_claim(&json!(ENCODED_TEST_JPEG.to_string()))
            .unwrap();
        assert_eq!(
            result,
            ExtractionResult::Value(ENCODED_TEST_JPEG.to_string())
        );
    }

    #[test]
    fn extract_cbor_bytes() {
        let provider = PictureDataType::new(Params {
            accept: None,
            file_size: None,
        });

        let result = provider
            .extract_cbor_claim(&ciborium::Value::Bytes(TEST_JPEG.to_vec()))
            .unwrap();
        assert_eq!(
            result,
            ExtractionResult::Value(ENCODED_TEST_JPEG.to_string())
        );
    }

    #[test]
    fn extract_cbor_bytes_jp2() {
        let provider = PictureDataType::new(Params {
            accept: None,
            file_size: None,
        });

        let result = provider
            .extract_cbor_claim(&ciborium::Value::Bytes(TEST_JPEG_2000.to_vec()))
            .unwrap();
        assert_eq!(
            result,
            ExtractionResult::Value(ENCODED_TEST_JPEG_2000.to_string())
        );
    }

    #[test]
    fn extract_cbor_array() {
        let provider = PictureDataType::new(Params {
            accept: None,
            file_size: None,
        });

        let result = provider
            .extract_cbor_claim(&ciborium::Value::Array(vec![ciborium::Value::Text("data:image/jpeg;base64".to_string()), ciborium::Value::Bytes("/9j/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k=".as_bytes().to_vec())]))
            .unwrap();
        assert_eq!(
            result,
            ExtractionResult::Value(ENCODED_TEST_JPEG.to_string())
        );
    }

    #[test]
    fn extract_cbor_array_file_too_big() {
        let provider = PictureDataType::new(Params {
            accept: None,
            file_size: Some(106),
        });

        let result = provider
            .extract_cbor_claim(&ciborium::Value::Array(vec![ciborium::Value::Text("data:image/jpeg;base64".to_string()), ciborium::Value::Bytes("/9j/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k=".as_bytes().to_vec())]))
            .unwrap();
        assert_eq!(result, ExtractionResult::NotApplicable);
    }

    #[test]
    fn extract_cbor_bytes_jpeg_disabled() {
        let provider = PictureDataType::new(Params {
            accept: Some(vec!["image/png".to_string()]),
            file_size: None,
        });

        let result = provider
            .extract_cbor_claim(&ciborium::Value::Bytes(TEST_JPEG.to_vec()))
            .unwrap();
        assert_eq!(result, ExtractionResult::NotApplicable);
    }

    #[test]
    fn extract_cbor_bytes_file_too_big() {
        let provider = PictureDataType::new(Params {
            accept: None,
            file_size: Some(106),
        });

        let result = provider
            .extract_cbor_claim(&ciborium::Value::Bytes(TEST_JPEG.to_vec()))
            .unwrap();
        assert_eq!(result, ExtractionResult::NotApplicable);
    }
}
