use ciborium::cbor;
use coset::CborSerializable;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde::{Deserialize, Serialize, Serializer, de, ser};
use url::Url;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::util::Bstr;

/// ISO/IEC 18013-7:2025, C.5
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DcApiHandover {
    dcapi_info_hash: Bstr,
}

impl DcApiHandover {
    #[expect(unused)]
    pub(crate) fn compute(
        origin: &str,
        base64_encryption_info: &str,
    ) -> Result<Self, FormatterError> {
        let serialized_origin = serialized_origin(origin)?;
        let dcapi_info = cbor!([base64_encryption_info, serialized_origin])?.to_vec()?;

        let dcapi_info_hash = Bstr(SHA256.hash(&dcapi_info)?);
        Ok(Self { dcapi_info_hash })
    }
}

fn serialized_origin(origin: &str) -> Result<String, FormatterError> {
    // android app-to-app requests
    if origin.starts_with("android:") {
        return Ok(origin.to_string());
    }

    let origin = Url::parse(origin)?;

    let mut serialized = format!(
        "{}://{}",
        origin.scheme(),
        origin
            .host_str()
            .ok_or(FormatterError::CouldNotExtractPresentation(format!(
                "Missing host: {origin}"
            )))?
    );

    if let Some(port) = origin.port() {
        serialized += format!(":{port}").as_str();
    }

    Ok(serialized)
}

impl Serialize for DcApiHandover {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!(["dcapi", self.dcapi_info_hash])
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for DcApiHandover {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'a>,
    {
        let (fixed_id, dcapi_info_hash): (String, Bstr) =
            ciborium::Value::deserialize(deserializer)?
                .deserialized()
                .map_err(de::Error::custom)?;

        if fixed_id != "dcapi" {
            return Err(de::Error::custom(format!(
                "Invalid leading identifier: {fixed_id}"
            )));
        }

        Ok(Self { dcapi_info_hash })
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::serialized_origin;

    #[rstest::rstest]
    #[case::android_app_request_origin(
        "android:apk-key-hash:uU0nuZNNPgilLlLX2n2r-sSE7-N6U4DukIj3rOLvzek"
    )]
    #[case::plain_url("http://some.domain")]
    #[case::url_with_port("http://some.domain:8080")]
    #[test]
    fn test_serialized_origin_already_serialized(#[case] origin: &str) {
        assert_eq!(serialized_origin(origin).unwrap(), origin);
    }

    #[rstest::rstest]
    #[case::with_trailing_slash(("http://some.domain/", "http://some.domain"))]
    #[case::with_path(("http://some.domain/path", "http://some.domain"))]
    #[case::with_query(("http://some.domain/?query=x", "http://some.domain"))]
    #[test]
    fn test_serialized_origin_not_serialized(#[case] (origin, expected_result): (&str, &str)) {
        assert_eq!(serialized_origin(origin).unwrap(), expected_result);
    }
}
