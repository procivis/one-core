use indexmap::IndexMap;

use super::model::PublishedClaimValue;
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::der_chain_into_pem_chain;
use crate::proto::http_client::HttpClient;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::util::Bstr;
use crate::provider::credential_formatter::model::PublishedClaim;
use crate::service::credential::dto::{
    DetailCredentialClaimResponseDTO, DetailCredentialClaimValueResponseDTO,
};

/// Resolves the certificate (chain) referenced by the `x5u` header parameter
/// (IETF RFC 7515 clause 4.1.5 for JOSE, IETF RFC 9360 for COSE). ETSI TS 119 472-1
/// requires QEAA/PuB-EAA to make their signing certificate available this way
/// (QEAA-5.6.2-02, QEAA-6.6.2-02).
///
/// # Returns
/// The referenced resource as a PEM-encoded certificate chain, leaf first.
pub async fn resolve_x5u(
    url: &str,
    http_client: &dyn HttpClient,
) -> Result<String, FormatterError> {
    let response = async {
        http_client
            .get(url)
            .header(
                "Accept",
                "application/pem-certificate-chain, application/x-pem-file, application/cose-x509",
            )
            .send()
            .await?
            .error_for_status()
    }
    .await
    .error_while("fetching x5u certificate")?;

    let content_type = response.header_get("content-type");
    match content_type {
        Some(content_type) if content_type.contains("application/cose-x509") => {
            let cbor: Vec<Bstr> = ciborium::from_reader(response.body.as_slice())?;
            let der_chain = cbor.into_iter().map(|bstr| bstr.0).collect();
            return Ok(der_chain_into_pem_chain(der_chain));
        }
        Some(content_type)
            if content_type.contains("application/pem-certificate-chain")
                || content_type.contains("application/x-pem-file") =>
        {
            // recognized PEM chain - proceed
        }
        Some(unknown_content_type) => {
            tracing::warn!("x5u: unknown Content-Type provided: `{unknown_content_type}`");
            // try fallback to PEM
        }
        None => {
            tracing::warn!("x5u: no Content-Type provided");
            // try fallback to PEM
        }
    };

    String::from_utf8(response.body).map_err(|e| {
        FormatterError::CouldNotExtractCredentials(format!("x5u response is not valid PEM: {e}"))
    })
}

pub fn nest_claims(
    claims: impl IntoIterator<Item = PublishedClaim>,
) -> Result<IndexMap<String, serde_json::Value>, FormatterError> {
    let mut data = serde_json::Value::Object(Default::default());

    let mut claims = claims.into_iter().collect::<Vec<PublishedClaim>>();
    // numeric-aware ordering so array indices assign in order (1, 2, ..., 10 instead of 1, 10, 2)
    claims.sort_unstable_by(|a, b| human_sort::compare(&a.key, &b.key));

    for claim in claims {
        let path = format!("/{}", json_pointer_escape(&claim.key));
        let pointer = jsonptr::Pointer::parse(&path)?;
        let value: serde_json::Value = claim.value.try_into()?;
        pointer.assign(&mut data, value)?;
    }

    Ok(data
        .as_object()
        .ok_or(FormatterError::JsonMapping(
            "data is not an Object".to_string(),
        ))?
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect())
}

/// Escape paths based on <https://datatracker.ietf.org/doc/html/rfc6901#section-3>
/// except forward slash `/`, as that is used internally
fn json_pointer_escape(input: &str) -> String {
    input.replace("~", "~0")
}

pub(super) fn map_claims(
    claims: &[DetailCredentialClaimResponseDTO],
    array_item: bool,
) -> Vec<PublishedClaim> {
    let mut result = vec![];

    for claim in claims {
        let published_claim_value = match &claim.value {
            DetailCredentialClaimValueResponseDTO::Nested(value) => {
                result.extend(map_claims(value, claim.schema.array));
                None
            }
            DetailCredentialClaimValueResponseDTO::String(value) => {
                Some(PublishedClaimValue::String(value.to_owned()))
            }
            DetailCredentialClaimValueResponseDTO::Boolean(value) => {
                Some(PublishedClaimValue::Bool(value.to_owned()))
            }
            DetailCredentialClaimValueResponseDTO::Float(value) => {
                Some(PublishedClaimValue::Float(value.to_owned()))
            }
            DetailCredentialClaimValueResponseDTO::Integer(value) => {
                Some(PublishedClaimValue::Integer(value.to_owned()))
            }
        };

        let key = claim.path.clone();

        if let Some(value) = published_claim_value {
            result.push(PublishedClaim {
                key,
                value,
                datatype: Some(claim.schema.datatype.clone()),
                array_item,
            });
        }
    }

    result
}

#[cfg(test)]
#[derive(Clone)]
pub struct MockAuth<F: Fn(&[u8]) -> Vec<u8> + Send + Sync>(pub F);

#[cfg(test)]
pub use crate::config::core_config::KeyAlgorithmType;
#[cfg(test)]
pub use crate::provider::credential_formatter::model::SignatureProvider;
#[cfg(test)]
pub use crate::provider::key_algorithm::error::KeyAlgorithmError;

#[cfg(test)]
#[async_trait::async_trait]
impl<F: Fn(&[u8]) -> Vec<u8> + Send + Sync> SignatureProvider for MockAuth<F> {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        Ok(self.0(message))
    }

    fn get_key_id(&self) -> Option<String> {
        Some("#key0".to_owned())
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, KeyAlgorithmError> {
        Ok(KeyAlgorithmType::Ecdsa)
    }

    fn jose_alg(&self) -> Result<String, KeyAlgorithmError> {
        Ok("ES256".to_owned())
    }

    fn get_public_key(&self) -> Vec<u8> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_format_nested_vc_jwt() {
        let claims = vec![
            PublishedClaim {
                key: "name".into(),
                value: "John".into(),
                datatype: None,
                array_item: false,
            },
            PublishedClaim {
                key: "location/x".into(),
                value: "1".into(),
                datatype: None,
                array_item: false,
            },
            PublishedClaim {
                key: "location/y".into(),
                value: "2".into(),
                datatype: None,
                array_item: false,
            },
        ];
        let expected = IndexMap::from([
            (
                "location".to_string(),
                json!({
                  "x": "1",
                  "y": "2"
                }),
            ),
            ("name".to_string(), json!("John")),
        ]);

        assert_eq!(expected, nest_claims(claims).unwrap());
    }

    #[test]
    fn test_format_nested_vc_jwt_array() {
        let claims = vec![
            PublishedClaim {
                key: "name".into(),
                value: "John".into(),
                datatype: None,
                array_item: false,
            },
            PublishedClaim {
                key: "location/0".into(),
                value: "1".into(),
                datatype: None,
                array_item: true,
            },
            PublishedClaim {
                key: "location/1".into(),
                value: "2".into(),
                datatype: None,
                array_item: true,
            },
        ];
        let expected = IndexMap::from([
            ("location".to_string(), json!(["1", "2"])),
            ("name".to_string(), json!("John")),
        ]);

        assert_eq!(expected, nest_claims(claims).unwrap());
    }

    #[test]
    fn test_format_special_characters() {
        let claims = vec![
            PublishedClaim {
                key: "name".into(),
                value: "John".into(),
                datatype: None,
                array_item: false,
            },
            PublishedClaim {
                key: "location/weird ~!@#$%^&*()_+{}|:\"<>?`-=[]\\;',.".into(),
                value: "1".into(),
                datatype: None,
                array_item: false,
            },
        ];
        let expected = IndexMap::from([
            (
                "location".to_string(),
                json!({
                  "weird ~!@#$%^&*()_+{}|:\"<>?`-=[]\\;',.": "1",
                }),
            ),
            ("name".to_string(), json!("John")),
        ]);

        assert_eq!(expected, nest_claims(claims).unwrap());
    }

    #[test]
    fn test_json_pointer_escape() {
        assert_eq!(json_pointer_escape("bar"), "bar");
        assert_eq!(json_pointer_escape("/~bar/foo"), "/~0bar/foo");
        assert_eq!(json_pointer_escape("/bar/foo"), "/bar/foo");
    }
}
