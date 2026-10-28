//! Authorization Request
//!
//! Spec https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request

use serde::{Deserialize, Serialize};
use serde_with::{VecSkipError, serde_as, skip_serializing_none};
use strum::{Display, EnumString};
use url::Url;

use super::{ClientMetadata, ResponseMode};
use crate::mapper::deserialize_json_or_string;
use crate::openid4vp::dcql::{CredentialQueryId, DcqlQuery};

/// Authorization Request parameters as passed in the URL query string.
///
/// Non-primitive parameters are JSON-encoded strings here. `request` and `request_uri` are defined
/// by [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html#name-authorization-request).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AuthorizationRequestQueryParams {
    /// With Client Identifier Prefix.
    pub client_id: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<ResponseMode>,
    pub response_uri: Option<String>,
    pub client_metadata: Option<String>,
    pub dcql_query: Option<String>,
    pub transaction_data: Option<Vec<String>>,

    pub request: Option<String>,
    pub request_uri: Option<String>,

    pub redirect_uri: Option<String>,
}

/// Authorization Request as passed by value, i.e. as the payload of a signed request object (JAR)
/// or as a `request` parameter.
#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// With Client Identifier Prefix.
    pub client_id: String,

    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,

    #[serde(default)]
    pub response_type: Option<String>,
    #[serde(default)]
    pub response_mode: Option<ResponseMode>,
    #[serde(default)]
    pub response_uri: Option<Url>,

    #[serde(default, deserialize_with = "deserialize_json_or_string")]
    pub client_metadata: Option<ClientMetadata>,

    pub dcql_query: DcqlQuery,

    #[serde(default)]
    pub redirect_uri: Option<String>,

    /// Wallets SHOULD ignore any unrecognized or unsupported Verifier Info types.
    #[serde_as(as = "VecSkipError<_>")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifier_info: Vec<VerifierInfoAttestation>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_data: Vec<String>,
}

/// Entry of the `verifier_info` Authorization Request parameter.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierInfoAttestation {
    pub format: VerifierInfoAttestationFormat,
    pub data: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_ids: Vec<CredentialQueryId>,
}

/// Format of a [`VerifierInfoAttestation`]. The set of formats is an open registry, however wallets
/// should skip unrecognized verifier info types (which is handled on `AuthorizationRequest`), hence
/// there is no catch-all, other type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierInfoAttestationFormat {
    /// ETSI TS 119 472-3 V1.1.1, Section 4.2.3
    RegistrationCert,
}

/// Client Identifier Prefix.
///
/// Spec https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-prefix-an
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ClientIdPrefix {
    RedirectUri,
    VerifierAttestation,
    DecentralizedIdentifier,
    X509SanDns,
    X509Hash,
}

/// Custom claims of the Verifier Attestation JWT used with the `verifier_attestation`
/// Client Identifier Prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VerifierAttestationClaims {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_client_id_prefix_rejects_legacy_did() {
        assert!(serde_json::from_value::<ClientIdPrefix>(serde_json::json!("did")).is_err());
        assert_eq!(
            ClientIdPrefix::DecentralizedIdentifier,
            serde_json::from_value(serde_json::json!("decentralized_identifier")).unwrap()
        );
        assert_eq!(
            "decentralized_identifier",
            ClientIdPrefix::DecentralizedIdentifier.to_string()
        );
    }

    #[test]
    fn test_client_metadata_accepts_object_and_json_string() {
        let with_object = serde_json::json!({
            "client_id": "x509_san_dns:example.com",
            "dcql_query": { "credentials": [] },
            "client_metadata": { "jwks_uri": "https://example.com/jwks" },
        });
        let with_string = serde_json::json!({
            "client_id": "x509_san_dns:example.com",
            "dcql_query": { "credentials": [] },
            "client_metadata": "{\"jwks_uri\":\"https://example.com/jwks\"}",
        });

        let from_object: AuthorizationRequest = serde_json::from_value(with_object).unwrap();
        let from_string: AuthorizationRequest = serde_json::from_value(with_string).unwrap();

        assert_eq!(from_object, from_string);
        assert_eq!(
            Some("https://example.com/jwks".to_string()),
            from_object.client_metadata.unwrap().jwks_uri
        );
    }
}
