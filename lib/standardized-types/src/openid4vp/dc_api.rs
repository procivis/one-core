use serde::{Deserialize, Serialize};
use serde_with::{VecSkipError, serde_as, skip_serializing_none};

use super::dcql::DcqlQuery;
use super::{ClientMetadata, ResponseMode, VerifierInfoAttestation};
use crate::mapper::deserialize_json_or_string;

/// Modified params from AuthorizationRequest according to:
/// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-unsigned-request>
#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnsignedAuthorizationRequest {
    #[serde(default)]
    pub response_type: Option<String>,
    pub response_mode: ResponseMode,
    #[serde(default)]
    pub nonce: Option<String>,

    #[serde(default, deserialize_with = "deserialize_json_or_string")]
    pub client_metadata: Option<ClientMetadata>,

    pub dcql_query: DcqlQuery,

    /// Wallets SHOULD ignore any unrecognized or unsupported Verifier Info types.
    #[serde_as(as = "VecSkipError<_>")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifier_info: Vec<VerifierInfoAttestation>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_data: Vec<String>,
}

/// Modified params from AuthorizationRequest according to:
/// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-signed-request>
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedAuthorizationRequestPayload {
    /// With Client Identifier Prefix.
    pub client_id: String,

    pub expected_origins: Vec<String>,

    #[serde(flatten)]
    pub common: UnsignedAuthorizationRequest,
}

/// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-jws-compact-serialization>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JWSCompactSerialized {
    pub request: String,
}

/// <https://www.w3.org/TR/digital-credentials/#the-digitalcredentialgetrequest-dictionary>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", content = "data")]
pub enum DigitalCredentialGetRequest {
    #[serde(rename = "openid4vp-v1-unsigned")]
    OpenID4VpV1Unsigned(Box<UnsignedAuthorizationRequest>),
    #[serde(rename = "openid4vp-v1-signed")]
    OpenID4VpV1Signed(JWSCompactSerialized),
    // currently not supported:
    //  #[serde(rename = "openid4vp-v1-multisigned")]
    //  OpenID4VpV1Multisigned(JWSJsonSerialized),
    //  #[serde(rename = "org-iso-mdoc")]
    //  OrgIsoMdoc(...),
}

/// <https://www.w3.org/TR/digital-credentials/#the-digitalcredentialrequestoptions-dictionary>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DigitalCredentialRequestOptions {
    pub requests: Vec<DigitalCredentialGetRequest>,
}

/// <https://www.w3.org/TR/digital-credentials/#the-digitalcredential-interface>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", content = "data")]
pub enum DigitalCredential {
    #[serde(rename = "openid4vp-v1-unsigned")]
    OpenID4VpV1Unsigned(serde_json::Value),
    #[serde(rename = "openid4vp-v1-signed")]
    OpenID4VpV1Signed(serde_json::Value),
    // currently not supported:
    //  #[serde(rename = "openid4vp-v1-multisigned")]
    //  OpenID4VpV1Multisigned(JWSJsonSerialized),
    //  #[serde(rename = "org-iso-mdoc")]
    //  OrgIsoMdoc(...),
}

#[cfg(test)]
mod test {
    use super::*;

    // example requests from https://verifier.multipaz.org and https://digital-credentials.dev
    #[rstest::rstest]
    #[case(r#"{"client_metadata":{"vp_formats_supported":{"dc+sd-jwt":{"kb-jwt_alg_values":["ES256"],"sd-jwt_alg_values":["ES256"]},"mso_mdoc":{"deviceauth_alg_values":[-9,-7],"issuerauth_alg_values":[-9,-7]}}},"dcql_query":{"credentials":[{"claims":[{"path":["family_name"]},{"path":["given_name"]},{"path":["picture"]}],"format":"dc+sd-jwt","id":"cred1","meta":{"vct_values":["urn:eudi:pid:1"]}}]},"nonce":"n5ZRRoElLEPo4dAAQDUe6g","response_mode":"dc_api","response_type":"vp_token"}"#)]
    #[case(r#"{"client_metadata":{"vp_formats_supported":{"mso_mdoc":{"deviceauth_alg_values":[-7],"issuerauth_alg_values":[-7]}}},"dcql_query":{"credentials":[{"claims":[{"path":["org.iso.18013.5.1","family_name"]}],"format":"mso_mdoc","id":"cred1","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]},"nonce":"8BPaJv_ecq_-N-xDmwvxpYRKi84e6XaZJgZojj_1Li4","response_mode":"dc_api","response_type":"vp_token"}"#)]
    #[test]
    fn test_dc_api_unsigned_request_deserialization(#[case] request_json: &str) {
        let _request: UnsignedAuthorizationRequest = serde_json::from_str(request_json).unwrap();
    }

    #[rstest::rstest]
    #[case(r#"{"response_type":"vp_token","response_mode":"dc_api","nonce":"d_FPUQHg0xSo0uULCfKfPNKhXnpzBILPuLH_70Sv7XE","dcql_query":{"credentials":[{"id":"cred1","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","family_name"]}]}]},"client_metadata":{"vp_formats_supported":{"mso_mdoc":{"issuerauth_alg_values":[-7],"deviceauth_alg_values":[-7]}}},"client_id":"x509_hash:f1drGLOIT4kDBlJVsD-_33igSf5uwRnq3yO2NvcXEW0","expected_origins":["https://digital-credentials.dev"]}"#)]
    #[case(r#"{"iat":1792721601,"response_type":"vp_token","response_mode":"dc_api.jwt","client_id":"x509_san_dns:verifier.multipaz.org","expected_origins":["https://verifier.multipaz.org"],"dcql_query":{"credentials":[{"id":"cred1","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]},{"path":["given_name"]},{"path":["picture"]}]}]},"nonce":"KoDAYQxFZxDFq4T0aT3-CA","client_metadata":{"vp_formats_supported":{"mso_mdoc":{"issuerauth_alg_values":[-9,-7],"deviceauth_alg_values":[-9,-7]},"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]}},"jwks":{"keys":[{"crv":"P-256","kty":"EC","x":"0dr7Ib-YTng_lymUCmNQx1_Rmoim3_CVkpOm89POCuY","y":"85mXTb8-_0LEiQrItNAJt6d5K7SBUVIjo4MPQojnXZ0","kid":"response-encryption-key","alg":"ECDH-ES","use":"enc"}]}}}"#)]
    #[test]
    fn test_dc_api_signed_request_deserialization(#[case] request_json: &str) {
        let _request: SignedAuthorizationRequestPayload =
            serde_json::from_str(request_json).unwrap();
    }

    #[rstest::rstest]
    #[case(r#"{"requests":[{"data":{"request":"eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJ4NWMiOlsiTUlJQ3FqQ0NBbEdnQXdJQkFnSVVXcVlEaTZjZy9YeEFDbDU1U1hJS3I5cVRGak13Q2dZSUtvWkl6ajBFQXdJd2VqRUxNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2tOaGJHbG1iM0p1YVdFeEZqQVVCZ05WQkFjTURVMXZkVzUwWVdsdUlGWnBaWGN4SERBYUJnTlZCQW9NRTBScFoybDBZV3dnUTNKbFpHVnVkR2xoYkhNeElEQWVCZ05WQkFNTUYyUnBaMmwwWVd3dFkzSmxaR1Z1ZEdsaGJITXVaR1YyTUI0WERUSTFNRFF5TlRFek5URXdPRm9YRFRNMU1EUXhNekV6TlRFd09Gb3dlakVMTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnTUNrTmhiR2xtYjNKdWFXRXhGakFVQmdOVkJBY01EVTF2ZFc1MFlXbHVJRlpwWlhjeEhEQWFCZ05WQkFvTUUwUnBaMmwwWVd3Z1EzSmxaR1Z1ZEdsaGJITXhJREFlQmdOVkJBTU1GMlJwWjJsMFlXd3RZM0psWkdWdWRHbGhiSE11WkdWMk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRVgxbEVSYzlqNHBlbjdvRmszVU1FSEJjUEhvVlFYWDdXdkRwUkhNM1czdDNjeFNLRlA3T3dRcVJHNlZWQ01QdzJqeXM0NHpQTHZDaCtWNndDQlZ4R2FhT0J0RENCc1RBZEJnTlZIUTRFRmdRVTAwRm1Kd2kvazNlT09CU2Q5MnM0K1dYbnpIOHdId1lEVlIwakJCZ3dGb0FVMDBGbUp3aS9rM2VPT0JTZDkyczQrV1huekg4d0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBT0JnTlZIUThCQWY4RUJBTUNCNEF3S2dZRFZSMFNCQ013SVlZZmFIUjBjSE02THk5a2FXZHBkR0ZzTFdOeVpXUmxiblJwWVd4ekxtUmxkakFpQmdOVkhSRUVHekFaZ2hka2FXZHBkR0ZzTFdOeVpXUmxiblJwWVd4ekxtUmxkakFLQmdncWhrak9QUVFEQWdOSEFEQkVBaUVBdzA4bVozQUdtc1lKZnZ2Vldia0MwV1E2WVdVUlhXaFE2Vnh5ZlllQ2pnc0NIeElnLzh5TkJ6RDBNRndRcnBXWVhKTkxvbHdHYlpPSjM0TUI0eVdsemtvPSJdfQ.eyJyZXNwb25zZV90eXBlIjogInZwX3Rva2VuIiwgInJlc3BvbnNlX21vZGUiOiAiZGNfYXBpIiwgIm5vbmNlIjogImRfRlBVUUhnMHhTbzB1VUxDZktmUE5LaFhucHpCSUxQdUxIXzcwU3Y3WEUiLCAiZGNxbF9xdWVyeSI6IHsiY3JlZGVudGlhbHMiOiBbeyJpZCI6ICJjcmVkMSIsICJmb3JtYXQiOiAibXNvX21kb2MiLCAibWV0YSI6IHsiZG9jdHlwZV92YWx1ZSI6ICJvcmcuaXNvLjE4MDEzLjUuMS5tREwifSwgImNsYWltcyI6IFt7InBhdGgiOiBbIm9yZy5pc28uMTgwMTMuNS4xIiwgImZhbWlseV9uYW1lIl19XX1dfSwgImNsaWVudF9tZXRhZGF0YSI6IHsidnBfZm9ybWF0c19zdXBwb3J0ZWQiOiB7Im1zb19tZG9jIjogeyJpc3N1ZXJhdXRoX2FsZ192YWx1ZXMiOiBbLTddLCAiZGV2aWNlYXV0aF9hbGdfdmFsdWVzIjogWy03XX19fSwgImNsaWVudF9pZCI6ICJ4NTA5X2hhc2g6ZjFkckdMT0lUNGtEQmxKVnNELV8zM2lnU2Y1dXdSbnEzeU8yTnZjWEVXMCIsICJleHBlY3RlZF9vcmlnaW5zIjogWyJodHRwczovL2RpZ2l0YWwtY3JlZGVudGlhbHMuZGV2Il19.x0P3mzMs4gT70YVi2dOobL-2xRkYfAxZQE8wEXy_-_fyT3T_xNloPZO1i0NkQz_5xGIly4tYr7dathznEs5S0A"},"protocol":"openid4vp-v1-signed"}]}"#)]
    #[case(r#"{"requests":[{"data":{"client_metadata":{"vp_formats_supported":{"mso_mdoc":{"deviceauth_alg_values":[-7],"issuerauth_alg_values":[-7]}}},"dcql_query":{"credentials":[{"claims":[{"path":["org.iso.18013.5.1","family_name"]}],"format":"mso_mdoc","id":"cred1","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]},"nonce":"8BPaJv_ecq_-N-xDmwvxpYRKi84e6XaZJgZojj_1Li4","response_mode":"dc_api","response_type":"vp_token"},"protocol":"openid4vp-v1-unsigned"}]}"#)]
    #[case(r#"{"requests":[{"data":{"client_metadata":{"vp_formats_supported":{"dc+sd-jwt":{"kb-jwt_alg_values":["ES256"],"sd-jwt_alg_values":["ES256"]},"mso_mdoc":{"deviceauth_alg_values":[-9,-7],"issuerauth_alg_values":[-9,-7]}}},"dcql_query":{"credentials":[{"claims":[{"path":["family_name"]},{"path":["given_name"]},{"path":["picture"]}],"format":"dc+sd-jwt","id":"cred1","meta":{"vct_values":["urn:eudi:pid:1"]}}]},"nonce":"n5ZRRoElLEPo4dAAQDUe6g","response_mode":"dc_api","response_type":"vp_token"},"protocol":"openid4vp-v1-unsigned"}]}"#)]
    #[test]
    fn test_dc_api_request_json_deserialization(#[case] request_json: &str) {
        let _requests: DigitalCredentialRequestOptions =
            serde_json::from_str(request_json).unwrap();
    }
}
