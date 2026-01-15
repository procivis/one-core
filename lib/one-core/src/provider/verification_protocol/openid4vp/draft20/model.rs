use std::ops::Add;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::DidValue;
use standardized_types::openid4vp::ResponseMode;
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::mapper::params::deserialize_duration_seconds_option;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{JWTHeader, JWTPayload};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::verification_protocol::openid4vp::AuthenticationFn;
use crate::provider::verification_protocol::openid4vp::mapper::deserialize_with_serde_json;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VCPresentationHolderParams, OpenID4VCRedirectUriParams,
    OpenID4VPClientMetadata, OpenID4VPDraftClientMetadata, OpenID4VPPresentationDefinition,
    default_presentation_url_scheme,
};
use crate::service::error::ServiceError;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4Vp20Params {
    #[serde(default)]
    pub client_metadata_by_value: bool,
    #[serde(default)]
    pub presentation_definition_by_value: bool,
    #[serde(default)]
    pub allow_insecure_http_transport: bool,
    #[serde(default)]
    pub use_request_uri: bool,

    #[serde(default = "default_presentation_url_scheme")]
    pub url_scheme: String,

    pub holder: OpenID4VCPresentationHolderParams,
    pub verifier: OpenID4VC20PresentationVerifierParams,
    pub redirect_uri: OpenID4VCRedirectUriParams,
    // Required to handle SWIYU verification requests that have invalid client_metadata.
    // Remove when the SWIYU provider is removed.
    pub predefined_client_metadata: Option<OpenID4VPDraftClientMetadata>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VC20PresentationVerifierParams {
    pub supported_client_id_schemes: Vec<ClientIdScheme>,
    #[serde(default, deserialize_with = "deserialize_duration_seconds_option")]
    pub interaction_expires_in: Option<Duration>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct OpenID4VP20AuthorizationRequestQueryParams {
    pub client_id: String,
    pub client_id_scheme: Option<ClientIdScheme>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<ResponseMode>,
    pub response_uri: Option<String>,
    pub client_metadata: Option<String>,
    pub client_metadata_uri: Option<String>,
    pub presentation_definition: Option<String>,
    pub presentation_definition_uri: Option<String>,

    // https://www.rfc-editor.org/rfc/rfc9101.html#name-authorization-request
    pub request: Option<String>,
    pub request_uri: Option<String>,

    pub redirect_uri: Option<String>,
}
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct OpenID4VP20AuthorizationRequest {
    pub client_id: String,
    #[serde(default)]
    pub client_id_scheme: Option<ClientIdScheme>,

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

    #[serde(default, deserialize_with = "deserialize_with_serde_json")]
    pub client_metadata: Option<OpenID4VPClientMetadata>,
    #[serde(default)]
    pub client_metadata_uri: Option<Url>,

    #[serde(default, deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    #[serde(default)]
    pub presentation_definition_uri: Option<Url>,

    #[serde(default)]
    pub redirect_uri: Option<String>,
}

impl OpenID4VP20AuthorizationRequest {
    pub(crate) async fn as_signed_jwt(
        &self,
        did: &DidValue,
        auth_fn: AuthenticationFn,
    ) -> Result<String, ServiceError> {
        let unsigned_jwt = Jwt {
            header: JWTHeader {
                algorithm: auth_fn.jose_alg().ok_or(KeyAlgorithmError::Failed(
                    "No JOSE alg specified".to_string(),
                ))?,
                key_id: auth_fn.get_key_id(),
                r#type: Some("oauth-authz-req+jwt".to_string()),
                jwk: None,
                jwt: None,
                x5c: None,
                key_attestation: None,
            },
            payload: JWTPayload {
                issued_at: None,
                expires_at: Some(OffsetDateTime::now_utc().add(Duration::hours(1))),
                invalid_before: None,
                issuer: Some(did.to_string()),
                subject: None,
                audience: None,
                jwt_id: None,
                proof_of_possession_key: None,
                custom: self.clone(),
            },
        };
        Ok(unsigned_jwt.tokenize(Some(&*auth_fn)).await?)
    }
}
