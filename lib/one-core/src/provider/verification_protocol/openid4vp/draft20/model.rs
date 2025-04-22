use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::mapper::deserialize_with_serde_json;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VPClientMetadata, OpenID4VPPresentationDefinition,
};

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct OpenID4VP20AuthorizationRequestQueryParams {
    pub client_id: String,
    pub client_id_scheme: Option<ClientIdScheme>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<String>,
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
    pub response_mode: Option<String>,
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

impl TryFrom<OpenID4VP20AuthorizationRequestQueryParams> for OpenID4VP20AuthorizationRequest {
    type Error = VerificationProtocolError;

    fn try_from(value: OpenID4VP20AuthorizationRequestQueryParams) -> Result<Self, Self::Error> {
        let url_parse = |uri: String| {
            Url::parse(&uri).map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))
        };

        fn json_parse<T: for<'a> Deserialize<'a>>(
            input: String,
        ) -> Result<T, VerificationProtocolError> {
            serde_json::from_str(&input)
                .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))
        }

        Ok(OpenID4VP20AuthorizationRequest {
            client_id: value.client_id,
            client_id_scheme: value.client_id_scheme,
            state: value.state,
            nonce: value.nonce,
            response_type: value.response_type,
            response_mode: value.response_mode,
            response_uri: value.response_uri.map(url_parse).transpose()?,
            client_metadata: value.client_metadata.map(json_parse).transpose()?,
            client_metadata_uri: value.client_metadata_uri.map(url_parse).transpose()?,
            presentation_definition: value.presentation_definition.map(json_parse).transpose()?,
            presentation_definition_uri: value
                .presentation_definition_uri
                .map(url_parse)
                .transpose()?,
            redirect_uri: value.redirect_uri,
        })
    }
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct OpenID4VP20HolderInteractionData {
    pub response_type: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub client_id_scheme: ClientIdScheme,
    pub client_id: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub client_metadata: Option<OpenID4VPClientMetadata>,
    pub client_metadata_uri: Option<Url>,
    pub response_mode: Option<String>,
    pub response_uri: Option<Url>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    pub presentation_definition_uri: Option<Url>,

    #[serde(default, skip_serializing)]
    pub redirect_uri: Option<String>,

    #[serde(default)]
    pub verifier_did: Option<String>,
}

impl From<OpenID4VP20AuthorizationRequest> for OpenID4VP20HolderInteractionData {
    fn from(value: OpenID4VP20AuthorizationRequest) -> Self {
        Self {
            client_id: value.client_id,
            client_id_scheme: value
                .client_id_scheme
                .unwrap_or(ClientIdScheme::RedirectUri),
            response_type: value.response_type,
            response_mode: value.response_mode,
            response_uri: value.response_uri,
            state: value.state,
            nonce: value.nonce,
            client_metadata: value.client_metadata,
            client_metadata_uri: value.client_metadata_uri,
            presentation_definition: value.presentation_definition,
            presentation_definition_uri: value.presentation_definition_uri,
            redirect_uri: value.redirect_uri,
            verifier_did: None,
        }
    }
}
