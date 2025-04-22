use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft25::mappers::decode_client_id_with_scheme;
use crate::provider::verification_protocol::openid4vp::mapper::deserialize_with_serde_json;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPClientMetadata, OpenID4VPHolderInteractionData, OpenID4VPPresentationDefinition,
};

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct OpenID4VP25AuthorizationRequestQueryParams {
    pub client_id: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<String>,
    pub response_uri: Option<String>,
    pub client_metadata: Option<String>,
    pub presentation_definition: Option<String>,
    pub presentation_definition_uri: Option<String>,

    // https://www.rfc-editor.org/rfc/rfc9101.html#name-authorization-request
    pub request: Option<String>,
    pub request_uri: Option<String>,

    pub redirect_uri: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub(crate) struct OpenID4VP25AuthorizationRequest {
    pub client_id: String,

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

    #[serde(default, deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,

    #[serde(default)]
    pub presentation_definition_uri: Option<Url>,

    #[serde(default)]
    pub redirect_uri: Option<String>,
}
impl TryFrom<OpenID4VP25AuthorizationRequestQueryParams> for OpenID4VP25AuthorizationRequest {
    type Error = VerificationProtocolError;

    fn try_from(
        query_params: OpenID4VP25AuthorizationRequestQueryParams,
    ) -> Result<Self, Self::Error> {
        fn json_parse<T: for<'a> Deserialize<'a>>(
            input: String,
        ) -> Result<T, VerificationProtocolError> {
            serde_json::from_str(&input)
                .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))
        }

        let (client_id, _) = decode_client_id_with_scheme(query_params.client_id)?;

        Ok(OpenID4VP25AuthorizationRequest {
            client_id,
            state: query_params.state,
            nonce: query_params.nonce,
            response_type: query_params.response_type,
            response_mode: query_params.response_mode,
            presentation_definition_uri: query_params
                .presentation_definition_uri
                .map(|uri| {
                    uri.parse().map_err(|_| {
                        VerificationProtocolError::InvalidRequest(
                            "invalid presentation_definition_uri".to_string(),
                        )
                    })
                })
                .transpose()?,
            response_uri: query_params
                .response_uri
                .map(|uri| Url::parse(&uri))
                .transpose()
                .map_err(|_| {
                    VerificationProtocolError::InvalidRequest("invalid response_uri".to_string())
                })?,
            client_metadata: query_params.client_metadata.map(json_parse).transpose()?,
            presentation_definition: query_params
                .presentation_definition
                .map(json_parse)
                .transpose()?,
            redirect_uri: query_params.redirect_uri,
        })
    }
}

impl TryFrom<OpenID4VP25AuthorizationRequest> for OpenID4VPHolderInteractionData {
    type Error = VerificationProtocolError;

    fn try_from(value: OpenID4VP25AuthorizationRequest) -> Result<Self, Self::Error> {
        let (client_id, client_id_scheme) = decode_client_id_with_scheme(value.client_id)?;

        Ok(Self {
            client_id,
            response_type: value.response_type,
            state: value.state,
            nonce: value.nonce,
            client_id_scheme,
            client_metadata: value.client_metadata,
            client_metadata_uri: None,
            response_mode: value.response_mode,
            response_uri: value.response_uri,
            presentation_definition: value.presentation_definition,
            presentation_definition_uri: value.presentation_definition_uri,
            redirect_uri: value.redirect_uri,
            verifier_did: None,
        })
    }
}
