use std::sync::Arc;

use futures::future::BoxFuture;
use proc_macros::Provider;
use serde::Deserialize;
use serde_json::{Value, json};
use serde_with::{DurationSeconds, serde_as};
use standardized_types::iana::EncryptionAlgorithm;
use standardized_types::openid4vp::{
    AuthorizationRequest, AuthorizationRequestQueryParams, ClientIdPrefix,
};
use time::Duration;
use url::Url;

use crate::config::core_config::{DidType, IdentifierType, TransportType};
use crate::error::ContextWithErrorCode;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::provider::provider_directory::InitializationError;
use crate::provider::verification_protocol::dto::{
    Feature, FormattedCredentialPresentation, InvitationResponseDTO,
    PresentationDefinitionV2ResponseDTO, PresentationDefinitionVersion, ShareResponse,
    UpdateResponse, VerificationProtocolCapabilities,
};
use crate::provider::verification_protocol::openid4vp::final1_0::OpenID4VPFinal1_0;
use crate::provider::verification_protocol::openid4vp::model::OpenID4VPVerifierInteractionContent;
use crate::provider::verification_protocol::openid4vp::{FormatMapper, VerificationProtocolError};
use crate::provider::verification_protocol::{
    VerificationProtocol, deserialize_interaction_data, serialize_interaction_data,
};
use crate::service::proof::dto::ShareProofRequestParamsDTO;

#[derive(Provider)]
pub(crate) struct OpenID4VPFinalSwiyu {
    inner: OpenID4VPFinal1_0,
    client: Arc<dyn HttpClient>,
    params: OpenID4VpFinalSwiyuParams,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenID4VpFinalSwiyuParams {
    #[serde(default)]
    allow_insecure_http_transport: bool,
    #[serde(default)]
    verifier: Option<OpenID4Vp20SwiyuPresentationVerifierParams>,
}

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenID4Vp20SwiyuPresentationVerifierParams {
    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    interaction_expires_in_seconds: Option<Duration>,
}

pub(crate) fn swiyu_to_final_params(mut params: Value) -> Result<Value, serde_json::Error> {
    let swiyu_params: OpenID4VpFinalSwiyuParams = serde_json::from_value(params.clone())?;

    let verifier = if let Some(interaction_expires_in_seconds) = swiyu_params
        .verifier
        .and_then(|verifier| verifier.interaction_expires_in_seconds)
    {
        json!({
           "supportedClientIdSchemes": [ClientIdPrefix::DecentralizedIdentifier],
           "interactionExpiresInSeconds": interaction_expires_in_seconds.whole_seconds()
        })
    } else {
        json!({ "supportedClientIdSchemes": [ClientIdPrefix::DecentralizedIdentifier] })
    };

    let additional_params = json!({
        "useRequestUri": true,
        "useLegacyDidClientIdScheme": true,
        "urlScheme": "swiyu-verify",
        "predefinedVpFormatsSupported": {
            "dc+sd-jwt": {
                "sd-jwt_alg_values": ["ES256"],
                "kb-jwt_alg_values": ["ES256"],
            }
        },
        "holder": {
            "supportedClientIdSchemes": [ClientIdPrefix::DecentralizedIdentifier]
        },
        "verifier": verifier,
    });

    if let (Value::Object(a), Value::Object(b)) = (&mut params, additional_params) {
        a.extend(b);
    }

    Ok(params)
}

impl OpenID4VPFinalSwiyu {
    pub(crate) fn new(
        inner: OpenID4VPFinal1_0,
        client: Arc<dyn HttpClient>,
        params: Value,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: inner.config_name().to_string(),
                source: err,
            })?;

        Ok(Self {
            inner,
            client,
            params,
        })
    }
}

#[async_trait::async_trait]
impl VerificationProtocol for OpenID4VPFinalSwiyu {
    async fn retract_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        Ok(())
    }
    fn holder_can_handle(&self, url: &Url) -> bool {
        self.inner.holder_can_handle(url)
            || (url.scheme() == "https"
                || self.params.allow_insecure_http_transport && url.scheme() == "http")
                && url.query().is_none() // SWIYU invite links have no query param
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        let mut features = vec![];

        if self
            .inner
            .get_capabilities()
            .features
            .contains(&Feature::SupportsWebhooks)
        {
            features.push(Feature::SupportsWebhooks);
        }

        VerificationProtocolCapabilities {
            features,
            supported_transports: vec![TransportType::Http],
            did_methods: vec![DidType::WebVh],
            verifier_identifier_types: vec![IdentifierType::Did],
            supported_presentation_definition: vec![PresentationDefinitionVersion::V2],
            supported_encryption_algorithms: vec![
                EncryptionAlgorithm::A128GCM,
                EncryptionAlgorithm::A256GCM,
            ],
        }
    }

    async fn holder_handle_invitation<'a>(
        &self,
        url: Url,
        organisation: Organisation,
        transport: String,
    ) -> Result<InvitationResponseDTO<'a>, VerificationProtocolError> {
        if !self.holder_can_handle(&url) {
            return Err(VerificationProtocolError::Failed(
                "No OpenID4VC query params detected".to_string(),
            ));
        }

        if url.scheme() == "swiyu-verify" {
            return self
                .inner
                .holder_handle_invitation(url, organisation, transport)
                .await;
        }

        // https url case
        let response = async {
            self.client
                .get(url.as_str())
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("fetching swiyu request")?;
        let token = String::from_utf8(response.body).map_err(|e| {
            VerificationProtocolError::Failed(format!("Invalid request object: {e}"))
        })?;
        let params: DecomposedJwt<AuthorizationRequest> =
            Jwt::decompose_token(&token).error_while("parsing request JWT")?;
        let request_params = AuthorizationRequestQueryParams {
            client_id: params.payload.custom.client_id,
            request_uri: Some(url.to_string()),
            ..Default::default()
        };
        let adjusted_url: Url = format!(
            "swiyu-verify://?{}",
            serde_qs::to_string(&request_params).map_err(|e| VerificationProtocolError::Failed(
                format!("Failed to serialize query params: {e}")
            ))?
        )
        .parse()
        .map_err(|e| {
            VerificationProtocolError::Failed(format!("Failed to parse invitation URL: {e}"))
        })?;

        self.inner
            .holder_handle_invitation(adjusted_url, organisation, transport)
            .await
    }

    async fn holder_reject_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        // Rejection not supported and handled as no-op on holder side
        Ok(())
    }

    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<FormattedCredentialPresentation>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        self.inner
            .holder_submit_proof(proof, credential_presentations)
            .await
    }

    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        callback: Option<BoxFuture<'static, ()>>,
        params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse, VerificationProtocolError> {
        let mut response = self
            .inner
            .verifier_share_proof(proof, format_to_type_mapper, callback, params)
            .await?;
        let mut interaction_data: OpenID4VPVerifierInteractionContent =
            deserialize_interaction_data(response.interaction_data.as_ref())?;
        let mut response_url: Url = interaction_data
            .response_uri
            .ok_or(VerificationProtocolError::Failed(
                "missing response_uri".to_string(),
            ))?
            .parse()
            .map_err(|err| {
                VerificationProtocolError::Failed(format!(
                    "failed to parse response_uri in response URL: {err}"
                ))
            })?;
        response_url.set_path(&format!(
            "/ssi/openid4vp/final-1.0-swiyu/response/{}",
            response.interaction_id
        ));
        interaction_data.response_uri = Some(response_url.to_string());

        response.interaction_data = Some(serialize_interaction_data(&interaction_data)?);
        response.url = response.url.replace("final-1.0", "final-1.0-swiyu");
        Ok(response)
    }

    async fn holder_get_presentation_definition_v2(
        &self,
        proof: &Proof,
        context: Value,
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
        self.inner
            .holder_get_presentation_definition_v2(proof, context)
            .await
    }

    fn config_name(&self) -> &str {
        self.inner.config_name()
    }
}
