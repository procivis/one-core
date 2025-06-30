use std::collections::HashMap;
use std::sync::Arc;

use futures::future::BoxFuture;
use maplit::hashmap;
use serde::Deserialize;
use url::Url;

use crate::common_mapper::PublicKeyWithJwk;
use crate::config::core_config::{DidType, IdentifierType, TransportType};
use crate::model::did::Did;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::jwt::model::DecomposedToken;
use crate::provider::credential_formatter::model::{DetailCredential, HolderBindingCtx};
use crate::provider::http_client::HttpClient;
use crate::provider::verification_protocol::VerificationProtocol;
use crate::provider::verification_protocol::dto::{
    InvitationResponseDTO, PresentationDefinitionResponseDTO, PresentedCredential, ShareResponse,
    UpdateResponse, VerificationProtocolCapabilities,
};
use crate::provider::verification_protocol::openid4vp::draft20::OpenID4VP20HTTP;
use crate::provider::verification_protocol::openid4vp::draft20::model::{
    OpenID4VP20AuthorizationRequest, OpenID4VP20AuthorizationRequestQueryParams, OpenID4Vp20Params,
};
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VCPresentationHolderParams, OpenID4VCPresentationVerifierParams,
    OpenID4VCRedirectUriParams, OpenID4VPClientMetadata, OpenID4VPVcSdJwtAlgs,
    OpenID4VPVerifierInteractionContent, OpenID4VpPresentationFormat,
};
use crate::provider::verification_protocol::openid4vp::{
    FormatMapper, StorageAccess, TypeToDescriptorMapper, VerificationProtocolError,
};
use crate::service::proof::dto::ShareProofRequestParamsDTO;

pub(crate) struct OpenID4VP20Swiyu {
    inner: OpenID4VP20HTTP,
    client: Arc<dyn HttpClient>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4Vp20SwiyuParams {
    #[serde(default)]
    pub allow_insecure_http_transport: bool,
    pub redirect_uri: OpenID4VCRedirectUriParams,
}

impl From<OpenID4Vp20SwiyuParams> for OpenID4Vp20Params {
    fn from(value: OpenID4Vp20SwiyuParams) -> Self {
        Self {
            client_metadata_by_value: false,
            presentation_definition_by_value: false,
            allow_insecure_http_transport: value.allow_insecure_http_transport,
            use_request_uri: true,
            url_scheme: "openid4vp".to_string(),
            holder: OpenID4VCPresentationHolderParams {
                supported_client_id_schemes: vec![ClientIdScheme::Did],
            },
            verifier: OpenID4VCPresentationVerifierParams {
                supported_client_id_schemes: vec![ClientIdScheme::Did],
            },
            redirect_uri: value.redirect_uri,
            predefined_client_metadata: Some(OpenID4VPClientMetadata {
                vp_formats: hashmap! {
                    "dc+sd-jwt".to_string() =>  OpenID4VpPresentationFormat::SdJwtVcAlgs(
                        OpenID4VPVcSdJwtAlgs {
                            sd_jwt_algorithms: vec!["ES256".to_string()],
                            kb_jwt_algorithms: vec!["ES256".to_string()]
                        }
                    )
                },
                ..Default::default()
            }),
        }
    }
}

impl OpenID4VP20Swiyu {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(inner: OpenID4VP20HTTP, client: Arc<dyn HttpClient>) -> Self {
        Self { inner, client }
    }
}

#[allow(clippy::too_many_arguments)]
#[async_trait::async_trait]
impl VerificationProtocol for OpenID4VP20Swiyu {
    async fn retract_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        Ok(())
    }
    fn holder_can_handle(&self, url: &Url) -> bool {
        url.scheme() == "https" && url.query().is_none() // SWIYU invite links have no query param
    }

    async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        context: serde_json::Value,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
        self.inner
            .holder_get_presentation_definition(proof, context, storage_access)
            .await
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        VerificationProtocolCapabilities {
            supported_transports: vec![TransportType::Http],
            did_methods: vec![DidType::WebVh],
            verifier_identifier_types: vec![IdentifierType::Did],
        }
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, VerificationProtocolError> {
        todo!()
    }

    fn holder_get_holder_binding_context(
        &self,
        proof: &Proof,
        context: serde_json::Value,
    ) -> Result<Option<HolderBindingCtx>, VerificationProtocolError> {
        self.inner.holder_get_holder_binding_context(proof, context)
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        transport: String,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        if !self.holder_can_handle(&url) {
            return Err(VerificationProtocolError::Failed(
                "No OpenID4VC query params detected".to_string(),
            ));
        }

        let response = self.client.get(url.as_str()).send().await.map_err(|e| {
            VerificationProtocolError::Failed(format!("Failed to get request object: {e}"))
        })?;
        let token = String::from_utf8(response.body).map_err(|e| {
            VerificationProtocolError::Failed(format!("Invalid request object: {e}"))
        })?;
        let params: DecomposedToken<OpenID4VP20AuthorizationRequest> = Jwt::decompose_token(&token)
            .map_err(|e| {
                VerificationProtocolError::Failed(format!("Failed to decompose token: {e}"))
            })?;
        let request_params = OpenID4VP20AuthorizationRequestQueryParams {
            client_id: params.payload.custom.client_id,
            request_uri: Some(url.to_string()),
            client_id_scheme: params.payload.custom.client_id_scheme,
            ..Default::default()
        };
        let expected_url: Url = format!(
            "openid4vp://?{}",
            serde_qs::to_string(&request_params).map_err(|e| VerificationProtocolError::Failed(
                format!("Failed to serialize query params: {e}")
            ))?
        )
        .parse()
        .map_err(|e| {
            VerificationProtocolError::Failed(format!("Failed to parse query params: {e}"))
        })?;

        self.inner
            .holder_handle_invitation(expected_url, organisation, storage_access, transport)
            .await
    }

    async fn holder_reject_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        // Rejection not supported and handled as no-op on holder side
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        self.inner
            .holder_submit_proof(proof, credential_presentations, holder_did, key, jwk_key_id)
            .await
    }

    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        encryption_key_jwk: Option<PublicKeyWithJwk>,
        vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
        callback: Option<BoxFuture<'static, ()>>,
        params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse<serde_json::Value>, VerificationProtocolError> {
        let mut response = self
            .inner
            .verifier_share_proof(
                proof,
                format_to_type_mapper,
                encryption_key_jwk,
                vp_formats,
                type_to_descriptor,
                callback,
                params,
            )
            .await?;
        let mut interaction_data: OpenID4VPVerifierInteractionContent =
            serde_json::from_value(response.context).map_err(|err| {
                VerificationProtocolError::Failed(format!(
                    "failed to parse interaction data: {err}"
                ))
            })?;
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
            "/ssi/openid4vp/draft-20-swiyu/response/{}",
            response.interaction_id
        ));
        interaction_data.response_uri = Some(response_url.to_string());

        let url = response.url.parse::<Url>().map_err(|e| {
            VerificationProtocolError::Failed(format!("failed to transform response URL: {e}"))
        })?;

        response.context = serde_json::to_value(&interaction_data).map_err(|err| {
            VerificationProtocolError::Failed(format!(
                "failed to serialize interaction data: {err}"
            ))
        })?;
        response.url = url
            .query_pairs()
            .find(|(k, _)| k == "request_uri")
            .map(|(_, v)| v.to_string())
            .ok_or(VerificationProtocolError::Failed(
                "failed to find request_uri in response URL".to_string(),
            ))?;
        Ok(response)
    }
}
