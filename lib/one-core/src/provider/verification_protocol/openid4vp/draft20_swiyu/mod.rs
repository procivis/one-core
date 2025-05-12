use std::collections::HashMap;
use std::sync::Arc;

use futures::future::BoxFuture;
use url::Url;

use crate::common_mapper::PublicKeyWithJwk;
use crate::config::core_config::{DidType, TransportType};
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
use crate::provider::verification_protocol::openid4vp::model::OpenID4VpPresentationFormat;
use crate::provider::verification_protocol::openid4vp::{
    FormatMapper, StorageAccess, TypeToDescriptorMapper, VerificationProtocolError,
};
use crate::service::proof::dto::ShareProofRequestParamsDTO;

pub(crate) struct OpenID4VP20Swiyu {
    inner: OpenID4VP20HTTP,
    params: OpenID4Vp20Params,
    client: Arc<dyn HttpClient>,
}

impl OpenID4VP20Swiyu {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        inner: OpenID4VP20HTTP,
        params: OpenID4Vp20Params,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            inner,
            params,
            client,
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[async_trait::async_trait]
impl VerificationProtocol for OpenID4VP20Swiyu {
    async fn retract_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        Ok(())
    }
    fn holder_can_handle(&self, url: &Url) -> bool {
        self.params.url_scheme == url.scheme() && url.query().is_none() // SWIYU invite links have no query param
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
            VerificationProtocolError::Failed(format!("Failed to get request object: {}", e))
        })?;
        let token = String::from_utf8(response.body).map_err(|e| {
            VerificationProtocolError::Failed(format!("Invalid request object: {}", e))
        })?;
        let params: DecomposedToken<OpenID4VP20AuthorizationRequest> = Jwt::decompose_token(&token)
            .map_err(|e| {
                VerificationProtocolError::Failed(format!("Failed to decompose token: {}", e))
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
                format!("Failed to serialize query params: {}", e)
            ))?
        )
        .parse()
        .map_err(|e| {
            VerificationProtocolError::Failed(format!("Failed to parse query params: {}", e))
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
        _callback: Option<BoxFuture<'static, ()>>,
        params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse<serde_json::Value>, VerificationProtocolError> {
        self.inner
            .verifier_share_proof(
                proof,
                format_to_type_mapper,
                encryption_key_jwk,
                vp_formats,
                type_to_descriptor,
                _callback,
                params,
            )
            .await
    }
}
