use std::ops::Add;
use std::sync::Arc;

use async_trait::async_trait;
use dcql::DcqlQuery;
use futures::future::{BoxFuture, Shared};
use one_crypto::utilities;
use shared_types::{DidValue, ProofId};
use time::{Duration, OffsetDateTime};
use tokio::select;
use tokio_util::sync::CancellationToken;

use crate::config::core_config::TransportType;
use crate::error::ErrorCode::BR_0000;
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::{InteractionId, UpdateInteractionRequest};
use crate::model::proof::{ProofStateEnum, UpdateProofRequest};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{JWTHeader, JWTPayload};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::final1_0::mappers::encode_client_id_with_scheme;
use crate::provider::verification_protocol::openid4vp::final1_0::model::AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, DcqlSubmission, OpenID4VPPresentationDefinition, PexSubmission,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::dto::{
    ProtocolVersion, WithProtocolVersion,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::key_agreement_key::KeyAgreementKey;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;

#[async_trait]
pub(super) trait ProximityVerifierTransport: Send + Sync {
    type Context;

    fn transport_type(&self) -> TransportType;

    async fn wallet_connect(
        &mut self,
        key_agreement: &KeyAgreementKey,
    ) -> Result<Self::Context, VerificationProtocolError>
    where
        Self::Context: WithProtocolVersion;

    async fn send_presentation_request(
        &mut self,
        context: &Self::Context,
        signed_presentation_request: String,
    ) -> Result<(), VerificationProtocolError>;

    async fn receive_presentation(
        &mut self,
        context: &mut Self::Context,
    ) -> Result<HolderResponse, VerificationProtocolError>;

    fn interaction_data_from_submission(
        &self,
        context: Self::Context,
        nonce: String,
        data: SubmissionData,
    ) -> Result<Vec<u8>, VerificationProtocolError>;

    async fn clean_up(&self);
}

pub(super) enum HolderResponse {
    Submission(HolderSubmission),
    Rejection,
}

pub(super) enum HolderSubmission {
    V1(PexSubmission),
    V2(DcqlSubmission),
}

#[expect(clippy::large_enum_variant)]
pub(super) enum SubmissionData {
    V1 {
        request: OpenID4VP20AuthorizationRequest,
        submission: PexSubmission,
        presentation_definition: OpenID4VPPresentationDefinition,
    },
    V2 {
        request: AuthorizationRequest,
        submission: DcqlSubmission,
        dcql_query: DcqlQuery,
    },
}

#[derive(Clone)]
pub(super) struct AsyncVerifierFlowParams {
    pub proof_id: ProofId,
    pub dcql_query: DcqlQuery,
    pub presentation_definition: OpenID4VPPresentationDefinition,
    pub did: DidValue,
    pub interaction_id: InteractionId,
    pub proof_repository: Arc<dyn ProofRepository>,
    pub interaction_repository: Arc<dyn InteractionRepository>,
    pub key_agreement: KeyAgreementKey,
    pub cancellation_token: CancellationToken,
}

enum FlowState {
    Cancelled,
    Finished,
    Rejected,
}

pub(super) async fn verifier_flow<C: WithProtocolVersion>(
    params: AsyncVerifierFlowParams,
    auth_fn: AuthenticationFn,
    on_submission_callback: Option<Shared<BoxFuture<'static, ()>>>,
    mut transport: impl ProximityVerifierTransport<Context = C>,
) {
    let transport_type = transport.transport_type();
    let proof_id = params.proof_id;
    let proof_repository = params.proof_repository.clone();

    let result = verifier_flow_internal(params, auth_fn, &mut transport).await;
    transport.clean_up().await;

    match result {
        Ok(FlowState::Finished) => {
            if let Some(callback) = on_submission_callback {
                callback.await;
            }
        }
        Ok(FlowState::Cancelled) => {} // cancel -> nothing to do
        Ok(FlowState::Rejected) => {
            tracing::info!("{transport_type} verifier flow: stopping, proof request rejected");
            set_proof_state_infallible(
                &proof_id,
                ProofStateEnum::Rejected,
                None,
                &*proof_repository,
            )
            .await;
        }
        Err(err) => {
            let message = format!("{transport_type} verifier flow failure: {err}");
            tracing::info!(message);
            let error_metadata = HistoryErrorMetadata {
                error_code: BR_0000,
                message,
            };
            set_proof_state_infallible(
                &proof_id,
                ProofStateEnum::Error,
                Some(error_metadata),
                &*proof_repository,
            )
            .await;
        }
    }
}

enum Request {
    V1(OpenID4VP20AuthorizationRequest),
    V2(AuthorizationRequest),
}

async fn verifier_flow_internal<C: WithProtocolVersion>(
    params: AsyncVerifierFlowParams,
    auth_fn: AuthenticationFn,
    transport: &mut dyn ProximityVerifierTransport<Context = C>,
) -> Result<FlowState, VerificationProtocolError> {
    let transport_type = transport.transport_type();
    let mut context = select! {
        result = transport.wallet_connect(&params.key_agreement) => result,
        _ = params.cancellation_token.cancelled() => {
                tracing::info!("{transport_type} verifier flow: stopping, other transport selected");
                return Ok(FlowState::Cancelled);
            }
    }?;

    // we notify other transport that this was selected so they can cancel their work
    params.cancellation_token.cancel();

    params
        .proof_repository
        .update_proof(
            &params.proof_id,
            UpdateProofRequest {
                transport: Some(transport_type.to_string()),
                ..Default::default()
            },
            None,
        )
        .await
        .map_err(|err| {
            VerificationProtocolError::Failed(format!("Failed to update proof transport: {err}"))
        })?;

    let nonce = utilities::generate_alphanumeric(32);

    let (signed_request, request) = match context.protocol_version() {
        ProtocolVersion::V1 => {
            let (signed_request, request) =
                get_request_v1(nonce.to_owned(), &params, auth_fn).await?;
            (signed_request, Request::V1(request))
        }
        ProtocolVersion::V2 => {
            let (signed_request, request) =
                get_request_v2(nonce.to_owned(), &params, auth_fn).await?;
            (signed_request, Request::V2(request))
        }
    };

    transport
        .send_presentation_request(&context, signed_request)
        .await?;

    set_proof_state(
        &params.proof_id,
        ProofStateEnum::Requested,
        None,
        &*params.proof_repository,
    )
    .await?;

    let holder_response = transport.receive_presentation(&mut context).await?;
    let holder_submission = match holder_response {
        HolderResponse::Submission(submission) => submission,
        HolderResponse::Rejection => return Ok(FlowState::Rejected),
    };

    let submission_data = match (holder_submission, request) {
        (HolderSubmission::V1(submission), Request::V1(request)) => SubmissionData::V1 {
            request,
            submission,
            presentation_definition: params.presentation_definition,
        },
        (HolderSubmission::V2(submission), Request::V2(request)) => SubmissionData::V2 {
            request,
            submission,
            dcql_query: params.dcql_query,
        },
        _ => {
            return Err(VerificationProtocolError::Failed(
                "Mismatch request/response".to_string(),
            ));
        }
    };

    let interaction_data =
        transport.interaction_data_from_submission(context, nonce, submission_data)?;

    params
        .interaction_repository
        .update_interaction(
            params.interaction_id,
            UpdateInteractionRequest {
                data: Some(Some(interaction_data)),
            },
        )
        .await
        .map_err(|err| {
            VerificationProtocolError::Failed(format!("failed to update interaction: {err}"))
        })?;
    tracing::info!("{transport_type} verifier flow: finished, received proof submission");
    Ok(FlowState::Finished)
}

async fn get_request_v1(
    nonce: String,
    params: &AsyncVerifierFlowParams,
    auth_fn: AuthenticationFn,
) -> Result<(String, OpenID4VP20AuthorizationRequest), VerificationProtocolError> {
    let request = OpenID4VP20AuthorizationRequest {
        nonce: Some(nonce),
        presentation_definition: Some(params.presentation_definition.clone()),
        client_id: params.did.to_string(),
        client_id_scheme: Some(ClientIdScheme::Did),
        ..Default::default()
    };
    let signed_request = request
        .clone()
        .as_signed_jwt(&params.did, auth_fn)
        .await
        .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;
    Ok((signed_request, request))
}

async fn get_request_v2(
    nonce: String,
    params: &AsyncVerifierFlowParams,
    auth_fn: AuthenticationFn,
) -> Result<(String, AuthorizationRequest), VerificationProtocolError> {
    let request = AuthorizationRequest {
        nonce: Some(nonce),
        client_id: encode_client_id_with_scheme(params.did.to_string(), ClientIdScheme::Did),
        dcql_query: Some(params.dcql_query.clone()),
        ..Default::default()
    };
    let signed_request = request_as_signed_jwt(request.clone(), &params.did, auth_fn).await?;
    Ok((signed_request, request))
}

async fn set_proof_state_infallible(
    id: &ProofId,
    state: ProofStateEnum,
    error_metadata: Option<HistoryErrorMetadata>,
    proof_repository: &dyn ProofRepository,
) {
    let result = set_proof_state(id, state, error_metadata, proof_repository).await;
    if let Err(err) = result {
        tracing::warn!("failed to set proof state: {}", err);
    }
}

async fn set_proof_state(
    id: &ProofId,
    state: ProofStateEnum,
    error_metadata: Option<HistoryErrorMetadata>,
    proof_repository: &dyn ProofRepository,
) -> Result<(), VerificationProtocolError> {
    if let Err(error) = proof_repository
        .update_proof(
            id,
            UpdateProofRequest {
                state: Some(state),
                ..Default::default()
            },
            error_metadata,
        )
        .await
    {
        tracing::error!(%error, proof_id=%id, ?state, "Failed setting proof state");
        return Err(VerificationProtocolError::Failed(error.to_string()));
    }
    Ok(())
}

pub(super) async fn request_as_signed_jwt(
    params: AuthorizationRequest,
    did: &DidValue,
    auth_fn: AuthenticationFn,
) -> Result<String, VerificationProtocolError> {
    let unsigned_jwt = Jwt {
        header: JWTHeader {
            algorithm: auth_fn.jose_alg().ok_or(VerificationProtocolError::Failed(
                "No JOSE alg specified".to_string(),
            ))?,
            key_id: auth_fn.get_key_id(),
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: None,
            key_attestation: None,
            x5c: None,
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
            custom: params,
        },
    };
    unsigned_jwt
        .tokenize(Some(&*auth_fn))
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
}
