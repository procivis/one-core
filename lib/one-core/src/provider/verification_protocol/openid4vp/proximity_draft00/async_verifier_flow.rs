use std::sync::Arc;

use async_trait::async_trait;
use futures::future::{BoxFuture, Shared};
use one_crypto::utilities;
use shared_types::{DidValue, ProofId};
use tokio::select;
use tokio_util::sync::CancellationToken;

use crate::config::core_config::TransportType;
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::{InteractionId, UpdateInteractionRequest};
use crate::model::proof::{ProofStateEnum, UpdateProofRequest};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VPPresentationDefinition,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::key_agreement_key::KeyAgreementKey;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ErrorCode::BR_0000;

#[async_trait]
pub(super) trait ProximityVerifierTransport: Send + Sync {
    type Context;
    type PresentationSubmission;

    fn transport_type(&self) -> TransportType;

    async fn wallet_connect(
        &mut self,
        key_agreement: &KeyAgreementKey,
    ) -> Result<Self::Context, VerificationProtocolError>;

    async fn send_presentation_request(
        &mut self,
        context: &Self::Context,
        signed_presentation_request: String,
    ) -> Result<(), VerificationProtocolError>;

    async fn receive_presentation(
        &mut self,
        context: &mut Self::Context,
    ) -> Result<HolderSubmission<Self::PresentationSubmission>, VerificationProtocolError>;

    fn interaction_data_from_submission(
        &self,
        context: Self::Context,
        nonce: String,
        presentation_definition: OpenID4VPPresentationDefinition,
        request: OpenID4VP20AuthorizationRequest,
        presentation_submission: Self::PresentationSubmission,
    ) -> Result<Vec<u8>, VerificationProtocolError>;

    async fn clean_up(&self);
}

pub(crate) enum HolderSubmission<T> {
    Presentation(T),
    Rejection,
}

#[derive(Clone)]
pub(crate) struct AsyncVerifierFlowParams {
    pub proof_id: ProofId,
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

pub(crate) async fn verifier_flow(
    params: AsyncVerifierFlowParams,
    auth_fn: AuthenticationFn,
    on_submission_callback: Option<Shared<BoxFuture<'static, ()>>>,
    mut transport: impl ProximityVerifierTransport,
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

async fn verifier_flow_internal<C, S>(
    params: AsyncVerifierFlowParams,
    auth_fn: AuthenticationFn,
    transport: &mut dyn ProximityVerifierTransport<Context = C, PresentationSubmission = S>,
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

    let update_proof_request = UpdateProofRequest {
        transport: Some(transport_type.to_string()),
        ..Default::default()
    };
    params
        .proof_repository
        .update_proof(&params.proof_id, update_proof_request, None)
        .await
        .map_err(|err| {
            VerificationProtocolError::Failed(format!("Failed to update proof transport: {err}"))
        })?;

    let nonce = utilities::generate_alphanumeric(32);
    let request = OpenID4VP20AuthorizationRequest {
        nonce: Some(nonce.to_owned()),
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

    let holder_submission = transport.receive_presentation(&mut context).await?;
    let presentation_submission = match holder_submission {
        HolderSubmission::Presentation(submission) => submission,
        HolderSubmission::Rejection => return Ok(FlowState::Rejected),
    };

    let interaction_data = transport.interaction_data_from_submission(
        context,
        nonce,
        params.presentation_definition,
        request,
        presentation_submission,
    )?;
    params
        .interaction_repository
        .update_interaction(
            params.interaction_id,
            UpdateInteractionRequest {
                data: Some(Some(interaction_data)),
                ..Default::default()
            },
        )
        .await
        .map_err(|err| {
            VerificationProtocolError::Failed(format!("failed to update interaction: {err}"))
        })?;
    tracing::info!("{transport_type} verifier flow: finished, received proof submission");
    Ok(FlowState::Finished)
}

pub(crate) async fn set_proof_state_infallible(
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
