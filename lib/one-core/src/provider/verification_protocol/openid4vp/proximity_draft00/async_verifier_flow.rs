use std::future;
use std::sync::Arc;

use futures::future::BoxFuture;
use futures::FutureExt;
use one_crypto::utilities;
use shared_types::DidValue;
use tokio::select;
use tokio_util::sync::CancellationToken;

use crate::config::core_config::TransportType;
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::{InteractionId, UpdateInteractionRequest};
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VPPresentationDefinition,
};
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;

type SendPresentationFn<C> = fn(
    signed_presentation_request: String,
    context: Arc<C>,
) -> BoxFuture<'static, Result<(), VerificationProtocolError>>;
type ReceivePresentationFn<C, T> =
    fn(context: Arc<C>) -> BoxFuture<'static, Result<T, VerificationProtocolError>>;
type InteractionDataMapper<C, T> = fn(
    nonce: String,
    presentation_definition: OpenID4VPPresentationDefinition,
    request: OpenID4VP20AuthorizationRequest,
    submission: T,
    context: Arc<C>,
) -> Result<Vec<u8>, VerificationProtocolError>;

pub(crate) struct AsyncTransportHooks<C, T> {
    pub wallet_connect: BoxFuture<'static, Result<C, VerificationProtocolError>>,
    pub wallet_disconnect: fn(context: Arc<C>) -> BoxFuture<'static, ()>,
    pub wallet_reject: fn(context: Arc<C>) -> BoxFuture<'static, ()>,
    pub send_presentation_request: SendPresentationFn<C>,
    pub receive_presentation: ReceivePresentationFn<C, T>,
    pub interaction_data_from_response: InteractionDataMapper<C, T>,
}

pub(crate) struct AsyncVerifierFlowParams<'a> {
    pub proof: &'a Proof,
    pub presentation_definition: OpenID4VPPresentationDefinition,
    pub did: &'a DidValue,
    pub interaction_id: InteractionId,
    pub proof_repository: &'a dyn ProofRepository,
    pub interaction_repository: &'a dyn InteractionRepository,
    pub transport_type: TransportType,
    pub cancellation_token: CancellationToken,
}

#[derive(Debug)]
pub(crate) enum FlowState {
    Cancelled,
    Rejected,
    Finished,
}

pub(crate) async fn async_verifier_flow<C, T>(
    params: AsyncVerifierFlowParams<'_>,
    hooks: AsyncTransportHooks<C, T>,
    auth_fn: AuthenticationFn,
) -> Result<FlowState, VerificationProtocolError> {
    let context: C = select! {
        connection_result = hooks.wallet_connect => connection_result,
        _ = params.cancellation_token.cancelled() => {
                tracing::info!("{} verifier flow: stopping, other transport selected", params.transport_type);
                return Ok(FlowState::Cancelled);
            }
    }?;
    let context = Arc::new(context);

    // we notify other transport that this was selected so they can cancel their work
    params.cancellation_token.cancel();

    let update_proof_request = UpdateProofRequest {
        transport: Some(params.transport_type.to_string()),
        ..Default::default()
    };
    params
        .proof_repository
        .update_proof(&params.proof.id, update_proof_request, None)
        .await
        .map_err(|err| {
            VerificationProtocolError::Failed(format!("Failed to update proof transport: {err}"))
        })?;

    let nonce = utilities::generate_alphanumeric(32);
    let request = OpenID4VP20AuthorizationRequest {
        nonce: Some(nonce.to_owned()),
        response_type: None,
        response_mode: None,
        response_uri: None,
        client_metadata: None,
        client_metadata_uri: None,
        presentation_definition: Some(params.presentation_definition.clone()),
        presentation_definition_uri: None,
        client_id: params.did.to_string(),
        client_id_scheme: Some(ClientIdScheme::Did),
        state: None,
        redirect_uri: None,
    };
    let signed_request = request
        .clone()
        .as_signed_jwt(params.did, auth_fn)
        .await
        .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;

    let presentation_submission = select! {
        biased;
        _ = (hooks.wallet_disconnect)(context.clone()) => Err(VerificationProtocolError::Failed("wallet_disconnected".into()))?,
        _ = (hooks.wallet_reject)(context.clone()) => {
            tracing::info!("{} verifier flow: stopping, proof request rejected", params.transport_type);
            set_proof_state(params.proof, ProofStateEnum::Rejected, None, params.proof_repository).await?;
            return Ok(FlowState::Rejected);
        },
        result = send_request_and_receive_response(
            signed_request,
            &params,
            hooks.send_presentation_request,
            hooks.receive_presentation,
            context.clone())
        => result
    }?;
    let organisation = params
        .proof
        .schema
        .as_ref()
        .and_then(|schema| schema.organisation.as_ref())
        .ok_or_else(|| VerificationProtocolError::Failed("Missing organisation".to_string()))?;

    let interaction_data = (hooks.interaction_data_from_response)(
        nonce,
        params.presentation_definition,
        request,
        presentation_submission,
        context.clone(),
    )?;
    params
        .interaction_repository
        .update_interaction(UpdateInteractionRequest {
            id: params.interaction_id,
            host: None,
            data: Some(interaction_data),
            organisation: Some(organisation.clone()),
        })
        .await
        .map_err(|err| {
            VerificationProtocolError::Failed(format!("failed to update interaction: {err}"))
        })?;

    tracing::info!(
        "{} verifier flow: finished, received proof submission",
        params.transport_type
    );
    Ok(FlowState::Finished)
}

async fn send_request_and_receive_response<'a, C, T>(
    request: String,
    params: &'a AsyncVerifierFlowParams<'a>,
    send_presentation_request: SendPresentationFn<C>,
    receive_presentation_submission: ReceivePresentationFn<C, T>,
    context: Arc<C>,
) -> Result<T, VerificationProtocolError> {
    send_presentation_request(request, context.clone()).await?;
    set_proof_state(
        params.proof,
        ProofStateEnum::Requested,
        None,
        params.proof_repository,
    )
    .await?;
    receive_presentation_submission(context).await
}

/// Function that returns a `BoxFuture` that never completes.
pub(crate) fn never<T>(_: T) -> BoxFuture<'static, ()> {
    future::pending().boxed()
}

pub(crate) async fn set_proof_state_infallible(
    proof: &Proof,
    state: ProofStateEnum,
    error_metadata: Option<HistoryErrorMetadata>,
    proof_repository: &dyn ProofRepository,
) {
    let result = set_proof_state(proof, state, error_metadata, proof_repository).await;
    if let Err(err) = result {
        tracing::warn!("failed to set proof state: {}", err);
    }
}

async fn set_proof_state(
    proof: &Proof,
    state: ProofStateEnum,
    error_metadata: Option<HistoryErrorMetadata>,
    proof_repository: &dyn ProofRepository,
) -> Result<(), VerificationProtocolError> {
    if let Err(error) = proof_repository
        .update_proof(
            &proof.id,
            UpdateProofRequest {
                state: Some(state.clone()),
                ..Default::default()
            },
            error_metadata,
        )
        .await
    {
        tracing::error!(%error, proof_id=%proof.id, ?state, "Failed setting proof state");
        return Err(VerificationProtocolError::Failed(error.to_string()));
    }
    Ok(())
}
