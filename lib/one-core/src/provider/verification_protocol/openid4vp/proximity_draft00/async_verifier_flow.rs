use std::ops::Add;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::{BoxFuture, Shared};
use one_crypto::utilities;
use serde::Serialize;
use shared_types::{DidValue, InteractionId, ProofId};
use standardized_types::openid4vp::dcql::DcqlQuery;
use standardized_types::openid4vp::{AuthorizationRequest, ClientIdPrefix, VpTokenResponse};
use time::Duration;
use tokio::select;
use tokio_util::sync::CancellationToken;

use crate::config::core_config::TransportType;
use crate::error::ContextWithErrorCode;
use crate::error::ErrorCode::BR_0000;
use crate::mapper::x509::{fingerprint_into_sha256_thumbprint, pem_chain_into_x5c};
use crate::model::certificate::Certificate;
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::UpdateInteractionRequest;
use crate::model::proof::{ProofStateEnum, UpdateProofRequest};
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::final1_0::mappers::encode_client_id_with_scheme;
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
    // Proximity protocol V1 removed
    // V1(PexSubmission),
    V2(VpTokenResponse),
}

pub(super) enum SubmissionData {
    // Proximity protocol V1 removed
    // V1,
    V2 {
        request: AuthorizationRequest,
        submission: VpTokenResponse,
        dcql_query: DcqlQuery,
    },
}

#[derive(Clone)]
pub(super) enum VerifierIdentifier {
    Did(DidValue),
    Certificate { x509_hash: String, x5c: Vec<String> },
}

impl VerifierIdentifier {
    pub(super) fn certificate(
        certificate: &Certificate,
    ) -> Result<Self, VerificationProtocolError> {
        Ok(Self::Certificate {
            x509_hash: fingerprint_into_sha256_thumbprint(&certificate.fingerprint)
                .error_while("computing x509_hash client_id")?,
            x5c: pem_chain_into_x5c(&certificate.chain).error_while("parsing PEM chain")?,
        })
    }

    pub(super) fn client_id(&self) -> String {
        match self {
            Self::Did(did) => encode_client_id_with_scheme(
                did.to_string(),
                ClientIdPrefix::DecentralizedIdentifier,
                false,
            ),
            Self::Certificate { x509_hash, .. } => {
                encode_client_id_with_scheme(x509_hash.to_owned(), ClientIdPrefix::X509Hash, false)
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct AsyncVerifierFlowParams {
    pub proof_id: ProofId,
    pub dcql_query: DcqlQuery,
    pub verifier: VerifierIdentifier,
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
    // Proximity protocol V1 removed
    // V1(OpenID4VP20AuthorizationRequest),
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
        .error_while("updating proof")?;

    let nonce = utilities::generate_alphanumeric(32);

    let (signed_request, request) = match context.protocol_version() {
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
        (HolderSubmission::V2(submission), Request::V2(request)) => SubmissionData::V2 {
            request,
            submission,
            dcql_query: params.dcql_query,
        },
    };

    let interaction_data =
        transport.interaction_data_from_submission(context, nonce, submission_data)?;

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
        .error_while("updating interaction")?;
    tracing::info!("{transport_type} verifier flow: finished, received proof submission");
    Ok(FlowState::Finished)
}

async fn get_request_v2(
    nonce: String,
    params: &AsyncVerifierFlowParams,
    auth_fn: AuthenticationFn,
) -> Result<(String, AuthorizationRequest), VerificationProtocolError> {
    let request = AuthorizationRequest {
        nonce: Some(nonce),
        response_type: None,
        response_mode: None,
        response_uri: None,
        client_id: params.verifier.client_id(),
        dcql_query: params.dcql_query.clone(),
        redirect_uri: None,
        verifier_info: vec![],
        state: None,
        client_metadata: None,
        transaction_data: vec![],
    };
    let signed_request = request_as_signed_jwt(request.clone(), &params.verifier, auth_fn).await?;
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
    proof_repository
        .update_proof(
            id,
            UpdateProofRequest {
                state: Some(state),
                ..Default::default()
            },
            error_metadata,
        )
        .await
        .error_while("updating proof")?;
    Ok(())
}

pub(super) async fn request_as_signed_jwt<T: Serialize>(
    params: T,
    verifier: &VerifierIdentifier,
    auth_fn: AuthenticationFn,
) -> Result<String, VerificationProtocolError> {
    let (key_id, public_key_info, issuer) = match verifier {
        VerifierIdentifier::Did(did) => (auth_fn.get_key_id(), None, Some(did.to_string())),
        VerifierIdentifier::Certificate { x5c, .. } => {
            (None, Some(JwtPublicKeyInfo::X5c(x5c.to_owned())), None)
        }
    };
    let unsigned_jwt = Jwt::new(
        "oauth-authz-req+jwt".to_string(),
        auth_fn.jose_alg().error_while("getting JOSE algorithm")?,
        key_id,
        public_key_info,
        JWTPayload {
            issued_at: None,
            expires_at: Some(crate::clock::now_utc().add(Duration::hours(1))),
            invalid_before: None,
            issuer,
            subject: None,
            audience: None,
            jwt_id: None,
            proof_of_possession_key: None,
            custom: params,
        },
    );
    Ok(unsigned_jwt
        .tokenize(Some(&*auth_fn))
        .await
        .error_while("creating request JWT")?)
}
