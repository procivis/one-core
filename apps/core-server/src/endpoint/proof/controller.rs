use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use shared_types::ProofId;

use super::dto::{
    CreateProofRequestRestDTO, GetProofQuery, PresentationDefinitionResponseRestDTO,
    ProofDetailResponseRestDTO,
};
use crate::dto::common::{
    EntityResponseRestDTO, EntityShareResponseRestDTO, GetProofsResponseRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/proof-request/v1/{id}/presentation-definition",
    responses(OkOrErrorResponse<PresentationDefinitionResponseRestDTO>),
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve presentation definition",
    description = indoc::formatdoc! {"
        For wallets; after a wallet connects to a verifier's request for proof via the [Handle Invitation](/core/handle-invitation)
        endpoint, the presentation definition endpoint takes the resulting `proofId` and filters the wallet, returning credentials which match the verifier's request.
    "},
)]
pub(crate) async fn get_proof_presentation_definition(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<PresentationDefinitionResponseRestDTO> {
    let result = state
        .core
        .proof_service
        .get_proof_presentation_definition(&id)
        .await;
    OkOrErrorResponse::from_result(result, state, "getting presentation definition")
}

#[utoipa::path(
    get,
    path = "/api/proof-request/v1/{id}",
    responses(OkOrErrorResponse<ProofDetailResponseRestDTO>),
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve a proof request",
    description = "Returns detailed information on a proof request.",
)]
pub(crate) async fn get_proof_details(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<ProofDetailResponseRestDTO> {
    let result = state.core.proof_service.get_proof(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting proof")
}

#[utoipa::path(
    get,
    path = "/api/proof-request/v1",
    responses(OkOrErrorResponse<GetProofsResponseRestDTO>),
    params(GetProofQuery),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "List proof requests",
    description = "Returns a list of proof requests in an organization.",
)]
pub(crate) async fn get_proofs(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetProofQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetProofsResponseRestDTO> {
    let result = state.core.proof_service.get_proof_list(query.into()).await;
    OkOrErrorResponse::from_result(result, state, "getting proofs")
}

#[utoipa::path(
    post,
    path = "/api/proof-request/v1",
    request_body = CreateProofRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create a proof request",
    description = "Creates a proof request, which can then be shared with a wallet holder.",
)]
pub(crate) async fn post_proof(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateProofRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state.core.proof_service.create_proof(request.into()).await;
    CreatedOrErrorResponse::from_result(result, state, "creating proof")
}

#[utoipa::path(
    post,
    path = "/api/proof-request/v1/{id}/share",
    responses(OkOrErrorResponse<EntityShareResponseRestDTO>),
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Request a proof",
    description = "Creates a share endpoint URL from a proof request. A wallet holder can use this URL to access the proof request.",
)]
pub(crate) async fn share_proof(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<EntityShareResponseRestDTO> {
    let result = state.core.proof_service.share_proof(&id).await;
    OkOrErrorResponse::from_result(result, state, "sharing proof")
}

#[utoipa::path(
    post,
    path = "/api/proof-request/v1/{id}/retract",
    responses(OkOrErrorResponse<EntityResponseRestDTO>),
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retract a proof request",
    description = indoc::formatdoc! {"
        Retracts a proof request. For those proof requests still in `PENDING` or `REQUESTED`, use this endpoint to
        retract the request, effectively renewing it. This is helpful for preventing the creation of excess proof requests
        during verification workflows. See the [proof request states](/api/resources/proof_requests#proof-request-states) guide.
    "},
)]
pub(crate) async fn retract_proof(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .proof_service
        .retract_proof(id)
        .await
        .map(|id| EntityResponseRestDTO { id: id.into() });

    OkOrErrorResponse::from_result(result, state, " retracting proof")
}

#[utoipa::path(
    delete,
    path = "/api/proof-request/v1/{id}/claims",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Delete proof claims",
    description = "",
)]
pub(crate) async fn delete_proof_claims(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state.core.proof_service.delete_proof_claims(id).await;
    EmptyOrErrorResponse::from_result(result, state, " deleting proof claims")
}
