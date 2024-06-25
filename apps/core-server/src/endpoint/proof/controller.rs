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
use crate::dto::response::{
    declare_utoipa_alias, AliasResponse, CreatedOrErrorResponse, OkOrErrorResponse,
};
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
)]
pub(crate) async fn get_proof_details(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<ProofDetailResponseRestDTO> {
    let result = state.core.proof_service.get_proof(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting proof")
}

declare_utoipa_alias!(GetProofsResponseRestDTO);

#[utoipa::path(
    get,
    path = "/api/proof-request/v1",
    responses(OkOrErrorResponse<AliasResponse<GetProofsResponseRestDTO>>),
    params(GetProofQuery),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
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
)]
pub(crate) async fn share_proof(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<EntityShareResponseRestDTO> {
    let result = state.core.proof_service.share_proof(&id).await;
    OkOrErrorResponse::from_result(result, state, "sharing proof")
}
