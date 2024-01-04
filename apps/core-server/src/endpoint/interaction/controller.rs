use super::dto::{
    HandleInvitationRequestRestDTO, HandleInvitationResponseRestDTO, IssuanceRejectRequestRestDTO,
    IssuanceSubmitRequestRestDTO, PresentationRejectRequestRestDTO,
    PresentationSubmitRequestRestDTO,
};
use crate::{
    dto::response::{EmptyOrErrorResponse, OkOrErrorResponse},
    router::AppState,
};
use axum::{extract::State, Json};

#[utoipa::path(
    post,
    path = "/api/interaction/v1/handle-invitation",
    request_body = HandleInvitationRequestRestDTO,
    responses(OkOrErrorResponse<HandleInvitationResponseRestDTO>),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn handle_invitation(
    state: State<AppState>,
    Json(request): Json<HandleInvitationRequestRestDTO>,
) -> OkOrErrorResponse<HandleInvitationResponseRestDTO> {
    let result = state
        .core
        .ssi_holder_service
        .handle_invitation(request.url, &request.did_id)
        .await;
    OkOrErrorResponse::from_result(result, state, "handling invitation")
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/issuance-submit",
    request_body = IssuanceSubmitRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn issuance_submit(
    state: State<AppState>,
    Json(request): Json<IssuanceSubmitRequestRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_holder_service
        .accept_credential(&request.interaction_id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "accepting credential")
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/issuance-reject",
    request_body = IssuanceRejectRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn issuance_reject(
    state: State<AppState>,
    Json(request): Json<IssuanceRejectRequestRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_holder_service
        .reject_credential(&request.interaction_id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "rejecting credential")
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/presentation-reject",
    request_body = PresentationRejectRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn presentation_reject(
    state: State<AppState>,
    Json(request): Json<PresentationRejectRequestRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_holder_service
        .reject_proof_request(&request.interaction_id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "rejecting proof request")
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/presentation-submit",
    request_body = PresentationSubmitRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn presentation_submit(
    state: State<AppState>,
    Json(request): Json<PresentationSubmitRequestRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_holder_service
        .submit_proof(request.into())
        .await;
    EmptyOrErrorResponse::from_result(result, state, "submitting proof")
}
