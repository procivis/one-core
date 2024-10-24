use axum::extract::State;
use axum::Json;
use axum_extra::extract::WithRejection;

use super::dto::{
    HandleInvitationRequestRestDTO, HandleInvitationResponseRestDTO, IssuanceAcceptRequestRestDTO,
    IssuanceRejectRequestRestDTO, PresentationRejectRequestRestDTO,
    PresentationSubmitRequestRestDTO, ProposeProofRequestRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::interaction::dto::ProposeProofResponseRestDTO;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/interaction/v1/handle-invitation",
    request_body = HandleInvitationRequestRestDTO,
    responses(OkOrErrorResponse<HandleInvitationResponseRestDTO>),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
    summary = "Handle invitation",
    description = indoc::formatdoc! {"
        For a wallet, handles the interaction once the wallet connects to a share endpoint url
        (e.g. scans the QR code of an offered credential or request for proof).
    "},
)]
pub(crate) async fn handle_invitation(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<HandleInvitationRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<HandleInvitationResponseRestDTO> {
    let result = state
        .core
        .ssi_holder_service
        .handle_invitation(request.url, request.organisation_id, request.transport)
        .await;
    OkOrErrorResponse::from_result(result, state, "handling invitation")
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/issuance-accept",
    request_body = IssuanceAcceptRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
    summary = "Accept issuance",
    description = indoc::formatdoc! {"
        Accepts an offered credential. The associated DID will be listed as the
        subject of the issued credential.
    "},
)]
pub(crate) async fn issuance_accept(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<IssuanceAcceptRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_holder_service
        .accept_credential(&request.interaction_id, request.did_id, request.key_id)
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
    summary = "Reject issuance",
    description = "Rejects an offered credential.",
)]
pub(crate) async fn issuance_reject(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<IssuanceRejectRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
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
    summary = "Reject presentation",
    description = "For a wallet, rejects a request to submit credentials to a verifier.",
)]
pub(crate) async fn presentation_reject(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<PresentationRejectRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
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
    summary = "Submit presentation",
    description = "Submits a presentation to a verifier.",
)]
pub(crate) async fn presentation_submit(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<PresentationSubmitRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_holder_service
        .submit_proof(request.into())
        .await;
    EmptyOrErrorResponse::from_result(result, state, "submitting proof")
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/propose-proof",
    request_body = ProposeProofRequestRestDTO,
    responses(CreatedOrErrorResponse<ProposeProofResponseRestDTO>),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
    summary = "Propose a proof",
    description = indoc::formatdoc! {"
        For digital wallets, creates an engagement QR code which can be scanned by a
        mobile verifier to establish a Bluetooth Low Energy connection. See the [SDK](/sdk/propose_proof).
    "},
)]
pub(crate) async fn propose_proof(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<ProposeProofRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<ProposeProofResponseRestDTO> {
    let result = state
        .core
        .proof_service
        .propose_proof(request.exchange, request.organisation_id)
        .await;
    CreatedOrErrorResponse::from_result(result, state, "proposing proof")
}
