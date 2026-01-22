use axum::Json;
use axum::extract::State;
use axum_extra::extract::WithRejection;
use proc_macros::require_permissions;
use shared_types::Permission;

use super::dto::{
    ContinueIssuanceRequestRestDTO, ContinueIssuanceResponseRestDTO,
    HandleInvitationRequestRestDTO, HandleInvitationResponseRestDTO, IssuanceAcceptRequestRestDTO,
    IssuanceRejectRequestRestDTO, PresentationRejectRequestRestDTO,
    PresentationSubmitRequestRestDTO, PresentationSubmitV2RequestRestDTO,
    ProposeProofRequestRestDTO,
};
use crate::dto::common::EntityResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::interaction::dto::{
    InitiateIssuanceRequestRestDTO, InitiateIssuanceResponseRestDTO, ProposeProofResponseRestDTO,
};
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/interaction/v1/handle-invitation",
    request_body = HandleInvitationRequestRestDTO,
    responses(CreatedOrErrorResponse<HandleInvitationResponseRestDTO>),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
    summary = "Handle invitation",
    description = indoc::formatdoc! {"
        For a wallet, handles the interaction once the wallet connects to a share
        endpoint URL (for example, scans the QR code of an offered credential or
        request for proof).

        To start the wallet-initiated Authorization Code Flow request for issuance,
        use the [initiate-issuance](/reference/core/initiate-issuance) endpoint.
    "},
)]
#[require_permissions(Permission::InteractionIssuance, Permission::InteractionProof)]
pub(crate) async fn handle_invitation(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<HandleInvitationRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<HandleInvitationResponseRestDTO> {
    let result = async {
        state
            .core
            .ssi_holder_service
            .handle_invitation(
                request.url,
                fallback_organisation_id_from_session(request.organisation_id)?,
                request.transport,
                request.redirect_uri,
            )
            .await
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "handling invitation")
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/issuance-accept",
    request_body = IssuanceAcceptRequestRestDTO,
    responses(OkOrErrorResponse<EntityResponseRestDTO>),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
    summary = "Accept issuance",
    description = indoc::formatdoc! {"
        Accepts an offered credential. The system will generate a new
        identifier that matches issuer's restrictions. Alternatively,
        you can specify an existing identifier.

        `didId` is deprecated.
    "},
)]
#[require_permissions(Permission::InteractionIssuance)]
pub(crate) async fn issuance_accept(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<IssuanceAcceptRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .ssi_holder_service
        .accept_credential(
            request.interaction_id,
            request.did_id,
            request.identifier_id,
            request.key_id,
            request.tx_code,
            request.holder_wallet_unit_id,
        )
        .await;
    OkOrErrorResponse::from_result(result, state, "accepting credential")
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
#[require_permissions(Permission::InteractionIssuance)]
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
    description = "Rejects a request to submit credentials.",
)]
#[require_permissions(Permission::InteractionProof)]
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
    description = indoc::formatdoc! {"
        Submits a presentation in response to a request. Choose the
        identifier used to accept the credentials. This endpoint uses
          Presentation Exchange as the query language and should be used
          after \"Presentation Definition (V1)\".

        `didId` is deprecated.
    "},
)]
#[require_permissions(Permission::InteractionProof)]
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
    path = "/api/interaction/v2/presentation-submit",
    request_body = PresentationSubmitV2RequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
    summary = "Submit presentation",
    description = indoc::formatdoc! {"
        Submits a presentation in response to a request. This endpoint uses DCQL
        as a query language and should be used after \"Presentation Definition (V2)\".
    "},
)]
#[require_permissions(Permission::InteractionProof)]
pub(crate) async fn presentation_submit_v2(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<PresentationSubmitV2RequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .ssi_holder_service
        .submit_proof_v2(request.into())
        .await;
    EmptyOrErrorResponse::from_result(result, state, "submitting proof v2")
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
        Not for use via the API; this enables mobile wallets to initiate
        device engagement for offline flows. See the SDK.
    "},
)]
#[require_permissions(Permission::InteractionProof)]
pub(crate) async fn propose_proof(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<ProposeProofRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<ProposeProofResponseRestDTO> {
    let result = async {
        state
            .core
            .proof_service
            .propose_proof(request.try_into()?)
            .await
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "proposing proof")
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/initiate-issuance",
    request_body = InitiateIssuanceRequestRestDTO,
    responses(OkOrErrorResponse<InitiateIssuanceResponseRestDTO>),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
    summary = "Initiate OID4VCI issuance",
    description = indoc::formatdoc! {"
        For wallets, starts the OpenID4VCI Authorization Code Flow.
    "},
)]
#[require_permissions(Permission::InteractionIssuance)]
pub(crate) async fn initiate_issuance(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<InitiateIssuanceRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<InitiateIssuanceResponseRestDTO> {
    let result = async {
        state
            .core
            .ssi_holder_service
            .initiate_issuance(request.try_into()?)
            .await
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "initiating issuance")
}

#[utoipa::path(
    post,
    path = "/api/interaction/v1/continue-issuance",
    request_body = ContinueIssuanceRequestRestDTO,
    responses(CreatedOrErrorResponse<ContinueIssuanceResponseRestDTO>),
    tag = "interaction",
    security(
        ("bearer" = [])
    ),
    summary = "Continue OID4VCI issuance",
    description = indoc::formatdoc! {"
        For wallet-initiated flows, continues the OpenID4VCI issuance process after
        completing authorization.
    "},
)]
#[require_permissions(Permission::InteractionIssuance)]
pub(crate) async fn continue_issuance(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<ContinueIssuanceRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<ContinueIssuanceResponseRestDTO> {
    let result = state
        .core
        .ssi_holder_service
        .continue_issuance(request.url)
        .await;
    OkOrErrorResponse::from_result(result, state, "continue issuance")
}
