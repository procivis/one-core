use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use proc_macros::require_permissions;
use uuid::Uuid;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse};
use crate::endpoint::signature::dto::{
    CreateSignatureRequestRestDTO, CreateSignatureResponseRestDTO,
};
use crate::permissions::Permission;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/signature/v1",
    request_body = CreateSignatureRequestRestDTO,
    responses(CreatedOrErrorResponse<CreateSignatureResponseRestDTO>),
    tag = "signature",
    security(
        ("bearer" = [])
    ),
    summary = "Create a signature",
    description = indoc::formatdoc! {"
    Creates signature.

    The `signer` value must reference a specific signature provider
    configured in your system.
"},
)]
#[require_permissions(Permission::RegistrationCertificateCreate)]
pub(crate) async fn create_signature(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateSignatureRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<CreateSignatureResponseRestDTO> {
    let result = state.core.signature_service.sign(request.into()).await;
    CreatedOrErrorResponse::from_result(result, state, "creating signature")
}

#[utoipa::path(
    post,
    path = "/api/signature/v1/{id}/revoke",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = Uuid, Path, description = "Signature id")
    ),
    tag = "signature",
    security(
        ("bearer" = [])
    ),
    summary = "Revoke a signature",
    description = indoc::formatdoc! {"
    Revokes a previously-created signature.
"},
)]
#[require_permissions(Permission::RegistrationCertificateRevoke)]
pub(crate) async fn revoke_signature(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<Uuid>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state.core.signature_service.revoke(id).await;
    EmptyOrErrorResponse::from_result(result, state, "revoking signature")
}
