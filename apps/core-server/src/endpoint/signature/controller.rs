use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_dto_mapper::convert_inner;
use proc_macros::endpoint;
use shared_types::Permission;
use uuid::Uuid;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::signature::dto::{
    CreateSignatureRequestRestDTO, CreateSignatureResponseRestDTO,
    SignatureRevocationCheckRequestRestDTO, SignatureRevocationCheckResponseRestDTO,
};
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::AccessCertificateSign, Permission::RegistrationCertificateSign, Permission::X509CertificateSign, Permission::SwiyuProofOfPossessionSign],
    post,
    path = "/api/signature/v1",
    request_body = CreateSignatureRequestRestDTO,
    tag = "signature",
    security(
        ("bearer" = [])
    ),
    summary = "Create a signature",
    description = indoc::formatdoc! {"
    Signs a request with the specified signer and returns the result: an
    X.509 certificate chain, an Access Certificate, or a Registration
    Certificate. The structure of `data` depends on the signer; see
    [Signatures](https://docs.procivis.ch/signatures) for each signer's
    request data.

    The required permission depends on the signer. Store the returned `id`
    to revoke the signature or check its status later.
"},
)]
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

#[endpoint(
    permissions = [Permission::AccessCertificateRevoke, Permission::RegistrationCertificateRevoke, Permission::X509CertificateRevoke],
    post,
    path = "/api/signature/v1/{id}/revoke",
    params(
        ("id" = Uuid, Path, description = "Signature ID, as returned when the signature was created.")
    ),
    tag = "signature",
    security(
        ("bearer" = [])
    ),
    summary = "Revoke a signature",
    description = indoc::formatdoc! {"
    Revokes a signature created with this API. Fails if the signer that
    created it has no revocation method.

    The required permission depends on the signer that created the
    signature.
"},
)]
pub(crate) async fn revoke_signature(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<Uuid>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state.core.signature_service.revoke(id).await;
    EmptyOrErrorResponse::from_result(result, state, "revoking signature")
}

#[endpoint(
    permissions = [Permission::TaskCreate],
    post,
    path = "/api/signature/v1/revocation-check",
    request_body = SignatureRevocationCheckRequestRestDTO,
    tag = "signature",
    security(
        ("bearer" = [])
    ),
    summary = "Check signature status",
    description = indoc::formatdoc! {"
    Returns the current state of each specified signature, along with the
    name of the signer that created it. Signature IDs that are not found
    are omitted from the response.
"},
)]
pub(crate) async fn signature_revocation_check(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<SignatureRevocationCheckRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<SignatureRevocationCheckResponseRestDTO> {
    let result = state
        .core
        .signature_service
        .revocation_check(request.signature_ids)
        .await
        .map(|map| SignatureRevocationCheckResponseRestDTO {
            result: convert_inner(map),
        });
    OkOrErrorResponse::from_result(result, state, "signature revocation check")
}
