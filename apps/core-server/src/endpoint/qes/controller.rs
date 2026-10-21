use axum::Json;
use axum::extract::State;
use axum_extra::extract::WithRejection;
use proc_macros::endpoint;
use shared_types::Permission;

use super::dto::{
    QesAuthorizeRequestRestDTO, QesAuthorizeResponseRestDTO, QesSignRequestRestDTO,
    QesSignResponseRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::CreatedOrErrorResponse;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::QesDocumentSign],
    post,
    path = "/api/qes/v1/authorize",
    request_body = QesAuthorizeRequestRestDTO,
    tag = "qes",
    security(
        ("bearer" = [])
    ),
    summary = "Authorize a document signature",
    description = indoc::formatdoc! {"
    Initiates the QES signing flow for a document with a configured QES provider.
    Returns an `authorizationUrl` for the user to authenticate with the provider,
    and a `codeVerifier` to be passed to `/api/qes/v1/sign` on return.
"},
)]
pub(crate) async fn authorize(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<QesAuthorizeRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<QesAuthorizeResponseRestDTO> {
    let result = async { state.core.qes_service.authorize(request.try_into()?).await }.await;
    CreatedOrErrorResponse::from_result(result, state, "creating qes authorization")
}

#[endpoint(
    permissions = [Permission::QesDocumentSign],
    post,
    path = "/api/qes/v1/sign",
    request_body = QesSignRequestRestDTO,
    tag = "qes",
    security(
        ("bearer" = [])
    ),
    summary = "Sign a document",
    description = indoc::formatdoc! {"
    Completes the QES signing flow. Exchanges the authorization `code` received
    from the provider redirect and the `codeVerifier` from `/api/qes/v1/authorize`
    for a signed document.
"},
)]
pub(crate) async fn sign(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<QesSignRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<QesSignResponseRestDTO> {
    let result = async {
        let response = state.core.qes_service.sign(request.try_into()?).await?;
        QesSignResponseRestDTO::try_from(response)
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "signing document")
}
