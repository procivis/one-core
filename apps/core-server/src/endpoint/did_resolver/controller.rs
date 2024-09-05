use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::service::error::ServiceError;
use shared_types::DidValue;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::endpoint::ssi::dto::DidDocumentRestDTO;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/did-resolver/v1/{didvalue}",
    params(
        ("didvalue" = DidValue, Path, description = "DID value")
    ),
    responses(OkOrErrorResponse<DidDocumentRestDTO>),
    tag = "did_resolver",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn resolve_did(
    state: State<AppState>,
    WithRejection(Path(did_value), _): WithRejection<Path<DidValue>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<DidDocumentRestDTO> {
    let result = state
        .core
        .did_service
        .resolve_did(&did_value)
        .await
        .map_err(ServiceError::from);
    OkOrErrorResponse::from_result(result, state, "resolving did document")
}
