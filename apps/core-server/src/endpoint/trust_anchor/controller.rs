use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use shared_types::TrustAnchorId;

use crate::dto::common::{EntityResponseRestDTO, GetTrustAnchorListResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::trust_anchor::dto::{
    CreateTrustAnchorRequestRestDTO, GetTrustAnchorResponseRestDTO, ListTrustAnchorsQuery,
};
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/trust-anchor/v1",
    request_body = CreateTrustAnchorRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "trust_anchor",
    security(
        ("bearer" = [])
    ),
    summary = "Add a trust anchor",
    description = indoc::formatdoc! {"
    Publishes a new trust anchor or subscribes to an existing trust anchor.

    The `type` value must reference specific configuration instances from
    your system configuration. This is because the system allows multiple
    configurations of the same type.
"},
)]
pub(crate) async fn create_trust_anchor(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateTrustAnchorRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .trust_anchor_service
        .create_trust_anchor(request.into())
        .await;
    CreatedOrErrorResponse::from_result(result, state, "creating trust anchor")
}

#[utoipa::path(
    get,
    path = "/api/trust-anchor/v1/{id}",
    params(
        ("id" = TrustAnchorId, Path, description = "Trust anchor id")
    ),
    responses(OkOrErrorResponse<GetTrustAnchorResponseRestDTO>),
    tag = "trust_anchor",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve a trust anchor",
    description = "Returns details on a given trust anchor.",
)]
pub(crate) async fn get_trust_anchor(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustAnchorId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetTrustAnchorResponseRestDTO> {
    let result = state.core.trust_anchor_service.get_trust_anchor(id).await;
    OkOrErrorResponse::from_result(result, state, "fetching trust anchor")
}

#[utoipa::path(
    get,
    path = "/api/trust-anchor/v1",
    responses(OkOrErrorResponse<GetTrustAnchorListResponseRestDTO>),
    params(ListTrustAnchorsQuery),
    tag = "trust_anchor",
    security(
        ("bearer" = [])
    ),
    summary = "List trust anchors",
    description = "Returns a list of trust anchors in an organization. See the [filtering](/reference/api/filtering) guide for handling list endpoints.",
)]
pub(crate) async fn get_trust_anchors(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<ListTrustAnchorsQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetTrustAnchorListResponseRestDTO> {
    let result = state
        .core
        .trust_anchor_service
        .list_trust_anchors(query.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "listing trust anchors")
}

#[utoipa::path(
    delete,
    path = "/api/trust-anchor/v1/{id}",
    params(
        ("id" = TrustAnchorId, Path, description = "Trust anchor id")
    ),
    responses(EmptyOrErrorResponse),
    tag = "trust_anchor",
    security(
        ("bearer" = [])
    ),
    summary = "Delete a trust anchor",
    description = indoc::formatdoc! {"
        Deletes a trust anchor. All trust entities on the deleted trust anchor
        are also deleted.
    "},
)]
pub(crate) async fn delete_trust_anchor(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustAnchorId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .trust_anchor_service
        .delete_trust_anchor(id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "deleting trust anchor")
}
