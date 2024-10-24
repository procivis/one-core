use axum::extract::State;
use axum_extra::extract::WithRejection;

use super::dto::ResolveJsonLDContextQuery;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::endpoint::jsonld::dto::ResolveJsonLDContextResponseRestDTO;
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/jsonld-context/v1",
    params(ResolveJsonLDContextQuery),
    responses(OkOrErrorResponse<ResolveJsonLDContextResponseRestDTO>),
    tag = "jsonld",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve JSON-lD context",
    description = "Returns the context of a JSON-LD credential. This is a [cached entity](/api/caching).",
)]
pub(crate) async fn resolve_jsonld_context(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<ResolveJsonLDContextQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<ResolveJsonLDContextResponseRestDTO> {
    let result = state
        .core
        .jsonld_service
        .resolve_context(query.url)
        .await
        .map(|context| ResolveJsonLDContextResponseRestDTO { context });
    OkOrErrorResponse::from_result(result, state, "resolving jsonld context")
}
