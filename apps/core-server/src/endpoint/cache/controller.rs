use axum::extract::State;
use axum::response::IntoResponse;
use axum_extra::extract::WithRejection;
use one_dto_mapper::convert_inner;

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::EmptyOrErrorResponse;
use crate::endpoint::cache::dto::DeleteCacheQuery;
use crate::extractor::QsOpt;
use crate::router::AppState;

#[utoipa::path(
    delete,
    path = "/api/cache/v1",
    params(DeleteCacheQuery),
    responses(EmptyOrErrorResponse),
    security(
        ("bearer" = [])
    ),
    tag = "cache",
    summary = "Prune cache",
    description = "Removes cached entities. If types are not specified, all cached entities are pruned.",
)]
#[axum::debug_handler]
pub(crate) async fn prune_cache(
    state: State<AppState>,
    WithRejection(QsOpt(query), _): WithRejection<QsOpt<DeleteCacheQuery>, ErrorResponseRestDTO>,
) -> impl IntoResponse {
    let result = state
        .core
        .cache_service
        .prune_cache(query.types.map(convert_inner))
        .await;
    EmptyOrErrorResponse::from_result(result, state, "pruning cache")
}
