use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use shared_types::HistoryId;

use super::dto::GetHistoryQuery;
use crate::dto::common::GetHistoryListResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::endpoint::history::dto::HistoryResponseRestDTO;
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/history/v1",
    responses(OkOrErrorResponse<GetHistoryListResponseRestDTO>),
    params(
        GetHistoryQuery
    ),
    tag = "history_management",
    security(
        ("bearer" = [])
    ),
    summary = "List history events",
    description = indoc::formatdoc! {"
        Returns a list of history events for entities in the system. Use the parameters
        to filter.
    "},
)]
pub(crate) async fn get_history_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetHistoryQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetHistoryListResponseRestDTO> {
    let result = state
        .core
        .history_service
        .get_history_list(query.into())
        .await;

    OkOrErrorResponse::from_result(result, state, "getting history list")
}

#[utoipa::path(
    get,
    path = "/api/history/v1/{id}",
    params(
        ("id" = HistoryId, Path, description = "History id")
    ),
    responses(OkOrErrorResponse<HistoryResponseRestDTO>),
    tag = "history_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve history entry",
    description = "Returns details on a single event.",
)]
pub(crate) async fn get_history_entry(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<HistoryId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<HistoryResponseRestDTO> {
    let result = state.core.history_service.get_history_entry(id).await;
    OkOrErrorResponse::from_result(result, state, "getting history entry")
}
