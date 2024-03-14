use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use shared_types::HistoryId;

use crate::{
    dto::{
        common::GetHistoryListResponseRestDTO,
        error::ErrorResponseRestDTO,
        response::{declare_utoipa_alias, AliasResponse, OkOrErrorResponse},
    },
    endpoint::history::dto::HistoryResponseRestDTO,
    extractor::Qs,
    router::AppState,
};

use super::dto::GetHistoryQuery;

declare_utoipa_alias!(GetHistoryListResponseRestDTO);

#[utoipa::path(
    get,
    path = "/api/history/v1",
    responses(OkOrErrorResponse<AliasResponse<GetHistoryListResponseRestDTO>>),
    params(
        GetHistoryQuery
    ),
    tag = "history_management",
    security(
        ("bearer" = [])
    ),
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
        ("id" = Uuid, Path, description = "History id")
    ),
    responses(OkOrErrorResponse<HistoryResponseRestDTO>),
    tag = "history_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_history_entry(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<HistoryId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<HistoryResponseRestDTO> {
    let result = state.core.history_service.get_history_entry(id).await;
    OkOrErrorResponse::from_result(result, state, "getting history entry")
}
