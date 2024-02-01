use axum::extract::State;
use axum_extra::extract::WithRejection;

use crate::{
    dto::{
        common::GetHistoryListResponseRestDTO,
        error::ErrorResponseRestDTO,
        response::{declare_utoipa_alias, AliasResponse, OkOrErrorResponse},
    },
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
    match query.try_into() {
        Ok(query) => {
            let result = state.core.history_service.get_history_list(query).await;

            OkOrErrorResponse::from_result(result, state, "getting history list")
        }
        Err(error) => {
            OkOrErrorResponse::from_service_error(error, state.config.hide_error_response_cause)
        }
    }
}
