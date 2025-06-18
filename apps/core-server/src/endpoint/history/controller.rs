use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::service::error::ServiceError;
use shared_types::HistoryId;

use super::dto::{GetHistoryQuery, HistoryResponseDetailRestDTO};
use crate::dto::common::GetHistoryListResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/history/v1",
    responses(OkOrErrorResponse<GetHistoryListResponseRestDTO>),
    params(GetHistoryQuery),
    tag = "history_management",
    security(
        ("bearer" = [])
    ),
    summary = "List history events",
    description = indoc::formatdoc! {"
        Returns a list of history events for entities in the system.

        Related guide: [History](/history)
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
    responses(OkOrErrorResponse<HistoryResponseDetailRestDTO>),
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
) -> OkOrErrorResponse<HistoryResponseDetailRestDTO> {
    let result = state.core.history_service.get_history_entry(id).await;
    match result {
        Ok(value) => match HistoryResponseDetailRestDTO::try_from(value) {
            Ok(value) => OkOrErrorResponse::ok(value),
            Err(error) => {
                tracing::error!("Error while mapping response: {:?}", error);
                OkOrErrorResponse::from_service_error(
                    ServiceError::MappingError(error.to_string()),
                    state.config.hide_error_response_cause,
                )
            }
        },
        Err(error) => {
            tracing::error!("Error while getting history entry: {:?}", error);
            OkOrErrorResponse::from_service_error(error, state.config.hide_error_response_cause)
        }
    }
}
