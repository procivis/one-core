use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::service::error::ServiceError;
use proc_macros::require_permissions;
use shared_types::HistoryId;

use super::dto::{GetHistoryQuery, HistoryResponseDetailRestDTO};
use crate::dto::common::{EntityResponseRestDTO, GetHistoryListResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::history::dto::CreateHistoryRequestRestDTO;
use crate::extractor::Qs;
use crate::permissions::Permission;
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
#[require_permissions(Permission::HistoryList)]
pub(crate) async fn get_history_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetHistoryQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetHistoryListResponseRestDTO> {
    let result = async {
        state
            .core
            .history_service
            .get_history_list(query.try_into()?)
            .await
    }
    .await;

    OkOrErrorResponse::from_result(result, state, "getting history list")
}

#[utoipa::path(
    post,
    path = "/api/history/v1",
    request_body = CreateHistoryRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "history_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create history event",
    description = indoc::formatdoc! {"
        Creates a new history entry managed outside core

        Related guide: [History](/history)
    "},
)]
#[require_permissions(Permission::HistoryCreate)]
pub(crate) async fn create_history(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateHistoryRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .history_service
        .create_history(request.into())
        .await;

    CreatedOrErrorResponse::from_result(result, state, "creating history")
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
#[require_permissions(Permission::HistoryDetail)]
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
