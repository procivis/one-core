use axum::extract::{Path, State};
use axum::{Extension, Json};
use axum_extra::extract::WithRejection;
use one_core::proto::session_provider::SessionProvider;
use one_core::service::error::{ServiceError, ValidationError};
use proc_macros::require_permissions;
use shared_types::HistoryId;

use super::dto::{GetHistoryQuery, HistoryResponseDetailRestDTO};
use crate::dto::common::{Boolean, EntityResponseRestDTO, GetHistoryListResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::{CreatedOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::history::dto::CreateHistoryRequestRestDTO;
use crate::extractor::Qs;
use crate::middleware::Authorized;
use crate::permissions::{Permission, permission_check};
use crate::router::AppState;
use crate::session::CoreServerSessionProvider;

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
#[require_permissions(Permission::HistoryList, Permission::SystemHistoryList)]
pub(crate) async fn get_history_list(
    state: State<AppState>,
    Extension(authorization): Extension<Authorized>,
    WithRejection(Qs(mut query), _): WithRejection<Qs<GetHistoryQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetHistoryListResponseRestDTO> {
    let result =
        async {
            let show_system_history: bool = query
                .filter
                .show_system_history
                .unwrap_or(Boolean::False)
                .into();

            if show_system_history {
                if !has_permission(&authorization, &state, Permission::SystemHistoryList) {
                    tracing::error!("Querying system history list without permission");
                    return Err(ValidationError::Forbidden.into());
                }
            } else if let Some(organisation_ids) = &query.filter.organisation_ids {
                if let Some(session) = CoreServerSessionProvider.session() {
                    match (&session.organisation_id, organisation_ids.as_slice()) {
                        (Some(a), [b]) if a == b => {
                            // organisation id matches, proceed
                        }
                        _ => {
                            tracing::error!("Querying history list with wrong organisation filter");
                            return Err(ValidationError::Forbidden.into());
                        }
                    }
                }
            } else {
                query.filter.organisation_ids =
                    Some(vec![fallback_organisation_id_from_session(None)?]);
            }

            state
                .core
                .history_service
                .get_history_list(query.try_into().map_err(|e: std::convert::Infallible| {
                    ServiceError::MappingError(e.to_string())
                })?)
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
#[require_permissions(Permission::HistoryDetail, Permission::SystemHistoryDetail)]
pub(crate) async fn get_history_entry(
    state: State<AppState>,
    Extension(authorization): Extension<Authorized>,
    WithRejection(Path(id), _): WithRejection<Path<HistoryId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<HistoryResponseDetailRestDTO> {
    let result = async {
        let entry = state.core.history_service.get_history_entry(id).await?;

        if let Some(session) = CoreServerSessionProvider.session()
            && !has_permission(&authorization, &state, Permission::SystemHistoryDetail)
        {
            match (session.organisation_id, entry.organisation_id) {
                (Some(a), Some(b)) if a == b => {
                    // organisation id matches, proceed
                }
                _ => {
                    tracing::error!("Querying history entry without permission");
                    return Err(ValidationError::Forbidden.into());
                }
            }
        }

        HistoryResponseDetailRestDTO::try_from(entry)
            .map_err(|e| ServiceError::MappingError(e.to_string()))
    }
    .await;

    OkOrErrorResponse::from_result(result, state, "getting history entry")
}

fn has_permission(
    authorization: &Authorized,
    state: &State<AppState>,
    permission: Permission,
) -> bool {
    permission_check(authorization, &state.config, &[permission]).is_ok()
}
