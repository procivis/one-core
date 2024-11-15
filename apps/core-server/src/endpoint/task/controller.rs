use axum::extract::State;
use axum::Json;
use axum_extra::extract::WithRejection;

use super::dto::{TaskRequestRestDTO, TaskResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/task/v1/run",
    request_body = TaskRequestRestDTO,
    responses(OkOrErrorResponse<TaskResponseRestDTO>),
    tag = "task",
    security(
        ("bearer" = [])
    ),
    summary = "Run task",
    description = indoc::formatdoc! {"
        Runs a task. Typically tasks are run as part of a schedule via the CLI, but it is also possible to run them
        through this endpoint.
    "},
)]
pub(crate) async fn post_task(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<Json<TaskRequestRestDTO>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<TaskResponseRestDTO> {
    let result = state.core.task_service.run(&request.name).await;
    OkOrErrorResponse::from_result(
        result.map(|result| TaskResponseRestDTO { result }),
        state,
        "running task",
    )
}
