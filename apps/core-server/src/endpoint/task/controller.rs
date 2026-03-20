use axum::Json;
use axum::extract::State;
use axum_extra::extract::WithRejection;
use proc_macros::endpoint;
use shared_types::Permission;

use super::dto::{TaskRequestRestDTO, TaskResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::TaskCreate],
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
        Runs a task. Tasks can be also be run via the CLI after starting
        the core-server.

        Related guide: [Regular Tasks](https://docs.procivis.ch/reference/configuration/core#regular-tasks)
    "},
)]
pub(crate) async fn post_task(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<Json<TaskRequestRestDTO>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<TaskResponseRestDTO> {
    let result = state
        .core
        .task_service
        .run(&request.name.into(), request.params)
        .await;
    OkOrErrorResponse::from_result(
        result.map(|result| TaskResponseRestDTO { result }),
        state,
        "running task",
    )
}
