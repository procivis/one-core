use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use one_core::data_layer::DataLayerError;

use crate::data_model::{CreateDidRequest, CreateDidResponse};
use crate::AppState;

#[utoipa::path(
    post,
    path = "/tmp/did/v1",
    request_body = Option<CreateDidRequest>,
    responses(
        (status = 201, description = "Created", body = CreateDidResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "tmp",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_did(
    state: State<AppState>,
    Json(request): Json<CreateDidRequest>,
) -> Response {
    let result = state.core.data_layer.create_did(request.into()).await;

    match result {
        Err(DataLayerError::AlreadyExists) => {
            tracing::error!("Organisation already exists");
            StatusCode::CONFLICT.into_response()
        }
        Err(e) => {
            tracing::error!("Error while getting credential: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (
            StatusCode::CREATED,
            Json(CreateDidResponse { id: value.id }),
        )
            .into_response(),
    }
}
