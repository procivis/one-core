use axum::extract::{Path, State};

use axum::http::StatusCode;

use one_core::data_layer::DataLayerError;

use uuid::Uuid;

use crate::AppState;

#[utoipa::path(
    delete,
    path = "/api/credential-schema/v1/{id}",
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Schema not found"),
        (status = 500, description = "Server error"),
    ),
    params(
        ("id" = Uuid, Path, description = "Schema id")
    ),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn delete_credential_schema(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> StatusCode {
    let result = state
        .core
        .data_layer
        .delete_credential_schema(&id.to_string())
        .await;

    if let Err(error) = result {
        return match error {
            DataLayerError::RecordNotFound => StatusCode::NOT_FOUND,
            DataLayerError::RecordNotUpdated => StatusCode::NOT_FOUND,
            _ => {
                tracing::error!("Error while deleting credential: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
    }

    StatusCode::NO_CONTENT
}
