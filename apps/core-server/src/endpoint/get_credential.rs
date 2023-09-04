use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use uuid::Uuid;

use one_core::repository::error::DataLayerError;

use crate::data_model::{DetailCredentialResponseDTO, GetCredentialQuery};
use crate::dto::common::GetCredentialsResponseDTO;
use crate::AppState;

#[utoipa::path(
    get,
    path = "/api/credential/v1/{id}",
    responses(
        (status = 200, description = "OK", body = DetailCredentialResponseDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential not found"),
    ),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential_details(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    let result = state
        .core
        .data_layer
        .get_credential_details(&id.to_string())
        .await;

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(DetailCredentialResponseDTO::from(value)),
        )
            .into_response(),
        Err(error) => match error {
            DataLayerError::RecordNotFound => StatusCode::NOT_FOUND.into_response(),
            _ => {
                tracing::error!("Error while getting credential");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

#[utoipa::path(
    get,
    path = "/api/credential/v1",
    responses(
        (status = 200, description = "OK", body = GetCredentialsResponseDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Credential not found"),
    ),
    params(
        GetCredentialQuery
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credentials(
    state: State<AppState>,
    Query(query): Query<GetCredentialQuery>,
) -> Response {
    let result = state.core.data_layer.get_credentials(query.into()).await;

    match result {
        Ok(value) => (StatusCode::OK, Json(GetCredentialsResponseDTO::from(value))).into_response(),
        Err(error) => match error {
            DataLayerError::RecordNotFound => StatusCode::NOT_FOUND.into_response(),
            _ => {
                tracing::error!("Error while getting credential");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}
