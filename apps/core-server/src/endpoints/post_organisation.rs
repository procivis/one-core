use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use one_core::data_layer::DataLayerError;

use uuid::Uuid;

use crate::data_model::{CreateOrganisationRequestDTO, CreateOrganisationResponseDTO};
use crate::AppState;

#[utoipa::path(
    post,
    path = "/api/organisation/v1",
    request_body = Option<CreateOrganisationRequestDTO>,
    responses(
        (status = 201, description = "Created", body = CreateOrganisationResponseDTO),
        (status = 409, description = "Organisation already exists"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_organisation(
    state: State<AppState>,
    request: Option<Json<CreateOrganisationRequestDTO>>,
) -> Response {
    let Json(request): Json<CreateOrganisationRequestDTO> =
        request.unwrap_or(Json(CreateOrganisationRequestDTO {
            id: Some(Uuid::new_v4()),
        }));

    let result = state
        .core
        .data_layer
        .create_organisation(request.into())
        .await;

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
            Json(CreateOrganisationResponseDTO::from(value)),
        )
            .into_response(),
    }
}
