use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use one_core::data_layer::DataLayerError;

use uuid::Uuid;

use crate::data_model::GetOrganisationDetailsResponseDTO;
use crate::AppState;
#[utoipa::path(
    get,
    path = "/api/organisation/v1/{id}",
    responses(
        (status = 200, description = "OK", body = GetOrganisationDetailsResponseDTO),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Organisation not found"),
        (status = 500, description = "Server error"),
    ),
    params(
        ("id" = Uuid, Path, description = "Organisation id")
    ),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_organisation_details(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    let result = state
        .core
        .data_layer
        .get_organisation_details(&id.to_string())
        .await;

    match result {
        Err(error) => match error {
            DataLayerError::RecordNotFound => (StatusCode::NOT_FOUND).into_response(),
            _ => {
                tracing::error!("Error while getting organisation details: {:?}", error);
                (StatusCode::INTERNAL_SERVER_ERROR).into_response()
            }
        },
        Ok(value) => (
            StatusCode::OK,
            Json(GetOrganisationDetailsResponseDTO::from(value)),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/organisation/v1",
    responses(
        (status = 200, description = "OK", body = Vec<GetOrganisationDetailsResponseDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Server error"),
    ),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_organisations(state: State<AppState>) -> Response {
    let result = state.core.data_layer.get_organisations().await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting organisation details: {:?}", error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (
            StatusCode::OK,
            Json(
                value
                    .into_iter()
                    .map(|org| org.into())
                    .collect::<Vec<GetOrganisationDetailsResponseDTO>>(),
            ),
        )
            .into_response(),
    }
}
