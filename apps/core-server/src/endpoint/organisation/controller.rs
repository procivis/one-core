use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use crate::router::AppState;
use one_core::service::error::ServiceError;
use uuid::Uuid;

use super::dto::{
    CreateOrganisationRequestRestDTO, CreateOrganisationResponseRestDTO,
    GetOrganisationDetailsResponseRestDTO,
};

#[utoipa::path(
    get,
    path = "/api/organisation/v1/{id}",
    responses(
        (status = 200, description = "OK", body = GetOrganisationDetailsResponseRestDTO),
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
pub(crate) async fn get_organisation(state: State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = state.core.organisation_service.get_organisation(&id).await;

    match result {
        Err(error) => match error {
            ServiceError::NotFound => (StatusCode::NOT_FOUND).into_response(),
            _ => {
                tracing::error!("Error while getting organisation details: {:?}", error);
                (StatusCode::INTERNAL_SERVER_ERROR).into_response()
            }
        },
        Ok(value) => (
            StatusCode::OK,
            Json(GetOrganisationDetailsResponseRestDTO::from(value)),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/organisation/v1",
    responses(
        (status = 200, description = "OK", body = Vec<GetOrganisationDetailsResponseRestDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Server error"),
    ),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_organisations(state: State<AppState>) -> Response {
    let result = state
        .core
        .organisation_service
        .get_organisation_list()
        .await;

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
                    .collect::<Vec<GetOrganisationDetailsResponseRestDTO>>(),
            ),
        )
            .into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/api/organisation/v1",
    request_body = Option<CreateOrganisationRequestRestDTO>,
    responses(
        (status = 201, description = "Created", body = CreateOrganisationResponseRestDTO),
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
    request: Option<Json<CreateOrganisationRequestRestDTO>>,
) -> Response {
    let Json(request): Json<CreateOrganisationRequestRestDTO> =
        request.unwrap_or(Json(CreateOrganisationRequestRestDTO {
            id: Some(Uuid::new_v4()),
        }));

    let result = state
        .core
        .organisation_service
        .create_organisation(request.id)
        .await;

    match result {
        Err(ServiceError::AlreadyExists) => {
            tracing::error!("Organisation already exists");
            StatusCode::CONFLICT.into_response()
        }
        Err(e) => {
            tracing::error!("Error while creating organisation: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (
            StatusCode::CREATED,
            Json(CreateOrganisationResponseRestDTO::from(value)),
        )
            .into_response(),
    }
}
