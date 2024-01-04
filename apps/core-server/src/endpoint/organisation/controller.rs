use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};

use crate::dto::response::{CreatedOrErrorResponse, OkOrErrorResponse};
use crate::router::AppState;
use uuid::Uuid;

use super::dto::{
    CreateOrganisationRequestRestDTO, CreateOrganisationResponseRestDTO,
    GetOrganisationDetailsResponseRestDTO,
};

#[utoipa::path(
    get,
    path = "/api/organisation/v1/{id}",
    responses(OkOrErrorResponse<GetOrganisationDetailsResponseRestDTO>),
    params(
        ("id" = Uuid, Path, description = "Organisation id")
    ),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_organisation(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> OkOrErrorResponse<GetOrganisationDetailsResponseRestDTO> {
    let result = state.core.organisation_service.get_organisation(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting organisation details")
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
    responses(CreatedOrErrorResponse<CreateOrganisationResponseRestDTO>),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_organisation(
    state: State<AppState>,
    request: Option<Json<CreateOrganisationRequestRestDTO>>,
) -> CreatedOrErrorResponse<CreateOrganisationResponseRestDTO> {
    let Json(request): Json<CreateOrganisationRequestRestDTO> =
        request.unwrap_or(Json(CreateOrganisationRequestRestDTO {
            id: Some(Uuid::new_v4()),
        }));

    let result = state
        .core
        .organisation_service
        .create_organisation(request.id)
        .await;
    CreatedOrErrorResponse::from_result(result, state, "creating organisation")
}
