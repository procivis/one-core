use axum::extract::{Path, State};
use axum::Json;

use crate::dto::response::{CreatedOrErrorResponse, OkOrErrorResponse, VecResponse};
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
    responses(OkOrErrorResponse<VecResponse<GetOrganisationDetailsResponseRestDTO>>),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_organisations(
    state: State<AppState>,
) -> OkOrErrorResponse<VecResponse<GetOrganisationDetailsResponseRestDTO>> {
    let result = state
        .core
        .organisation_service
        .get_organisation_list()
        .await;
    OkOrErrorResponse::from_result(result, state, "getting organisations")
}

//TODO Handle option
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
    // In this case fail turns into None.
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
