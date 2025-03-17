use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use shared_types::OrganisationId;

use super::dto::{
    CreateOrganisationRequestRestDTO, CreateOrganisationResponseRestDTO,
    GetOrganisationDetailsResponseRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, OkOrErrorResponse, VecResponse};
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/organisation/v1/{id}",
    responses(OkOrErrorResponse<GetOrganisationDetailsResponseRestDTO>),
    params(
        ("id" = OrganisationId, Path, description = "Organization id")
    ),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve organization",
    description = "Returns information on an organization",
)]
pub(crate) async fn get_organisation(
    state: State<AppState>,
    Path(id): Path<OrganisationId>,
) -> OkOrErrorResponse<GetOrganisationDetailsResponseRestDTO> {
    let result = state.core.organisation_service.get_organisation(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting organization details")
}

#[utoipa::path(
    get,
    path = "/api/organisation/v1",
    responses(OkOrErrorResponse<VecResponse<GetOrganisationDetailsResponseRestDTO>>),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
    summary = "List organizations",
    description = "Returns a list of organizations in the system.",
)]
pub(crate) async fn get_organisations(
    state: State<AppState>,
) -> OkOrErrorResponse<VecResponse<GetOrganisationDetailsResponseRestDTO>> {
    let result = state
        .core
        .organisation_service
        .get_organisation_list()
        .await;
    OkOrErrorResponse::from_result(result, state, "getting organizations")
}

#[utoipa::path(
    post,
    path = "/api/organisation/v1",
    request_body(
        content((Option<CreateOrganisationRequestRestDTO>)),
        example = json!({ "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "name": "default organisation" }),
    ),
    responses(CreatedOrErrorResponse<CreateOrganisationResponseRestDTO>),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create organization",
    description = indoc::formatdoc! {"
        Creates an organisation. All entities and transactions belong to one organisation. The system
        supports the creation of as many organisations as is needed.
    "},
)]
#[axum::debug_handler]
pub(crate) async fn post_organisation(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateOrganisationRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<CreateOrganisationResponseRestDTO> {
    let result = state
        .core
        .organisation_service
        .create_organisation(request.into())
        .await;
    CreatedOrErrorResponse::from_result(result, state, "creating organization")
}
