use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_dto_mapper::convert_inner;
use proc_macros::require_permissions;
use shared_types::OrganisationId;

use super::dto::{
    CreateOrganisationRequestRestDTO, CreateOrganisationResponseRestDTO,
    GetOrganisationDetailsResponseRestDTO, GetOrganisationsQuery, UpsertOrganisationRequestRestDTO,
};
use crate::dto::common::GetOrganisationListResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::organisation::mapper::upsert_request_from_request;
use crate::extractor::Qs;
use crate::permissions::Permission;
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
    description = "Returns information about an organization.",
)]
#[require_permissions(Permission::StsOrganisationDetail)]
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
    responses(OkOrErrorResponse<GetOrganisationListResponseRestDTO>),
    params(GetOrganisationsQuery),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
    summary = "List organizations",
    description = "Returns a list of organizations in the system.",
)]
#[require_permissions(Permission::StsOrganisationList)]
pub(crate) async fn get_organisations(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetOrganisationsQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetOrganisationListResponseRestDTO> {
    let result = async {
        state
            .core
            .organisation_service
            .get_organisation_list(query.try_into()?)
            .await
    }
    .await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting organisation list: {:?}", error);
            OkOrErrorResponse::from_service_error(error, state.config.hide_error_response_cause)
        }
        Ok(value) => OkOrErrorResponse::Ok(GetOrganisationListResponseRestDTO {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }),
    }
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
        Creates an organization. If no UUID is passed, one will be created.
        If no name is passed, the UUID will be used.

        All entities and transactions belong to one organization. The system
        supports the creation of as many organizations as is needed.
    "},
)]
#[require_permissions(Permission::StsOrganisationCreate)]
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

#[utoipa::path(
    patch,
    path = "/api/organisation/v1/{id}",
    params(
        ("id" = OrganisationId, Path, description = "Organization id")
    ),
    request_body = UpsertOrganisationRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
    summary = "Update or insert organization",
    description = indoc::formatdoc! {"
        Updates the name or deactivates an organization if it exists, otherwise creates
        a new organization using the provided UUID and name.
    "},
)]
#[require_permissions(Permission::StsOrganisationEdit)]
pub(crate) async fn patch_organisation(
    state: State<AppState>,
    Path(id): Path<OrganisationId>,
    WithRejection(Json(request), _): WithRejection<
        Json<UpsertOrganisationRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .organisation_service
        .upsert_organisation(upsert_request_from_request(id, request))
        .await;
    EmptyOrErrorResponse::from_result(result, state, "upserting organization")
}
