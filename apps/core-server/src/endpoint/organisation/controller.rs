use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use one_dto_mapper::convert_inner;
use proc_macros::endpoint;
use shared_types::{OrganisationId, Permission};

use super::dto::{
    CreateOrganisationRequestRestDTO, CreateOrganisationResponseRestDTO,
    GetOrganisationDetailsResponseRestDTO, GetOrganisationsQuery,
    OrganisationEcosystemListResponseRestDTO, OrganisationTrustCollectionRestDTO,
    UpsertOrganisationRequestRestDTO,
};
use crate::dto::common::GetOrganisationListResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{
    CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse, VecResponse,
};
use crate::endpoint::organisation::mapper::upsert_request_from_request;
use crate::extractor::Qs;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::StsOrganisationDetail],
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
pub(crate) async fn get_organisation(
    state: State<AppState>,
    Path(id): Path<OrganisationId>,
) -> OkOrErrorResponse<GetOrganisationDetailsResponseRestDTO> {
    let result = state.core.organisation_service.get_organisation(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting organization details")
}

#[endpoint(
    permissions = [Permission::StsOrganisationList],
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
pub(crate) async fn get_organisations(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetOrganisationsQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetOrganisationListResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .organisation_service
                .get_organisation_list(query.try_into()?)
                .await
                .error_while("getting organisation list")?,
        )
    }
    .await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting organisation list: {:?}", error);
            OkOrErrorResponse::from_error(&error, state.config.hide_error_response_cause)
        }
        Ok(value) => OkOrErrorResponse::Ok(GetOrganisationListResponseRestDTO {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }),
    }
}

#[endpoint(
    permissions = [Permission::StsOrganisationCreate],
    post,
    path = "/api/organisation/v1",
    request_body(
        content((Option<CreateOrganisationRequestRestDTO>)),
        example = json!({ "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6" }),
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

#[endpoint(
    permissions = [Permission::StsOrganisationEdit],
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
pub(crate) async fn patch_organisation(
    state: State<AppState>,
    Path(id): Path<OrganisationId>,
    WithRejection(Json(request), _): WithRejection<
        Json<UpsertOrganisationRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let request = match upsert_request_from_request(id, request) {
        Ok(request) => request,
        Err(error) => {
            tracing::error!("Error while upserting organisation: {error}");
            return EmptyOrErrorResponse::from_error(
                &error,
                state.config.hide_error_response_cause,
            );
        }
    };

    let result = state
        .core
        .organisation_service
        .upsert_organisation(request)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "upserting organization")
}

#[endpoint(
    permissions = [Permission::StsOrganisationDetail],
    get,
    path = "/api/organisation/v1/{id}/trust-collections",
    responses(OkOrErrorResponse<VecResponse<OrganisationTrustCollectionRestDTO>>),
    params(
        ("id" = OrganisationId, Path, description = "Organization id")
    ),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve organization trust collections",
    description = indoc::formatdoc! {"
        Returns the trust collections available to this organization's wallet
        provider, annotated with whether the organization currently
        subscribes to each one.
    "},
)]
#[deprecated = "Deprecated in favor of GET /api/organisation/v1/{id}/ecosystems"]
pub(crate) async fn get_organisation_trust_collections(
    state: State<AppState>,
    Path(id): Path<OrganisationId>,
) -> OkOrErrorResponse<VecResponse<OrganisationTrustCollectionRestDTO>> {
    let result = state
        .core
        .organisation_service
        .get_trust_collections(&id)
        .await;
    OkOrErrorResponse::from_result(result, state, "getting organization trust collections")
}

#[endpoint(
    permissions = [Permission::StsOrganisationDetail],
    get,
    path = "/api/organisation/v1/{id}/ecosystems",
    responses(OkOrErrorResponse<OrganisationEcosystemListResponseRestDTO>),
    params(
        ("id" = OrganisationId, Path, description = "Organization id")
    ),
    tag = "organisation_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve organization ecosystems",
    description = indoc::formatdoc! {"
        Returns the ecosystems offered to this organization by its wallet
        or verifier provider, annotated with whether the organization
        currently selected each one. Ecosystems this system is not
        configured for are omitted.
        If there is no wallet or verifier provider, the ecosystems
        configured in the local system are returned.
    "},
)]
pub(crate) async fn get_organisation_ecosystems(
    state: State<AppState>,
    Path(id): Path<OrganisationId>,
) -> OkOrErrorResponse<OrganisationEcosystemListResponseRestDTO> {
    let result = state.core.organisation_service.get_ecosystems(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting organization ecosystems")
}
