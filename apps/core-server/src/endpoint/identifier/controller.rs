use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use one_dto_mapper::convert_inner_of_inner;
use proc_macros::endpoint;
use shared_types::{IdentifierId, Permission};

use super::dto::{
    CreateIdentifierRequestRestDTO, GetIdentifierListResponseRestDTO, GetIdentifierQuery,
    GetIdentifierResponseRestDTO, PatchIdentifierRequestRestDTO, ResolveTrustEntriesRequestRestDTO,
    ResolvedTrustEntriesResponseRestDTO,
};
use crate::dto::common::EntityResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{
    CreatedOrErrorResponse, EmptyOrErrorResponse, InlineOkOrErrorResponse, OkOrErrorResponse,
};
use crate::endpoint::identifier::dto::CreateRemoteIdentifierRequestRestDTO;
use crate::extractor::Qs;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::IdentifierCreate],
    post,
    path = "/api/identifier/v1",
    request_body = CreateIdentifierRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "identifier_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create an identifier",
    description = indoc::formatdoc! {"
    Creates a new identifier for use in signing and credential operations.

    An identifier wraps an underlying resource (key, certificate, CA, or DID)
    and provides a stable identifier ID. The underlying resource retains its
    own ID for resource-specific management via its respective API.

    Provide exactly one of: `key`, `certificates`, `certificateAuthorities`,
    or `did`.
    "},
)]
pub(crate) async fn post_identifier(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateIdentifierRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .identifier_service
                .create_identifier(request.try_into()?)
                .await
                .error_while("creating identifier")?,
        )
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "creating identifier")
}

#[endpoint(
    permissions = [Permission::IdentifierCreate],
    post,
    path = "/api/identifier/v1/remote",
    request_body = CreateRemoteIdentifierRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "identifier_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create a remote identifier",
    description = indoc::formatdoc! {"
    Creates a new remote identifier for an external party whose private key 
    is not held within Procivis One. Remote identifiers can be added as 
    entries to trust list publications.

    The request follows the same structure as `POST /api/identifier/v1`.
    Provide exactly one of: `key`, `certificates`, `certificateAuthorities`,
    or `did`.
    "},
)]
pub(crate) async fn post_remote_identifier(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateRemoteIdentifierRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .identifier_service
                .create_remote_identifier(request.try_into()?)
                .await
                .error_while("creating remote identifier")?,
        )
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "creating remote identifier")
}

#[endpoint(
    permissions = [Permission::IdentifierDetail],
    get,
    path = "/api/identifier/v1/{id}",
    responses(OkOrErrorResponse<GetIdentifierResponseRestDTO>),
    params(
        ("id" = IdentifierId, Path, description = "Identifier id")
    ),
    tag = "identifier_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve an identifier",
    description = "Returns detailed information about an identifier.",
)]
pub(crate) async fn get_identifier(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<IdentifierId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetIdentifierResponseRestDTO> {
    let result = state.core.identifier_service.get_identifier(&id).await;

    match result {
        Ok(value) => match GetIdentifierResponseRestDTO::try_from(value) {
            Ok(value) => OkOrErrorResponse::ok(value),
            Err(error) => {
                tracing::error!("Error while converting identifier response: {:?}", error);
                OkOrErrorResponse::from_error(
                    &ServiceError::MappingError(error.to_string()),
                    state.config.hide_error_response_cause,
                )
            }
        },
        Err(error) => {
            tracing::error!("Error while getting identifier details: {:?}", error);
            OkOrErrorResponse::from_error(&error, state.config.hide_error_response_cause)
        }
    }
}

#[endpoint(
    permissions = [Permission::IdentifierDelete],
    delete,
    path = "/api/identifier/v1/{id}",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = IdentifierId, Path, description = "Identifier id")
    ),
    tag = "identifier_management",
    security(
        ("bearer" = [])
    ),
    summary = "Delete an identifier",
    description = "Deletes an identifier.",
)]
pub(crate) async fn delete_identifier(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<IdentifierId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state.core.identifier_service.delete_identifier(&id).await;

    EmptyOrErrorResponse::from_result(result, state, "deleting identifier")
}

#[endpoint(
    permissions = [Permission::IdentifierEdit],
    patch,
    path = "/api/identifier/v1/{id}",
    request_body = PatchIdentifierRequestRestDTO,
    responses(EmptyOrErrorResponse),
    params(
        ("id" = IdentifierId, Path, description = "Identifier id")
    ),
    tag = "identifier_management",
    security(
        ("bearer" = [])
    ),
    summary = "Update an identifier",
    description = indoc::formatdoc! {"
    Updates an identifier in place.

    Only local (non-remote) identifiers can be updated. Provided attributes
    fully replace their current value; omitted attributes are left
    unchanged. An empty `trustInformation` array removes all trust
    information.
    "},
)]
pub(crate) async fn patch_identifier(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<IdentifierId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<PatchIdentifierRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .identifier_service
                .update_identifier(&id, request.try_into()?)
                .await
                .error_while("updating identifier")?,
        )
    }
    .await;
    EmptyOrErrorResponse::from_result(result, state, "updating identifier")
}

#[endpoint(
    permissions = [Permission::IdentifierList],
    get,
    path = "/api/identifier/v1",
    responses(OkOrErrorResponse<GetIdentifierListResponseRestDTO>),
    params(GetIdentifierQuery),
    tag = "identifier_management",
    security(
        ("bearer" = [])
    ),
    summary = "List identifiers",
    description = "Returns a list of identifiers within an organization.",
)]
pub(crate) async fn get_identifier_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetIdentifierQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetIdentifierListResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .identifier_service
                .get_identifier_list(query.try_into()?)
                .await
                .error_while("getting identifier list")?,
        )
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting identifiers")
}

#[endpoint(
    permissions = [Permission::IdentifierDetail],
    post,
    path = "/api/identifier/v1/resolve-trust-entries",
    request_body = ResolveTrustEntriesRequestRestDTO,
    responses(InlineOkOrErrorResponse<Vec<ResolvedTrustEntriesResponseRestDTO>>),
    tag = "identifier_management",
    security(
        ("bearer" = [])
    ),
    summary = "Resolve trust entries",
    description = "",
)]
#[deprecated = "Deprecated in favor of credential and proof trust details"]
pub(crate) async fn resolve_trust_entries(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<ResolveTrustEntriesRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<Vec<ResolvedTrustEntriesResponseRestDTO>> {
    let result = state
        .core
        .identifier_service
        .resolve_trust_entries(request.into())
        .await;
    OkOrErrorResponse::from_result(
        convert_inner_of_inner(result),
        state,
        "resolving trust entries for identifiers",
    )
}
