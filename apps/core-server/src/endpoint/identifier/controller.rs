use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use proc_macros::endpoint;
use shared_types::{IdentifierId, Permission};

use super::dto::{
    CreateIdentifierRequestRestDTO, GetIdentifierListResponseRestDTO, GetIdentifierQuery,
    GetIdentifierResponseRestDTO, ResolveTrustEntitiesRequestRestDTO,
    ResolveTrustEntitiesResponseRestDTO,
};
use crate::dto::common::EntityResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
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
    Creates a new identifier for use in credential issuance and verification.

    An identifier wraps an underlying resource (key, certificate, CA, or DID)
    and provides a stable identifier ID for credential operations. The
    underlying resource retains its own ID for resource-specific management
    via its respective API.

    Provide one of: `key`, `certificates`, `certificateAuthorities`, or
    `did`.
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
        let organisation_id = fallback_organisation_id_from_session(query.filter.organisation_id)?;
        Ok::<_, ServiceError>(
            state
                .core
                .identifier_service
                .get_identifier_list(&organisation_id, query.try_into()?)
                .await
                .error_while("getting identifier list")?,
        )
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting identifiers")
}

#[endpoint(
    permissions = [Permission::TrustEntityDetail],
    post,
    path = "/api/identifier/v1/resolve-trust-entity",
    request_body = ResolveTrustEntitiesRequestRestDTO,
    responses(OkOrErrorResponse<ResolveTrustEntitiesResponseRestDTO>),
    tag = "identifier_management",
    security(
        ("bearer" = [])
    ),
    summary = "Resolve trust entities",
    description = indoc::formatdoc! {"
    Resolves trust entity information of supplied identifiers.

    For holders and verifiers: get identifiers from offered credentials or shared
    proofs and pass them here. The system checks the identifiers against your trust
    anchors and returns information for trusted entities.

    Note that trust information is informational only. Holders and verifiers can
    decide how to proceed with any given interaction.
"},
)]
#[deprecated = "Deprecated in favor of trust list publisher mechanism"]
pub(crate) async fn resolve_trust_entity(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<ResolveTrustEntitiesRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<ResolveTrustEntitiesResponseRestDTO> {
    let result = state
        .core
        .trust_entity_service
        .resolve_identifiers(request.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "resolving trust entities for identifiers")
}
