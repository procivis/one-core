use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::service::error::ServiceError;
use shared_types::IdentifierId;

use super::dto::{
    CreateIdentifierRequestRestDTO, GetIdentifierListResponseRestDTO, GetIdentifierQuery,
    GetIdentifierResponseRestDTO, ResolveTrustEntitiesRequestRestDTO,
    ResolveTrustEntitiesResponseRestDTO,
};
use crate::dto::common::EntityResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/identifier/v1",
    request_body = CreateIdentifierRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "identifier_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create an identifier",
    description = "Creates a new identifier of the specified type.",
)]
pub(crate) async fn post_identifier(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateIdentifierRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .identifier_service
        .create_identifier(request.into())
        .await;

    CreatedOrErrorResponse::from_result(result, state, "creating identifier")
}

#[utoipa::path(
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
                OkOrErrorResponse::from_service_error(
                    ServiceError::MappingError(error.to_string()),
                    state.config.hide_error_response_cause,
                )
            }
        },
        Err(error) => {
            tracing::error!("Error while getting identifier details: {:?}", error);
            OkOrErrorResponse::from_service_error(error, state.config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
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

#[utoipa::path(
    get,
    path = "/api/identifier/v1",
    responses(OkOrErrorResponse<GetIdentifierListResponseRestDTO>),
    params(GetIdentifierQuery),
    tag = "identifier_management",
    security(
        ("bearer" = [])
    ),
    summary = "List identifiers",
    description = "Returns a list of identifiers within an organization. See the [guidelines](/api/general_guidelines) for handling list endpoints.",
)]
pub(crate) async fn get_identifier_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetIdentifierQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetIdentifierListResponseRestDTO> {
    let result = state
        .core
        .identifier_service
        .get_identifier_list(query.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "getting identifiers")
}

#[utoipa::path(
    post,
    path = "/api/identifier/v1/resolve-trust-entity",
    request_body = ResolveTrustEntitiesRequestRestDTO,
    responses(OkOrErrorResponse<ResolveTrustEntitiesResponseRestDTO>),
    tag = "identifier_management",
    security(
        ("bearer" = [])
    ),
    summary = "Resolve the trust entity of each of the supplied identifiers",
    description = "Returns a list of identifiers within an organization. See the [guidelines](/api/general_guidelines) for handling list endpoints.",
)]
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
