use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::service::error::ServiceError;
use proc_macros::require_permissions;
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
    description = indoc::formatdoc! {"
    Creates a new identifier to use for issuing, holding, or verifying. All
    identifiers have an identifier ID for credential operations and a separate
    ID for managing the underlying resource.

    Use the identifier ID with the `issuer` field when issuing credentials,
    the `verifier` field when verifying credentials, and the `identifierId`
    field when interacting as a holder. Use the resource ID
    (DID ID, key ID, or certificate ID) with their respective APIs for
    resource-specific management operations.

    For a DID identifier: Specify a name, the method, and the keys
    to use for the verification methods. The system assigns an ID to both
    the identifier and the DID. Use the DID ID with the DID API for operations
    like deactivation.

    For a key identifier: Create the key first using the key API. Pass
    the key ID and a name for the identifier. The system assigns an ID
    to the identifier. Use the key ID with the key API for key-specific
    management operations.

    For a certificate identifier: Use the key API to generate a key and a
    Certificate Signing Request (CSR). When you have a signed certificate,
    pass the certificate in PEM format, also specifying the original key ID
    and a name for the identifier. Use the certificate ID with the certificate
    API for certificate operations.
    "},
)]
#[require_permissions(Permission::IdentifierCreate)]
pub(crate) async fn post_identifier(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateIdentifierRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = async {
        state
            .core
            .identifier_service
            .create_identifier(request.try_into()?)
            .await
    }
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
#[require_permissions(Permission::IdentifierDetail)]
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
#[require_permissions(Permission::IdentifierDelete)]
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
    description = "Returns a list of identifiers within an organization.",
)]
#[require_permissions(Permission::IdentifierList)]
pub(crate) async fn get_identifier_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetIdentifierQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetIdentifierListResponseRestDTO> {
    let result = async {
        let organisation_id = fallback_organisation_id_from_session(query.filter.organisation_id)?;
        state
            .core
            .identifier_service
            .get_identifier_list(&organisation_id, query.try_into()?)
            .await
    }
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
#[require_permissions(Permission::TrustEntityDetail)]
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
