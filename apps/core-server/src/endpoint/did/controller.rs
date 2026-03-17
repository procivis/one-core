use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use proc_macros::endpoint;
use shared_types::{DidId, Permission};

use super::dto::{
    CreateDidRequestRestDTO, DidPatchRequestRestDTO, DidResponseRestDTO, GetDidQuery,
};
use crate::dto::common::{EntityResponseRestDTO, GetDidsResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::trust_entity::dto::GetTrustEntityResponseRestDTO;
use crate::extractor::Qs;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::DidDetail],
    get,
    path = "/api/did/v1/{id}",
    responses(OkOrErrorResponse<DidResponseRestDTO>),
    params(
        ("id" = DidId, Path, description = "DID id")
    ),
    tag = "did_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve a DID",
    description = "Returns detailed information about a DID.",
)]
#[deprecated = "Deprecated in favour of trust list publisher mechanism (ONE-8838)"]
pub(crate) async fn get_did(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<DidId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<DidResponseRestDTO> {
    let result = state.core.did_service.get_did(&id).await;

    match result {
        Ok(value) => match DidResponseRestDTO::try_from(value) {
            Ok(value) => OkOrErrorResponse::ok(value),
            Err(error) => {
                tracing::error!("Error while encoding base64: {:?}", error);
                OkOrErrorResponse::from_error(
                    &ServiceError::MappingError(error.to_string()),
                    state.config.hide_error_response_cause,
                )
            }
        },
        Err(error) => {
            tracing::error!("Error while getting did details: {:?}", error);
            OkOrErrorResponse::from_error(&error, state.config.hide_error_response_cause)
        }
    }
}

#[endpoint(
    permissions = [Permission::DidList],
    get,
    path = "/api/did/v1",
    responses(OkOrErrorResponse<GetDidsResponseRestDTO>),
    params(
        GetDidQuery
    ),
    tag = "did_management",
    security(
        ("bearer" = [])
    ),
    summary = "List DIDs",
    description = "Returns a list of DIDs within an organization.",
)]
#[deprecated = "Deprecated in favour of trust list publisher mechanism (ONE-8838)"]
pub(crate) async fn get_did_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetDidQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetDidsResponseRestDTO> {
    let result = async {
        let organisation_id = fallback_organisation_id_from_session(query.filter.organisation_id)?;
        Ok::<_, ServiceError>(
            state
                .core
                .did_service
                .get_did_list(&organisation_id, query.try_into()?)
                .await
                .error_while("getting did list")?,
        )
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting dids")
}

#[endpoint(
    permissions = [Permission::DidCreate],
    post,
    path = "/api/did/v1",
    request_body = CreateDidRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "did_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create a DID",
    description = indoc::formatdoc! {"
        Deprecated. Use the identifier API to create a DID as an identifier
          to use in issuing, holding, or verifying.

        When you create a DID as an identifier, both the identifier and the
        DID receive separate system IDs. You can access the DID's system ID
        from the identifier response to use with the DID API for operations
        like DID deactivation.
    "},
)]
#[deprecated = "Deprecated in favour of trust list publisher mechanism (ONE-8838)"]
pub(crate) async fn post_did(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateDidRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .did_service
                .create_did(request.try_into()?)
                .await
                .error_while("creating DID")?,
        )
    }
    .await;

    match result {
        Ok(id) => CreatedOrErrorResponse::created(EntityResponseRestDTO { id: id.into() }),
        Err(error) => {
            tracing::error!(%error, "Error while creating did");
            CreatedOrErrorResponse::from_error(&error, state.config.hide_error_response_cause)
        }
    }
}

#[endpoint(
    permissions = [Permission::DidDeactivate],
    patch,
    path = "/api/did/v1/{id}",
    request_body = DidPatchRequestRestDTO,
    responses(EmptyOrErrorResponse),
    tag = "did_management",
    params(
        ("id" = DidId, Path, description = "DID id")
    ),
    security(
        ("bearer" = [])
    ),
    summary = "Deactivate a DID",
    description = indoc::formatdoc! {"
        Permanently deactivates a DID.
    "},
)]
pub(crate) async fn update_did(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<DidId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<DidPatchRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state.core.did_service.update_did(&id, request.into()).await;
    EmptyOrErrorResponse::from_result(result, state, "updating DID")
}

#[endpoint(
    permissions = [Permission::TrustEntityDetail],
    get,
    path = "/api/did/v1/{id}/trust-entity",
    responses(OkOrErrorResponse<GetTrustEntityResponseRestDTO>),
    params(
        ("id" = DidId, Path, description = "DID id")
    ),
    tag = "did_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve the matching trust entity for a DID",
    description = "Returns details on the matching trust entity for a DID.",
)]
#[deprecated = "Deprecated in favour of trust list publisher mechanism (ONE-8838)"]
pub(crate) async fn get_did_trust_entity(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<DidId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetTrustEntityResponseRestDTO> {
    let result = state.core.trust_entity_service.lookup_did(id).await;

    OkOrErrorResponse::from_result(result, state, "getting trust entity by did id")
}
