use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use one_core::service::error::ServiceError;
use shared_types::DidId;

use super::dto::{
    CreateDidRequestRestDTO, DidPatchRequestRestDTO, DidResponseRestDTO, GetDidQuery,
};
use crate::dto::common::{EntityResponseRestDTO, GetDidsResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
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
    description = "Returns detailed information on a DID.",
)]
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
                OkOrErrorResponse::from_service_error(
                    ServiceError::MappingError(error.to_string()),
                    state.config.hide_error_response_cause,
                )
            }
        },
        Err(error) => {
            tracing::error!("Error while getting did details: {:?}", error);
            OkOrErrorResponse::from_service_error(error, state.config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
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
pub(crate) async fn get_did_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetDidQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetDidsResponseRestDTO> {
    let result = state.core.did_service.get_did_list(query.into()).await;
    OkOrErrorResponse::from_result(result, state, "getting dids")
}

#[utoipa::path(
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
        Creates a DID using a key, or keys, and a method. See the
        [DIDs](/api/resources/dids) guide for more information.
    "},
)]
pub(crate) async fn post_did(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateDidRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state.core.did_service.create_did(request.into()).await;

    match result {
        Ok(id) => CreatedOrErrorResponse::created(EntityResponseRestDTO { id: id.into() }),
        Err(error) => {
            tracing::error!(%error, "Error while creating did");
            CreatedOrErrorResponse::from_service_error(
                error,
                state.config.hide_error_response_cause,
            )
        }
    }
}

#[utoipa::path(
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
        Deactivate a DID. See the [DID deactivation](/api/resources/dids#did-deactivation)
        guide for a list of supported DID methods which allow deactivation.
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
