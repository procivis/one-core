use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use shared_types::{DidId, TrustEntityId};

use super::dto::{
    CreateRemoteTrustEntityRequestRestDTO, CreateTrustEntityRequestRestDTO, ListTrustEntitiesQuery,
};
use crate::dto::common::{EntityResponseRestDTO, GetTrustEntityListResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::ssi::dto::PatchTrustEntityRequestRestDTO;
use crate::endpoint::trust_entity::dto::GetTrustEntityResponseRestDTO;
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/trust-entity/v1",
    request_body = CreateTrustEntityRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "trust_entity",
    security(
        ("bearer" = [])
    ),
    summary = "Create a trust entity",
    description = "Adds a trust entity to a trust anchor.",
)]
pub(crate) async fn create_trust_entity(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateTrustEntityRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .trust_entity_service
        .create_trust_entity(request.into())
        .await;
    CreatedOrErrorResponse::from_result(result, state, "creating trust entity")
}

#[utoipa::path(
    patch,
    path = "/api/trust-entity/v1/{id}",
    responses(EmptyOrErrorResponse),
    request_body(content = PatchTrustEntityRequestRestDTO),
    params(
        ("id" = TrustEntityId, Path, description = "Trust entity ID"),
    ),
    tag = "trust_entity",
    security(
        ("bearer" = [])
    ),
    summary = "Update a trust entity",
    description = "Updates a trust entity in a trust anchor.",
)]
pub(crate) async fn update_trust_entity(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustEntityId>, ErrorResponseRestDTO>,
    WithRejection(Json(request_body), _): WithRejection<
        Json<PatchTrustEntityRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .trust_entity_service
        .update_trust_entity_by_trust_entity(id, request_body.into())
        .await;

    EmptyOrErrorResponse::from_result(result, state, "updating trust entity")
}

#[utoipa::path(
    get,
    path = "/api/trust-entity/v1/{id}",
    responses(OkOrErrorResponse<GetTrustEntityResponseRestDTO>),
    params(
        ("id" = TrustEntityId, Path, description = "Trust Entity id")
    ),
    tag = "trust_entity",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve a trust entity",
    description = "Returns details on a given trust entity.",
)]
pub(crate) async fn get_trust_entity_details(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustEntityId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetTrustEntityResponseRestDTO> {
    let result = state.core.trust_entity_service.get_trust_entity(id).await;

    OkOrErrorResponse::from_result(result, state, "getting trust entity")
}

#[utoipa::path(
    get,
    path = "/api/trust-entity/v1",
    responses(OkOrErrorResponse<GetTrustEntityListResponseRestDTO>),
    params(ListTrustEntitiesQuery),
    tag = "trust_entity",
    security(
        ("bearer" = [])
    ),
    summary = "List trust entities",
    description = "Returns a list of trust entities in an organization. See the [guidelines](../api/guidelines.mdx) for handling list endpoints.",
)]
pub(crate) async fn get_trust_entities(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<ListTrustEntitiesQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetTrustEntityListResponseRestDTO> {
    let result = state
        .core
        .trust_entity_service
        .list_trust_entities(query.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "listing trust entities")
}

#[utoipa::path(
    post,
    path = "/api/trust-entity/remote/v1",
    request_body = CreateRemoteTrustEntityRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    security(
        ("bearer" = [])
    ),
    tag = "trust_entity",
    summary = "Create a remote trust entity",
    description = "Create a trust entity inside a remote trust anchor",
)]
pub(crate) async fn create_remote_trust_entity(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateRemoteTrustEntityRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .trust_entity_service
        .create_remote_trust_entity_for_did(request.into())
        .await;

    CreatedOrErrorResponse::from_result(result, state, "creating remote trust entity")
}

#[utoipa::path(
    patch,
    path = "/api/trust-entity/remote/v1/{did_id}",
    responses(EmptyOrErrorResponse),
    request_body(content = PatchTrustEntityRequestRestDTO),
    params(
        ("did_id" = DidId, Path, description = "DID id"),
    ),
    tag = "trust_entity",
    security(
        ("bearer" = [])
    ),
    summary = "Update a remote trust entity",
    description = "Updates a trust entity inside a remote trust anchor.",
)]
pub(crate) async fn update_remote_trust_entity(
    state: State<AppState>,
    WithRejection(Path(did_id), _): WithRejection<Path<DidId>, ErrorResponseRestDTO>,
    WithRejection(Json(request_body), _): WithRejection<
        Json<PatchTrustEntityRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .trust_entity_service
        .update_remote_trust_entity_for_did(did_id, request_body.into())
        .await;

    EmptyOrErrorResponse::from_result(result, state, "updating remote trust entity")
}

#[utoipa::path(
    get,
    path = "/api/trust-entity/remote/v1/{did_id}",
    responses(OkOrErrorResponse<GetTrustEntityResponseRestDTO>),
    params(
        ("did_id" = DidId, Path, description = "DID id"),
    ),
    tag = "trust_entity",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve a remote trust entity",
    description = "Returns details of a remote trust entity.",
)]
pub(crate) async fn get_remote_trust_entity(
    state: State<AppState>,
    WithRejection(Path(did_id), _): WithRejection<Path<DidId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetTrustEntityResponseRestDTO> {
    let result = state
        .core
        .trust_entity_service
        .get_remote_trust_entity_for_did(did_id)
        .await;

    OkOrErrorResponse::from_result(result, state, "getting remote trust entity")
}
