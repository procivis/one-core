use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use shared_types::TrustEntityId;

use super::dto::{CreateTrustEntityRequestRestDTO, ListTrustEntitiesQuery};
use crate::dto::common::{EntityResponseRestDTO, GetTrustEntityListResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
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
    delete,
    path = "/api/trust-entity/v1/{id}",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = TrustEntityId, Path, description = "Trust entity ID"),
    ),
    tag = "trust_entity",
    security(
        ("bearer" = [])
    ),
    summary = "Delete a trust entity",
    description = "Deletes a trust entity from a trust anchor.",
)]
pub(crate) async fn delete_trust_entity(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustEntityId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .trust_entity_service
        .delete_trust_entity(id)
        .await;

    EmptyOrErrorResponse::from_result(result, state, "deleting trust entity")
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
    description = "Returns a list of trust entities in an organization.",
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
