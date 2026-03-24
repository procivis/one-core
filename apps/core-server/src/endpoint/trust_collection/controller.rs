use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use proc_macros::endpoint;
use shared_types::{Permission, TrustCollectionId, TrustListSubscriptionId};

use super::dto::{
    CreateTrustCollectionRestDTO, CreateTrustListSubscriptionRequestRestDTO,
    GetTrustCollectionListResponseRestDTO, GetTrustCollectionResponseRestDTO,
    GetTrustListSubscriptionListResponseRestDTO, ListTrustCollectionEntitiesQuery,
    ListTrustListSubscriptionsEntitiesQuery,
};
use crate::dto::common::EntityResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::extractor::Qs;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::TrustCollectionCreate],
    post,
    path = "/api/trust-collection/v1",
    request_body = CreateTrustCollectionRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "trust_collection_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create a trust collection",
    description = "Create a trust collection.",
)]
pub(crate) async fn post_trust_collection(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateTrustCollectionRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .trust_collection_service
                .create_trust_collection(request.try_into()?)
                .await
                .error_while("creating trust collection")?,
        )
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "creating trust collection")
}

#[endpoint(
    permissions = [Permission::TrustCollectionDetail],
    get,
    path = "/api/trust-collection/v1/{id}",
    responses(OkOrErrorResponse<GetTrustCollectionResponseRestDTO>),
    params(
        ("id" = TrustCollectionId, Path, description = "Trust collection id")
    ),
    tag = "trust_collection_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve an trust collection",
    description = "Returns detailed information about an trust collection.",
)]
pub(crate) async fn get_trust_collection(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustCollectionId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetTrustCollectionResponseRestDTO> {
    let result = state
        .core
        .trust_collection_service
        .get_trust_collection(id)
        .await;

    OkOrErrorResponse::from_result(result, state, "getting trust collection")
}

#[endpoint(
    permissions = [Permission::TrustCollectionList],
    get,
    path = "/api/trust-collection/v1",
    responses(OkOrErrorResponse<GetTrustCollectionListResponseRestDTO>),
    params(ListTrustCollectionEntitiesQuery),
    tag = "trust_collection_management",
    security(
        ("bearer" = [])
    ),
    summary = "List trust collections",
    description = "Returns a list of trust collections in an organization.",
)]
pub(crate) async fn get_trust_collection_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<
        Qs<ListTrustCollectionEntitiesQuery>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<GetTrustCollectionListResponseRestDTO> {
    let result = async {
        let organisation_id = fallback_organisation_id_from_session(query.filter.organisation_id)
            .error_while("fallback organisation id")?;
        state
            .core
            .trust_collection_service
            .get_trust_collection_list(
                organisation_id,
                query.try_into().error_while("mapping query")?,
            )
            .await
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting list of trust collections")
}

#[endpoint(
    permissions = [Permission::TrustCollectionDelete],
    delete,
    path = "/api/trust-collection/v1/{id}",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = TrustCollectionId, Path, description = "Trust collection id")
    ),
    tag = "trust_collection_management",
    security(
        ("bearer" = [])
    ),
    summary = "Delete a trust collection",
    description = "Delete a trust collection.",
)]
pub(crate) async fn delete_trust_collection(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustCollectionId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .trust_collection_service
        .delete_trust_collection(id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "deleting trust collection")
}

#[endpoint(
    permissions = [Permission::TrustCollectionEdit],
    post,
    path = "/api/trust-collection/v1/{trust_collection_id}/trust-list",
    request_body = CreateTrustListSubscriptionRequestRestDTO,
    params(
        ("trust_collection_id" = TrustCollectionId, Path, description = "Trust collection id")
    ),
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "trust_collection_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create a trust list subscription",
    description = "",
)]
pub(crate) async fn post_trust_list_subscription(
    state: State<AppState>,
    WithRejection(Path(trust_collection_id), _): WithRejection<
        Path<TrustCollectionId>,
        ErrorResponseRestDTO,
    >,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateTrustListSubscriptionRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .trust_collection_service
        .create_trust_list_subscription(trust_collection_id, request.into())
        .await;
    CreatedOrErrorResponse::from_result(result, state, "creating trust list subscription")
}

#[endpoint(
    permissions = [Permission::TrustCollectionEdit],
    delete,
    path = "/api/trust-collection/v1/{trust_collection_id}/trust-list/{trust_list_id}",
    params(
        ("trust_collection_id" = TrustCollectionId, Path, description = "Trust collection id"),
        ("trust_list_id" = TrustListSubscriptionId, Path, description = "Trust list subscription id")
    ),
    responses(EmptyOrErrorResponse),
    tag = "trust_collection_management",
    security(
        ("bearer" = [])
    ),
    summary = "Delete a trust list subscription",
    description = "Permanently removes a trust list subscription from a trust collection.",
)]
pub(crate) async fn delete_trust_list_subscription(
    state: State<AppState>,
    WithRejection(Path((_trust_list_id, trust_list_subscription_id)), _): WithRejection<
        Path<(TrustCollectionId, TrustListSubscriptionId)>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .trust_collection_service
        .delete_trust_list_subscription(trust_list_subscription_id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "deleting trust list subscription")
}

#[endpoint(
    permissions = [Permission::TrustCollectionDetail],
    get,
    path = "/api/trust-collection/v1/{trustCollectionId}/trust-list",
    responses(OkOrErrorResponse<GetTrustListSubscriptionListResponseRestDTO>),
    params(
        ("trustCollectionId" = TrustCollectionId, Path, description = "Trust collection id"),
        ListTrustListSubscriptionsEntitiesQuery
    ),
    tag = "trust_collection_management",
    security(
        ("bearer" = [])
    ),
    summary = "List trust list subscription entries",
    description = "Returns a filterable list of trust list subscriptions in a trust collection.",
)]
pub(crate) async fn get_trust_list_subscription_entries(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustCollectionId>, ErrorResponseRestDTO>,
    WithRejection(Qs(query), _): WithRejection<
        Qs<ListTrustListSubscriptionsEntitiesQuery>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<GetTrustListSubscriptionListResponseRestDTO> {
    let result = async {
        let query = query.try_into().error_while("mapping query")?;
        state
            .core
            .trust_collection_service
            .get_trust_list_subscription_list(id, query)
            .await
    }
    .await;

    OkOrErrorResponse::from_result(result, state, "getting trust list subscription list")
}
