use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use proc_macros::require_permissions;
use shared_types::{Permission, TrustEntryId, TrustListPublicationId};

use super::dto::{
    CreateTrustEntryRequestRestDTO, CreateTrustListRequestRestDTO,
    GetTrustEntryListResponseRestDTO, GetTrustListPublicationListResponseRestDTO,
    GetTrustListPublicationResponseRestDTO, ListTrustEntryEntitiesQuery,
    ListTrustListPublicationsEntitiesQuery, UpdateTrustEntryRequestRestDTO,
};
use crate::dto::common::EntityResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/trust-list/v1",
    request_body = CreateTrustListRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "trust_list_publication_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create a trust list publication",
    description = "Create a trust list publication.",
)]
#[require_permissions(Permission::TrustListPublicationCreate)]
pub(crate) async fn post_trust_list_publication(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateTrustListRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .trust_list_publication_service
                .create_trust_list_publication(request.try_into()?)
                .await
                .error_while("creating trust list publication")?,
        )
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "creating trust list publication")
}

#[utoipa::path(
    get,
    path = "/api/trust-list/v1/{id}",
    responses(OkOrErrorResponse<GetTrustListPublicationResponseRestDTO>),
    params(
        ("id" = TrustListPublicationId, Path, description = "Trust list publication id")
    ),
    tag = "trust_list_publication_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve an trust list publication",
    description = "Returns detailed information about an trust list publication.",
)]
#[require_permissions(Permission::TrustListPublicationDetail)]
pub(crate) async fn get_trust_list_publication(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustListPublicationId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetTrustListPublicationResponseRestDTO> {
    let result = state
        .core
        .trust_list_publication_service
        .get_trust_list_publication(id)
        .await;

    match result {
        Ok(value) => OkOrErrorResponse::Ok(GetTrustListPublicationResponseRestDTO::from(value)),
        Err(error) => {
            tracing::error!(
                "Error while getting trust list publication details: {:?}",
                error
            );
            OkOrErrorResponse::from_error(&error, state.config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/trust-list/v1",
    responses(OkOrErrorResponse<GetTrustListPublicationListResponseRestDTO>),
    params(ListTrustListPublicationsEntitiesQuery),
    tag = "trust_list_publication_management",
    security(
        ("bearer" = [])
    ),
    summary = "List trust list publications",
    description = "Returns a list of trust list publications in an organization.",
)]
#[require_permissions(Permission::TrustListPublicationList)]
pub(crate) async fn get_trust_list_publications(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<
        Qs<ListTrustListPublicationsEntitiesQuery>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<GetTrustListPublicationListResponseRestDTO> {
    let result = async {
        let organisation_id = fallback_organisation_id_from_session(query.filter.organisation_id)
            .error_while("fallback organisation id")?;
        state
            .core
            .trust_list_publication_service
            .get_trust_list_publication_list(
                organisation_id,
                query.try_into().error_while("mapping query")?,
            )
            .await
    }
    .await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting trust list publications: {:?}", error);
            OkOrErrorResponse::from_error(&error, state.config.hide_error_response_cause)
        }
        Ok(value) => OkOrErrorResponse::ok(GetTrustListPublicationListResponseRestDTO::from(value)),
    }
}

#[utoipa::path(
    delete,
    path = "/api/trust-list/v1/{id}",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = TrustListPublicationId, Path, description = "Trust list publication id")
    ),
    tag = "trust_list_publication_management",
    security(
        ("bearer" = [])
    ),
    summary = "Delete a trust list publication",
    description = "Delete a trust list publication.",
)]
#[require_permissions(Permission::TrustListPublicationDelete)]
pub(crate) async fn delete_trust_list_publication(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustListPublicationId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .trust_list_publication_service
        .delete_trust_list_publication(id)
        .await;

    match result {
        Ok(_) => EmptyOrErrorResponse::NoContent,
        Err(error) => {
            tracing::error!("Error while deleting trust list publication: {:?}", error);
            EmptyOrErrorResponse::from_error(&error, state.config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/trust-list/v1/{id}/entry",
    request_body = CreateTrustEntryRequestRestDTO,
    params(
        ("id" = TrustListPublicationId, Path, description = "Trust list publication id")
    ),
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "trust_list_publication_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create a trust entry",
    description = "Create a trust entry in a trust list publication.",
)]
#[require_permissions(Permission::TrustEntryPublicationCreate)]
pub(crate) async fn post_trust_entry(
    state: State<AppState>,
    WithRejection(Path(trust_list_id), _): WithRejection<
        Path<TrustListPublicationId>,
        ErrorResponseRestDTO,
    >,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateTrustEntryRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .trust_list_publication_service
                .create_trust_entry(trust_list_id, request.into())
                .await
                .error_while("creating trust entry")?,
        )
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "creating trust entry")
}

#[utoipa::path(
    patch,
    path = "/api/trust-list/v1/{list_id}/entry/{entry_id}",
    request_body = UpdateTrustEntryRequestRestDTO,
    params(
        ("list_id" = TrustListPublicationId, Path, description = "Trust list publication id"),
        ("entry_id" = TrustListPublicationId, Path, description = "Trust entry id")
    ),
    responses(EmptyOrErrorResponse),
    tag = "trust_list_publication_management",
    security(
        ("bearer" = [])
    ),
    summary = "Update trust entry",
    description = "Update trust entry",
)]
#[require_permissions(Permission::TrustEntryPublicationEdit)]
pub(crate) async fn patch_trust_entry(
    state: State<AppState>,
    WithRejection(Path((trust_list_id, entry_id)), _): WithRejection<
        Path<(TrustListPublicationId, TrustEntryId)>,
        ErrorResponseRestDTO,
    >,
    WithRejection(Json(request), _): WithRejection<
        Json<UpdateTrustEntryRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .trust_list_publication_service
                .update_trust_entry(trust_list_id, entry_id, request.into())
                .await
                .error_while("updating trust entry")?,
        )
    }
    .await;
    EmptyOrErrorResponse::from_result(result, state, "updating trust entry")
}

#[utoipa::path(
    delete,
    path = "/api/trust-list/v1/{list_id}/entry/{entry_id}",
    params(
        ("list_id" = TrustListPublicationId, Path, description = "Trust list publication id"),
        ("entry_id" = TrustListPublicationId, Path, description = "Trust entry id")
    ),
    responses(EmptyOrErrorResponse),
    tag = "trust_list_publication_management",
    security(
        ("bearer" = [])
    ),
    summary = "Delete trust entry",
    description = "Delete trust entry",
)]
#[require_permissions(Permission::TrustEntryPublicationDelete)]
pub(crate) async fn delete_trust_entry(
    state: State<AppState>,
    WithRejection(Path((trust_list_id, entry_id)), _): WithRejection<
        Path<(TrustListPublicationId, TrustEntryId)>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .trust_list_publication_service
                .delete_trust_entry(trust_list_id, entry_id)
                .await
                .error_while("deleting trust entry")?,
        )
    }
    .await;
    EmptyOrErrorResponse::from_result(result, state, "deleting trust entry")
}

#[utoipa::path(
    get,
    path = "/api/trust-list/v1/{id}/entry",
    responses(OkOrErrorResponse<GetTrustEntryListResponseRestDTO>),
    params(
        ("id" = TrustListPublicationId, Path, description = "Trust list publication id"),
        ListTrustEntryEntitiesQuery
    ),
    tag = "trust_list_publication_management",
    security(
        ("bearer" = [])
    ),
    summary = "List trust list publication entries",
    description = "Returns a list of trust list publications in an organization.",
)]
#[require_permissions(Permission::TrustEntryPublicationDetail)]
pub(crate) async fn get_trust_list_publication_entries(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<TrustListPublicationId>, ErrorResponseRestDTO>,
    WithRejection(Qs(query), _): WithRejection<
        Qs<ListTrustEntryEntitiesQuery>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<GetTrustEntryListResponseRestDTO> {
    let result = async {
        let query = query.try_into().error_while("mapping query")?;
        state
            .core
            .trust_list_publication_service
            .get_trust_entry_list(id, query)
            .await
    }
    .await;

    match result {
        Err(error) => {
            tracing::error!(
                "Error while getting trust list publication entries: {:?}",
                error
            );
            OkOrErrorResponse::from_error(&error, state.config.hide_error_response_cause)
        }
        Ok(value) => OkOrErrorResponse::ok(GetTrustEntryListResponseRestDTO::from(value)),
    }
}
