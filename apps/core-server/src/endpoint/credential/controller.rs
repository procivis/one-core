use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use dto_mapper::convert_inner;
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::service::credential::dto::GetCredentialQueryDTO;
use shared_types::CredentialId;

use super::dto::{
    CredentialRevocationCheckRequestRestDTO, CredentialRevocationCheckResponseRestDTO,
};
use crate::dto::common::{
    EntityResponseRestDTO, EntityShareResponseRestDTO, GetCredentialsResponseDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{
    declare_utoipa_alias, AliasResponse, CreatedOrErrorResponse, EmptyOrErrorResponse,
    OkOrErrorResponse, VecResponse,
};
use crate::endpoint::credential::dto::{
    CreateCredentialRequestRestDTO, GetCredentialQuery, GetCredentialResponseRestDTO,
    SuspendCredentialRequestRestDTO,
};
use crate::extractor::Qs;
use crate::router::AppState;

#[utoipa::path(
    delete,
    path = "/api/credential/v1/{id}",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = CredentialId, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn delete_credential(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state.core.credential_service.delete_credential(&id).await;
    EmptyOrErrorResponse::from_result(result, state, "deleting credential")
}

#[utoipa::path(
    get,
    path = "/api/credential/v1/{id}",
    responses(OkOrErrorResponse<GetCredentialResponseRestDTO>),
    params(
        ("id" = CredentialId, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetCredentialResponseRestDTO> {
    let result = state.core.credential_service.get_credential(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting credential")
}

declare_utoipa_alias!(GetCredentialsResponseDTO);

#[utoipa::path(
    get,
    path = "/api/credential/v1",
    responses(OkOrErrorResponse<AliasResponse<GetCredentialsResponseDTO>>),
    params(
        GetCredentialQuery
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetCredentialQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetCredentialsResponseDTO> {
    let filtering = match query.filter.try_into() {
        Ok(v) => v,
        Err(err) => {
            return OkOrErrorResponse::from_result(
                Err::<GetCredentialsResponseDTO, _>(err),
                state,
                "getting credential list",
            )
        }
    };

    let filters = GetCredentialQueryDTO {
        pagination: Some(ListPagination {
            page: query.page,
            page_size: query.page_size,
        }),
        sorting: query.sort.map(|column| ListSorting {
            column: column.into(),
            direction: convert_inner(query.sort_direction),
        }),
        filtering: Some(filtering),
        include: query.include.map(convert_inner),
    };

    let result = state
        .core
        .credential_service
        .get_credential_list(filters)
        .await;

    OkOrErrorResponse::from_result(result, state, "getting credential list")
}

#[utoipa::path(
    post,
    path = "/api/credential/v1",
    request_body = CreateCredentialRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_credential(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateCredentialRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .credential_service
        .create_credential(request.into())
        .await;

    CreatedOrErrorResponse::from_result(result, state, "creating credential")
}

#[utoipa::path(
    post,
    path = "/api/credential/v1/{id}/reactivate",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = CredentialId, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn reactivate_credential(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .credential_service
        .reactivate_credential(&id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "reactivating credential")
}

#[utoipa::path(
    post,
    path = "/api/credential/v1/{id}/revoke",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = CredentialId, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn revoke_credential(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state.core.credential_service.revoke_credential(&id).await;
    EmptyOrErrorResponse::from_result(result, state, "revoking credential")
}

#[utoipa::path(
    post,
    path = "/api/credential/v1/{id}/suspend",
    request_body = SuspendCredentialRequestRestDTO,
    responses(EmptyOrErrorResponse),
    params(
        ("id" = CredentialId, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn suspend_credential(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<SuspendCredentialRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .credential_service
        .suspend_credential(&id, request.into())
        .await;
    EmptyOrErrorResponse::from_result(result, state, "suspending credential")
}

#[utoipa::path(
    post,
    path = "/api/credential/v1/{id}/share",
    responses(OkOrErrorResponse<EntityShareResponseRestDTO>),
    params(
        ("id" = CredentialId, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn share_credential(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<EntityShareResponseRestDTO> {
    let result = state.core.credential_service.share_credential(&id).await;
    OkOrErrorResponse::from_result(result, state, "sharing credential")
}

#[utoipa::path(
    post,
    path = "/api/credential/v1/revocation-check",
    request_body = CredentialRevocationCheckRequestRestDTO,
    responses(OkOrErrorResponse<VecResponse<CredentialRevocationCheckResponseRestDTO>>),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn revocation_check(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CredentialRevocationCheckRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<VecResponse<CredentialRevocationCheckResponseRestDTO>> {
    let result = state
        .core
        .credential_service
        .check_revocation(request.credential_ids)
        .await;

    OkOrErrorResponse::from_result(result, state, "checking credentials")
}
