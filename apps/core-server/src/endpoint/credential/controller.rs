use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use crate::dto::common::{
    EntityResponseRestDTO, EntityShareResponseRestDTO, GetCredentialsResponseDTO,
};
use crate::dto::response::{
    declare_utoipa_alias, AliasResponse, CreatedOrErrorResponse, EmptyOrErrorResponse,
    OkOrErrorResponse, VecResponse,
};
use crate::endpoint::credential::dto::{
    CreateCredentialRequestRestDTO, GetCredentialQuery, GetCredentialResponseRestDTO,
};
use crate::extractor::Qs;

use crate::router::AppState;

use super::dto::{
    CredentialRevocationCheckRequestRestDTO, CredentialRevocationCheckResponseRestDTO,
};

#[utoipa::path(
    delete,
    path = "/api/credential/v1/{id}",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn delete_credential(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> EmptyOrErrorResponse {
    let result = state.core.credential_service.delete_credential(&id).await;
    EmptyOrErrorResponse::from_result(result, state, "deleting credential")
}

#[utoipa::path(
    get,
    path = "/api/credential/v1/{id}",
    responses(OkOrErrorResponse<GetCredentialResponseRestDTO>),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential(
    state: State<AppState>,
    Path(id): Path<Uuid>,
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
    Qs(query): Qs<GetCredentialQuery>,
) -> OkOrErrorResponse<GetCredentialsResponseDTO> {
    let result = state
        .core
        .credential_service
        .get_credential_list(query.into())
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
    Json(request): Json<CreateCredentialRequestRestDTO>,
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
    path = "/api/credential/v1/{id}/revoke",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn revoke_credential(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> EmptyOrErrorResponse {
    let result = state.core.credential_service.revoke_credential(&id).await;
    EmptyOrErrorResponse::from_result(result, state, "revoking credential")
}

#[utoipa::path(
    post,
    path = "/api/credential/v1/{id}/share",
    responses(OkOrErrorResponse<EntityShareResponseRestDTO>),
    params(
        ("id" = Uuid, Path, description = "Credential id")
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn share_credential(
    state: State<AppState>,
    Path(id): Path<Uuid>,
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
    Json(request): Json<CredentialRevocationCheckRequestRestDTO>,
) -> OkOrErrorResponse<VecResponse<CredentialRevocationCheckResponseRestDTO>> {
    let result = state
        .core
        .credential_service
        .check_revocation(request.credential_ids)
        .await;

    OkOrErrorResponse::from_result(result, state, "checking credentials")
}
