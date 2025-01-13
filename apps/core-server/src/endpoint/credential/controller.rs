use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::service::credential::dto::GetCredentialQueryDTO;
use one_dto_mapper::convert_inner;
use shared_types::CredentialId;

use super::dto::{
    BypassCacheQueryRestDTO, CredentialRevocationCheckRequestRestDTO,
    CredentialRevocationCheckResponseRestDTO,
};
use crate::dto::common::{
    EntityResponseRestDTO, EntityShareResponseRestDTO, GetCredentialsResponseDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{
    CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse, VecResponse,
};
use crate::endpoint::credential::dto::{
    CreateCredentialRequestRestDTO, GetCredentialQuery, GetCredentialResponseRestDTO,
    SuspendCredentialRequestRestDTO,
};
use crate::extractor::{Qs, QsOpt};
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
    summary = "Delete a credential",
    description = indoc::formatdoc! {"
        Prevents a credential from being returned when retrieving a list of credentials. The credential maintains its state in the
        system and can be retrieved by its ID. This has no impact on the holder's ability to keep and use the credential. Deletion cannot
        be completed if the credential state is `ACCEPTED` while the corresponding credential schema includes a revocation method. If revocation
        method is `NONE`, the credential can be deleted in any state.
    "},
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
    summary = "Retrieve a credential",
    description = "Returns detailed information on a credential.",
)]
pub(crate) async fn get_credential(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetCredentialResponseRestDTO> {
    let result = state.core.credential_service.get_credential(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting credential")
}

#[utoipa::path(
    get,
    path = "/api/credential/v1",
    responses(OkOrErrorResponse<GetCredentialsResponseDTO>),
    params(
        GetCredentialQuery
    ),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
    summary = "List credentials",
    description = "Returns a list of credentials within an organization. See the [guidelines](../api/guidelines.mdx) for handling list endpoints.",
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
    summary = "Create a credential",
    description = "Creates a credential, which can then be issued to a wallet holder.",
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
    summary = "Reactivate a credential",
    description = indoc::formatdoc! {"
        Reactivates a suspended credential.
        See the [suspension and reactivation](../api/credentials.mdx#suspension-and-reactivation) guide for more information.
    "},
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
    summary = "Revoke a credential",
    description = indoc::formatdoc! {"
        Changes a credential state to `REVOKED`.
        See the [credential states](../api/credentials.mdx#credential-states) guide.
    "},
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
    summary = "Suspend a credential",
    description = indoc::formatdoc! {"
        Suspends a credential, rendering it invalid until it has been reactivated.
        See the [suspension and reactivation](../api/credentials.mdx#suspension-and-reactivation) guide for more information.
    "},
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
    summary = "Issue a credential",
    description = "Creates a share endpoint URL. A wallet holder can use this to access the offered credential.",
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
    params(BypassCacheQueryRestDTO),
    responses(OkOrErrorResponse<VecResponse<CredentialRevocationCheckResponseRestDTO>>),
    tag = "credential_management",
    security(
        ("bearer" = [])
    ),
    summary = "Check revocation",
    description = indoc::formatdoc! {"
        Checks whether a held credential has been revoked. Only applicable to
        credentials with an associated revocation mechanism.
    "},
)]
pub(crate) async fn revocation_check(
    state: State<AppState>,
    WithRejection(QsOpt(query), _): WithRejection<
        QsOpt<BypassCacheQueryRestDTO>,
        ErrorResponseRestDTO,
    >,
    WithRejection(Json(request), _): WithRejection<
        Json<CredentialRevocationCheckRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<VecResponse<CredentialRevocationCheckResponseRestDTO>> {
    let result = state
        .core
        .credential_service
        .check_revocation(request.credential_ids, query.into())
        .await;

    OkOrErrorResponse::from_result(result, state, "checking credentials")
}
