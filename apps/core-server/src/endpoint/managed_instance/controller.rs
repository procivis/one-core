use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use proc_macros::endpoint;
use shared_types::{ManagedInstanceId, Permission};

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::managed_instance::dto::{
    GetManagedInstancesResponseRestDTO, ListManagedInstancesQuery, ManagedInstanceResponseRestDTO,
};
use crate::extractor::Qs;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::ManagedInstanceList],
    get,
    path = "/api/managed-instance/v1",
    params(ListManagedInstancesQuery),
    tag = "managed_instance",
    security(
        ("bearer" = [])
    ),
    summary = "List managed instances",
    description = indoc::formatdoc! {"
    Returns a list of managed instances.
"},
)]
pub(crate) async fn get_managed_instance_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<ListManagedInstancesQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetManagedInstancesResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .managed_instance_service
                .get_managed_instance_list(query.try_into()?)
                .await
                .error_while("getting managed instances")?,
        )
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting managed instance list")
}

#[endpoint(
    permissions = [Permission::ManagedInstanceDetail],
    get,
    path = "/api/managed-instance/v1/{id}",
    params(
        ("id" = ManagedInstanceId, Path, description = "Managed instance id")
    ),
    tag = "managed_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve a managed instance",
    description = "Returns details on a given managed instance.",
)]
pub(crate) async fn get_managed_instance_details(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ManagedInstanceId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<ManagedInstanceResponseRestDTO> {
    let result = state
        .core
        .managed_instance_service
        .get_managed_instance(&id)
        .await;
    OkOrErrorResponse::from_result(result, state, "fetching managed instance")
}

#[endpoint(
    permissions = [Permission::ManagedInstanceRevoke],
    post,
    path = "/api/managed-instance/v1/{id}/revoke",
    params(
        ("id" = ManagedInstanceId, Path, description = "Managed instance id")
    ),
    tag = "managed_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Revoke a managed instance",
    description = indoc::formatdoc! {"
        Revokes a managed instance, preventing issuance of any new attestation. If Token
        Status List is enabled for WIAs, all existing attestations are revoked as well.
        If the managed instance is a verifier instance, its linked access certificates are
        revoked as well.
    "},
)]
pub(crate) async fn revoke_managed_instance(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ManagedInstanceId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .managed_instance_service
        .revoke_managed_instance(&id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "revoking managed instance")
}

#[endpoint(
    permissions = [Permission::ManagedInstanceDelete],
    delete,
    path = "/api/managed-instance/v1/{id}",
    params(
        ("id" = ManagedInstanceId, Path, description = "Managed instance id")
    ),
    tag = "managed_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Delete a managed instance",
    description = indoc::formatdoc! {"
        Permanently deletes a given managed instance from the database, including history
        entries. If the managed instance is a verifier instance, its linked access
        certificates are revoked as well.
    "},
)]
pub(crate) async fn delete_managed_instance(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ManagedInstanceId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .managed_instance_service
        .delete_managed_instance(&id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "deleting managed instance")
}
