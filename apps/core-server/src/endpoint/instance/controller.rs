use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use proc_macros::endpoint;
use shared_types::{InstanceId, Permission};

use super::dto::{
    ActivateInstanceRequestRestDTO, ActivateInstanceResponseRestDTO, InstanceDetailRestDTO,
    RegisterInstanceResponseRestDTO, RegisterManagedInstanceRequestRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::InstanceRegister],
    post,
    path = "/api/instance/v1",
    request_body = RegisterManagedInstanceRequestRestDTO,
    responses(CreatedOrErrorResponse<RegisterInstanceResponseRestDTO>),
    tag = "instance",
    security(
        ("bearer" = [])
    ),
    summary = "Register with a Wallet Provider",
    description = indoc::formatdoc! {"
        Register a wallet instance with a Wallet Provider.
    "},
)]
pub(crate) async fn register_remote_instance(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<RegisterManagedInstanceRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<RegisterInstanceResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .instance_service
                .register_instance(request.try_into()?)
                .await
                .error_while("registering holder wallet instance")?,
        )
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "register wallet instance")
}

#[endpoint(
    permissions = [Permission::InstanceDetail],
    get,
    path = "/api/instance/v1/{id}",
    responses(OkOrErrorResponse<InstanceDetailRestDTO>),
    params(
        ("id" = InstanceId, Path, description = "Wallet Instance ID")
    ),
    tag = "instance",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve wallet registration details",
    description = "Retrieve details of a wallet instance's registration from the Wallet Provider.",
)]
pub(crate) async fn get_instance_details(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<InstanceId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<InstanceDetailRestDTO> {
    let result = state
        .core
        .instance_service
        .holder_get_instance_details(id)
        .await
        .error_while("getting holder wallet instance")
        .map_err(ServiceError::from);

    OkOrErrorResponse::from_result_fallible(result, state, "getting holder wallet instance")
}

#[endpoint(
    permissions = [Permission::InstanceDetail],
    post,
    path = "/api/instance/v1/{id}/status",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = InstanceId, Path, description = "Wallet Instance ID")
    ),
    tag = "instance",
    security(
        ("bearer" = [])
    ),
    summary = "Check wallet status",
    description = indoc::formatdoc! {
        "Check the status of a wallet instance. Active instances return `204`. Revoked instances return an error."},
)]
pub(crate) async fn instance_status(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<InstanceId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state.core.instance_service.holder_instance_status(id).await;

    EmptyOrErrorResponse::from_result(result, state, "holder wallet instance status check")
}

#[endpoint(
    permissions = [Permission::InstanceRegister],
    post,
    path = "/api/instance/v1/{id}/activate",
    request_body = ActivateInstanceRequestRestDTO,
    responses(OkOrErrorResponse<ActivateInstanceResponseRestDTO>),
    params(
        ("id" = InstanceId, Path, description = "Wallet Instance ID")
    ),
    tag = "instance",
    security(
        ("bearer" = [])
    ),
    summary = "Activate wallet instance",
    description = indoc::formatdoc! {"
        Complete registration by activating the wallet instance with the Wallet Provider.
        Required when the Wallet Provider has user authentication configured.
    "},
)]
pub(crate) async fn activate_remote_instance(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<InstanceId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<ActivateInstanceRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<ActivateInstanceResponseRestDTO> {
    let result = state
        .core
        .instance_service
        .holder_activate(id, request.into())
        .await;

    OkOrErrorResponse::from_result(result, state, "activating holder wallet instance")
}
