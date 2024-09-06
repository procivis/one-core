use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use one_core::service::error::ServiceError;
use one_core::service::key::dto::KeyListItemResponseDTO;
use shared_types::KeyId;

use super::dto::{GetKeyQuery, KeyCheckCertificateRequestRestDTO};
use crate::dto::common::{EntityResponseRestDTO, GetKeyListResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{
    declare_utoipa_alias, AliasResponse, CreatedOrErrorResponse, EmptyOrErrorResponse,
    OkOrErrorResponse,
};
use crate::endpoint::key::dto::{
    KeyGenerateCSRRequestRestDTO, KeyGenerateCSRResponseRestDTO, KeyListItemResponseRestDTO,
    KeyRequestRestDTO, KeyResponseRestDTO,
};
use crate::extractor::Qs;
use crate::mapper::list_try_from;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/key/v1/{id}",
    responses(OkOrErrorResponse<KeyResponseRestDTO>),
    params(
        ("id" = KeyId, Path, description = "Key id")
    ),
    tag = "key",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_key(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<KeyId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<KeyResponseRestDTO> {
    let result = state.core.key_service.get_key(&id).await;

    match result {
        Ok(value) => match KeyResponseRestDTO::try_from(value) {
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
            tracing::error!("Error while getting key: {:?}", error);
            OkOrErrorResponse::from_service_error(error, state.config.hide_error_response_cause)
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/key/v1",
    request_body = KeyRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "key",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_key(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<Json<KeyRequestRestDTO>, ErrorResponseRestDTO>,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state.core.key_service.generate_key(request.into()).await;
    CreatedOrErrorResponse::from_result(result, state, "creating key")
}

declare_utoipa_alias!(GetKeyListResponseRestDTO);

#[utoipa::path(
    get,
    path = "/api/key/v1",
    responses(OkOrErrorResponse<AliasResponse<GetKeyListResponseRestDTO>>),
    params(GetKeyQuery),
    tag = "key",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_key_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetKeyQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetKeyListResponseRestDTO> {
    let result = state.core.key_service.get_key_list(query.into()).await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting keys: {:?}", error);
            OkOrErrorResponse::from_service_error(error, state.config.hide_error_response_cause)
        }
        Ok(value) => {
            match list_try_from::<KeyListItemResponseRestDTO, KeyListItemResponseDTO>(value) {
                Ok(value) => OkOrErrorResponse::ok(value),
                Err(error) => {
                    tracing::error!("Error while encoding base64: {:?}", error);
                    OkOrErrorResponse::from_service_error(
                        ServiceError::MappingError(error.to_string()),
                        state.config.hide_error_response_cause,
                    )
                }
            }
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/key/v1/{id}/check-certificate",
    request_body = KeyCheckCertificateRequestRestDTO,
    responses(EmptyOrErrorResponse),
    params(
        ("id" = KeyId, Path, description = "Key id")
    ),
    tag = "key",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn check_certificate(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<KeyId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<KeyCheckCertificateRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .key_service
        .check_certificate(&id, request.into())
        .await;

    EmptyOrErrorResponse::from_result(result, state, "checking certificate")
}

#[utoipa::path(
    post,
    path = "/api/key/v1/{id}/generate-csr",
    request_body = KeyGenerateCSRRequestRestDTO,
    responses(OkOrErrorResponse<KeyGenerateCSRResponseRestDTO>),
    params(
        ("id" = KeyId, Path, description = "Key id")
    ),
    tag = "key",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn generate_csr(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<KeyId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<KeyGenerateCSRRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<KeyGenerateCSRResponseRestDTO> {
    let result = state
        .core
        .key_service
        .generate_csr(&id, request.into())
        .await;

    match result {
        Ok(value) => OkOrErrorResponse::ok(KeyGenerateCSRResponseRestDTO::from(value)),
        Err(error) => {
            tracing::error!("Error while getting key: {:?}", error);
            OkOrErrorResponse::from_service_error(error, state.config.hide_error_response_cause)
        }
    }
}
