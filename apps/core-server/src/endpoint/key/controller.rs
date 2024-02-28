use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use shared_types::KeyId;
use uuid::Uuid;

use one_core::service::error::ServiceError;
use one_core::service::key::dto::KeyListItemResponseDTO;

use crate::dto::common::{EntityResponseRestDTO, GetKeyListResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{
    declare_utoipa_alias, AliasResponse, CreatedOrErrorResponse, OkOrErrorResponse,
};
use crate::endpoint::key::dto::{
    KeyListItemResponseRestDTO, KeyRequestRestDTO, KeyResponseRestDTO,
};
use crate::extractor::Qs;
use crate::mapper::list_try_from;

use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/key/v1/{id}",
    responses(OkOrErrorResponse<KeyResponseRestDTO>),
    params(
        ("id" = Uuid, Path, description = "Key id")
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

use super::dto::GetKeyQuery;

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
    CreatedOrErrorResponse::from_result(result.map(Uuid::from), state, "creating key")
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
