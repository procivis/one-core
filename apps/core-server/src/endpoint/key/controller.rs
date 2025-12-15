use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use one_core::service::key::dto::KeyListItemResponseDTO;
use proc_macros::require_permissions;
use shared_types::KeyId;

use super::dto::GetKeyQuery;
use crate::dto::common::{EntityResponseRestDTO, GetKeyListResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::{CreatedOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::key::dto::{
    KeyGenerateCSRRequestRestDTO, KeyGenerateCSRResponseRestDTO, KeyListItemResponseRestDTO,
    KeyRequestRestDTO, KeyResponseRestDTO,
};
use crate::extractor::Qs;
use crate::mapper::list_try_from;
use crate::permissions::Permission;
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
    summary = "Retrieve key",
    description = "Returns detailed information about a key.",
)]
#[require_permissions(Permission::KeyDetail)]
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
                OkOrErrorResponse::from_error(
                    &ServiceError::MappingError(error.to_string()),
                    state.config.hide_error_response_cause,
                )
            }
        },
        Err(error) => {
            tracing::error!("Error while getting key: {:?}", error);
            OkOrErrorResponse::from_error(&error, state.config.hide_error_response_cause)
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
    summary = "Create a key",
    description = indoc::formatdoc! {"
    Creates a key within an organization, which can be used to create a DID.

    The `keyType` and `storageType` values must reference specific configuration
    instances from your system configuration. This is because the system allows
    multiple configurations of the same type.

    Related guide: [Keys](/keys)
"},
)]
#[require_permissions(Permission::KeyCreate)]
pub(crate) async fn post_key(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<Json<KeyRequestRestDTO>, ErrorResponseRestDTO>,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = async {
        state
            .core
            .key_service
            .create_key(request.try_into().error_while("mapping request")?)
            .await
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "creating key")
}

#[utoipa::path(
    get,
    path = "/api/key/v1",
    responses(OkOrErrorResponse<GetKeyListResponseRestDTO>),
    params(GetKeyQuery),
    tag = "key",
    security(
        ("bearer" = [])
    ),
    summary = "List keys",
    description = "Returns a list of keys created in an organization.",
)]
#[require_permissions(Permission::KeyList)]
pub(crate) async fn get_key_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetKeyQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetKeyListResponseRestDTO> {
    let result = async {
        let organisation_id = fallback_organisation_id_from_session(query.filter.organisation_id)
            .error_while("mapping organisation from session")?;
        state
            .core
            .key_service
            .get_key_list(
                &organisation_id,
                query.try_into().error_while("mapping query")?,
            )
            .await
    }
    .await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting keys: {:?}", error);
            OkOrErrorResponse::from_error(&error, state.config.hide_error_response_cause)
        }
        Ok(value) => {
            match list_try_from::<KeyListItemResponseRestDTO, KeyListItemResponseDTO>(value) {
                Ok(value) => OkOrErrorResponse::ok(value),
                Err(error) => {
                    tracing::error!("Error while encoding base64: {:?}", error);
                    OkOrErrorResponse::from_error(
                        &ServiceError::MappingError(error.to_string()),
                        state.config.hide_error_response_cause,
                    )
                }
            }
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/key/v1/{id}/generate-csr",
    request_body = KeyGenerateCSRRequestRestDTO,
    responses(CreatedOrErrorResponse<KeyGenerateCSRResponseRestDTO>),
    params(
        ("id" = KeyId, Path, description = "Key id. Must be either `ECDSA` or `EDDSA`.")
    ),
    tag = "key",
    security(
        ("bearer" = [])
    ),
    summary = "Generate a CSR",
    description = indoc::formatdoc! {"
        Generates a Certificate Signing Request (CSR). These are used to create mDL DS certificates, enabling mdoc issuance.
        Related guide: [ISO mdoc configuration](/configure/iso-mdoc)
    "},
)]
#[require_permissions(Permission::KeyGenerateCsr)]
pub(crate) async fn generate_csr(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<KeyId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<KeyGenerateCSRRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<KeyGenerateCSRResponseRestDTO> {
    let result = state
        .core
        .key_service
        .generate_csr(&id, request.into())
        .await;

    match result {
        Ok(value) => CreatedOrErrorResponse::created(KeyGenerateCSRResponseRestDTO::from(value)),
        Err(error) => {
            tracing::error!("Error while getting key: {:?}", error);
            CreatedOrErrorResponse::from_error(&error, state.config.hide_error_response_cause)
        }
    }
}
