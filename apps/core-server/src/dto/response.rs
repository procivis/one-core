use std::collections::BTreeMap;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use one_core::provider::credential_formatter::error::FormatterError;
use one_core::provider::did_method::error::DidMethodProviderError;
use one_core::provider::issuance_protocol::error::IssuanceProtocolError;
use one_core::service::error::{
    BusinessLogicError, ErrorCode, MissingProviderError, ServiceError, ValidationError,
};
use one_dto_mapper::convert_inner;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::{Cause, ErrorResponseRestDTO};
use crate::router::AppState;

#[derive(utoipa::IntoResponses)]
pub(crate) enum ErrorResponse {
    #[response(status = 401, description = "Unauthorized")]
    #[allow(dead_code)]
    Unauthorized,
    #[response(status = 400, description = "Bad Request")]
    BadRequest(#[to_schema] ErrorResponseRestDTO),
    #[response(status = 403, description = "Forbidden")]
    Forbidden,
    #[response(status = 404, description = "Entity Not Found")]
    NotFound(#[to_schema] ErrorResponseRestDTO),
    #[response(status = 500, description = "Internal error")]
    ServerError(#[to_schema] ErrorResponseRestDTO),
}

impl ErrorResponse {
    pub fn for_panic(panic_msg: String) -> Self {
        Self::ServerError(ErrorResponseRestDTO {
            code: ErrorCode::BR_0000.into(),
            message: panic_msg,
            cause: Some(Cause {
                message: "Panic".to_string(),
            }),
        })
    }

    fn from_service_error(error: ServiceError, hide_cause: bool) -> Self {
        let response = ErrorResponseRestDTO::from(&error).hide_cause(hide_cause);
        match error {
            ServiceError::EntityNotFound(_) => Self::NotFound(response),
            ServiceError::MissingProvider(MissingProviderError::DidMethod(_))
            | ServiceError::DidMethodProviderError(DidMethodProviderError::MissingProvider(_))
            | ServiceError::Validation(ValidationError::MissingLayoutAttribute(_))
            | ServiceError::BusinessLogic(BusinessLogicError::MissingTrustEntity(_)) => {
                Self::NotFound(response)
            }
            ServiceError::Validation(ValidationError::Forbidden) => Self::Forbidden,
            ServiceError::Validation(_)
            | ServiceError::ValidationError(_)
            | ServiceError::BusinessLogic(_)
            | ServiceError::FormatterError(FormatterError::BBSOnly)
            | ServiceError::ConfigValidationError(_)
            | ServiceError::IssuanceProtocolError(
                IssuanceProtocolError::OperationNotSupported
                | IssuanceProtocolError::TxCode(_)
                | IssuanceProtocolError::CredentialVerificationFailed(_)
                | IssuanceProtocolError::DidMismatch
                | IssuanceProtocolError::RefreshTooSoon
                | IssuanceProtocolError::Suspended
                | IssuanceProtocolError::InvalidRequest(_),
            )
            | ServiceError::TrustManagementError(_)
            | ServiceError::WalletProviderError(_) => Self::BadRequest(response),
            _ => Self::ServerError(response),
        }
    }

    #[track_caller]
    fn from_service_error_with_trace(
        error: ServiceError,
        state: State<AppState>,
        action_description: &str,
    ) -> Self {
        let location = std::panic::Location::caller();
        tracing::error!(%error, %location, "Error while {action_description}");
        Self::from_service_error(error, state.config.hide_error_response_cause)
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            Self::BadRequest(error) => (StatusCode::BAD_REQUEST, Json(error)).into_response(),
            Self::NotFound(error) => (StatusCode::NOT_FOUND, Json(error)).into_response(),
            Self::ServerError(error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
            }
            Self::Forbidden => StatusCode::FORBIDDEN.into_response(),
        }
    }
}

fn with_error_responses<SuccessResponse: utoipa::IntoResponses>()
-> BTreeMap<String, utoipa::openapi::RefOr<utoipa::openapi::Response>> {
    use utoipa::IntoResponses;
    let mut responses = SuccessResponse::responses();
    responses.append(&mut ErrorResponse::responses());
    responses
}

/// Wrapper for Swagger declaration of a vector response
pub(crate) struct VecResponse<T>(Vec<T>);

impl<T, F: Into<T>> From<Vec<F>> for VecResponse<T> {
    fn from(value: Vec<F>) -> Self {
        Self(convert_inner(value))
    }
}

pub(crate) enum OkOrErrorResponse<T> {
    Ok(T),
    Error(ErrorResponse),
}

impl<T> OkOrErrorResponse<T> {
    pub fn ok(value: impl Into<T>) -> Self {
        Self::Ok(value.into())
    }

    pub fn from_service_error(error: ServiceError, hide_cause: bool) -> Self {
        Self::Error(ErrorResponse::from_service_error(error, hide_cause))
    }

    #[track_caller]
    pub(crate) fn from_result(
        result: Result<impl Into<T>, ServiceError>,
        state: State<AppState>,
        action_description: &str,
    ) -> Self {
        match result {
            Ok(value) => Self::ok(value),
            Err(error) => Self::Error(ErrorResponse::from_service_error_with_trace(
                error,
                state,
                action_description,
            )),
        }
    }

    #[track_caller]
    pub(crate) fn from_result_fallible(
        result: Result<impl TryInto<T, Error = impl Into<ServiceError>>, ServiceError>,
        state: State<AppState>,
        action_description: &str,
    ) -> Self {
        let result = result.and_then(|r| r.try_into().map_err(Into::into));

        match result {
            Ok(value) => Self::ok(value),
            Err(error) => Self::Error(ErrorResponse::from_service_error_with_trace(
                error,
                state,
                action_description,
            )),
        }
    }
}

impl<T: Serialize> IntoResponse for OkOrErrorResponse<T> {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Ok(body) => (StatusCode::OK, Json(body)).into_response(),
            Self::Error(error) => error.into_response(),
        }
    }
}

impl<T: Serialize> IntoResponse for OkOrErrorResponse<VecResponse<T>> {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Ok(body) => (StatusCode::OK, Json(body.0)).into_response(),
            Self::Error(error) => error.into_response(),
        }
    }
}

impl<T: ToSchema> utoipa::IntoResponses for OkOrErrorResponse<T> {
    fn responses() -> BTreeMap<String, utoipa::openapi::RefOr<utoipa::openapi::Response>> {
        #[derive(utoipa::IntoResponses)]
        #[response(status = 200, description = "OK")]
        struct SuccessResponse<T: ToSchema>(#[to_schema] T);

        with_error_responses::<SuccessResponse<T>>()
    }
}

impl<T: ToSchema> utoipa::IntoResponses for OkOrErrorResponse<VecResponse<T>> {
    fn responses() -> BTreeMap<String, utoipa::openapi::RefOr<utoipa::openapi::Response>> {
        #[derive(utoipa::IntoResponses)]
        #[response(status = 200, description = "OK")]
        struct SuccessResponse<T: ToSchema>(
            #[to_schema]
            #[allow(dead_code)]
            Vec<T>,
        );

        with_error_responses::<SuccessResponse<T>>()
    }
}

impl<T> From<ErrorResponse> for OkOrErrorResponse<T> {
    fn from(value: ErrorResponse) -> Self {
        Self::Error(value)
    }
}

pub(crate) enum CreatedOrErrorResponse<T> {
    Created(T),
    Error(ErrorResponse),
}

impl<T> CreatedOrErrorResponse<T> {
    pub fn created(value: impl Into<T>) -> Self {
        Self::Created(value.into())
    }

    pub fn from_service_error(error: ServiceError, hide_cause: bool) -> Self {
        Self::Error(ErrorResponse::from_service_error(error, hide_cause))
    }

    #[track_caller]
    pub(crate) fn from_result(
        result: Result<impl Into<T>, ServiceError>,
        state: State<AppState>,
        action_description: &str,
    ) -> Self {
        match result {
            Ok(value) => Self::created(value),
            Err(error) => Self::Error(ErrorResponse::from_service_error_with_trace(
                error,
                state,
                action_description,
            )),
        }
    }
}

impl<T: Serialize> IntoResponse for CreatedOrErrorResponse<T> {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Created(body) => (StatusCode::CREATED, Json(body)).into_response(),
            Self::Error(error) => error.into_response(),
        }
    }
}

impl<T: ToSchema> utoipa::IntoResponses for CreatedOrErrorResponse<T> {
    fn responses() -> BTreeMap<String, utoipa::openapi::RefOr<utoipa::openapi::Response>> {
        #[derive(utoipa::IntoResponses)]
        #[response(status = 201, description = "Created")]
        struct SuccessResponse<T: ToSchema>(#[to_schema] T);

        with_error_responses::<SuccessResponse<T>>()
    }
}

impl<T> From<ErrorResponse> for CreatedOrErrorResponse<T> {
    fn from(value: ErrorResponse) -> Self {
        Self::Error(value)
    }
}

pub(crate) enum EmptyOrErrorResponse {
    NoContent,
    Error(ErrorResponse),
}

impl EmptyOrErrorResponse {
    pub fn from_service_error(error: ServiceError, hide_cause: bool) -> Self {
        Self::Error(ErrorResponse::from_service_error(error, hide_cause))
    }

    #[track_caller]
    pub(crate) fn from_result(
        result: Result<(), ServiceError>,
        state: State<AppState>,
        action_description: &str,
    ) -> Self {
        match result {
            Ok(_) => Self::NoContent,
            Err(error) => Self::Error(ErrorResponse::from_service_error_with_trace(
                error,
                state,
                action_description,
            )),
        }
    }
}

impl IntoResponse for EmptyOrErrorResponse {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::NoContent => StatusCode::NO_CONTENT.into_response(),
            Self::Error(error) => error.into_response(),
        }
    }
}

impl utoipa::IntoResponses for EmptyOrErrorResponse {
    fn responses() -> BTreeMap<String, utoipa::openapi::RefOr<utoipa::openapi::Response>> {
        #[derive(utoipa::IntoResponses)]
        #[response(status = 204, description = "No Content")]
        struct SuccessResponse;

        with_error_responses::<SuccessResponse>()
    }
}

impl From<ErrorResponse> for EmptyOrErrorResponse {
    fn from(value: ErrorResponse) -> Self {
        Self::Error(value)
    }
}
