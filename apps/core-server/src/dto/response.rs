use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use std::collections::BTreeMap;
use utoipa::ToSchema;

use super::error::ErrorResponseRestDTO;
use crate::router::AppState;
use one_core::service::error::ServiceError;

#[derive(utoipa::IntoResponses)]
pub enum ErrorResponse {
    #[response(status = 401, description = "Unauthorized")]
    Unauthorized,
    #[response(status = 400, description = "Bad Request")]
    BadRequest(#[to_schema] ErrorResponseRestDTO),
    #[response(status = 404, description = "Entity Not Found")]
    NotFound(#[to_schema] ErrorResponseRestDTO),
    #[response(status = 500, description = "Internal error")]
    ServerError(#[to_schema] ErrorResponseRestDTO),
}

impl ErrorResponse {
    fn from_service_error(error: ServiceError, hide_cause: bool) -> Self {
        let error: ErrorResponseRestDTO = ErrorResponseRestDTO::from(error).hide_cause(hide_cause);
        match &error.error {
            ServiceError::EntityNotFound(_) | ServiceError::NotFound => Self::NotFound(error),
            ServiceError::Validation(_)
            | ServiceError::BusinessLogic(_)
            | ServiceError::IncorrectParameters => Self::BadRequest(error),
            _ => Self::ServerError(error),
        }
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
        }
    }
}

pub enum OkOrErrorResponse<T: for<'a> ToSchema<'a>> {
    Ok(T),
    Error(ErrorResponse),
}

impl<T> OkOrErrorResponse<T>
where
    T: for<'a> ToSchema<'a> + Serialize,
{
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
            Err(error) => {
                tracing::error!(%error, "Error while {action_description}");
                Self::from_service_error(error, state.config.hide_error_response_cause)
            }
        }
    }
}

impl<T> IntoResponse for OkOrErrorResponse<T>
where
    T: for<'a> ToSchema<'a> + Serialize,
{
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Ok(body) => (StatusCode::OK, Json(body)).into_response(),
            Self::Error(error) => error.into_response(),
        }
    }
}

impl<T> utoipa::IntoResponses for OkOrErrorResponse<T>
where
    T: for<'a> ToSchema<'a> + Serialize,
{
    fn responses() -> BTreeMap<String, utoipa::openapi::RefOr<utoipa::openapi::Response>> {
        #[derive(utoipa::IntoResponses)]
        enum SuccessResponse<T: for<'a> ToSchema<'a>> {
            #[response(status = 200, description = "OK")]
            _Ok(#[to_schema] T),
        }

        let mut responses = SuccessResponse::<T>::responses();
        responses.append(&mut ErrorResponse::responses());
        responses
    }
}

pub enum CreatedOrErrorResponse<T: for<'a> ToSchema<'a>> {
    Created(T),
    Error(ErrorResponse),
}

impl<T> CreatedOrErrorResponse<T>
where
    T: for<'a> ToSchema<'a> + Serialize,
{
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
            Err(error) => {
                tracing::error!(%error, "Error while {action_description}");
                Self::from_service_error(error, state.config.hide_error_response_cause)
            }
        }
    }
}

impl<T> IntoResponse for CreatedOrErrorResponse<T>
where
    T: for<'a> ToSchema<'a> + Serialize,
{
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Created(body) => (StatusCode::CREATED, Json(body)).into_response(),
            Self::Error(error) => error.into_response(),
        }
    }
}

impl<T> utoipa::IntoResponses for CreatedOrErrorResponse<T>
where
    T: for<'a> ToSchema<'a> + Serialize,
{
    fn responses() -> BTreeMap<String, utoipa::openapi::RefOr<utoipa::openapi::Response>> {
        #[derive(utoipa::IntoResponses)]
        enum SuccessResponse<T: for<'a> ToSchema<'a>> {
            #[response(status = 201, description = "Created")]
            _Created(#[to_schema] T),
        }

        let mut responses = SuccessResponse::<T>::responses();
        responses.append(&mut ErrorResponse::responses());
        responses
    }
}

pub enum EmptyOrErrorResponse {
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
            Err(error) => {
                tracing::error!(%error, "Error while {action_description}");
                Self::from_service_error(error, state.config.hide_error_response_cause)
            }
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
        enum SuccessResponse {
            #[response(status = 204, description = "No Content")]
            _NoContent,
        }

        let mut responses = SuccessResponse::responses();
        responses.append(&mut ErrorResponse::responses());
        responses
    }
}
