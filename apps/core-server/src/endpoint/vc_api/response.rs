use axum::Json;
use axum::extract::rejection::{FormRejection, JsonRejection, PathRejection, QueryRejection};
use axum::response::IntoResponse;
use one_core::service::error::ServiceError;
use reqwest::StatusCode;
use serde::Serialize;

use super::dto::DidDocumentResolutionResponseDTO;
use super::error::{DidResolverError, VcApiError, VcApiErrorRestDTO};

pub enum VcApiResponse<T: Serialize> {
    Error(VcApiError),
    Ok(T),
    Created(T),
}

impl<T: Serialize> VcApiResponse<T> {
    pub fn created(result: Result<impl Into<T>, ServiceError>) -> Self {
        match result {
            Ok(value) => Self::Created(value.into()),
            Err(error) => Self::Error(error.into()),
        }
    }

    pub fn ok(result: Result<impl Into<T>, ServiceError>) -> Self {
        match result {
            Ok(value) => Self::Ok(value.into()),
            Err(error) => Self::Error(error.into()),
        }
    }
}

impl<T: Serialize> IntoResponse for VcApiResponse<T> {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Ok(value) => (StatusCode::OK, Json(value)).into_response(),
            Self::Created(value) => (StatusCode::CREATED, Json(value)).into_response(),
            Self::Error(error) => error.into_response(),
        }
    }
}

#[derive(Serialize, Debug)]
struct VcApiErrorListResponseDTO {
    pub errors: Vec<VcApiErrorRestDTO>,
}

impl IntoResponse for VcApiError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::UnmappedError(message) => (
                StatusCode::BAD_REQUEST,
                Json(VcApiErrorListResponseDTO {
                    errors: vec![VcApiErrorRestDTO {
                        status: Some(400),
                        title: message,
                        detail: None,
                    }],
                }),
            )
                .into_response(),
            Self::DidResolverError(error) => error.into_response(),
        }
    }
}

impl IntoResponse for DidResolverError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::BAD_REQUEST,
            Json(DidDocumentResolutionResponseDTO::from_error(self)),
        )
            .into_response()
    }
}

macro_rules! gen_from_rejection {
    ($from:ty, $rejection:ty ) => {
        impl From<$from> for $rejection {
            fn from(value: $from) -> Self {
                VcApiError::UnmappedError(value.to_string())
            }
        }
    };
}

gen_from_rejection!(JsonRejection, VcApiError);
gen_from_rejection!(QueryRejection, VcApiError);
gen_from_rejection!(PathRejection, VcApiError);
gen_from_rejection!(FormRejection, VcApiError);
