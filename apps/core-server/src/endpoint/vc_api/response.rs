use std::collections::BTreeMap;

use axum::extract::rejection::{FormRejection, JsonRejection, PathRejection, QueryRejection};
use axum::http::StatusCode;
use axum::{response::IntoResponse, Json};
use one_core::service::error::ServiceError;
use one_providers::did::error::{DidMethodError, DidMethodProviderError};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::dto::response::ErrorResponse;

use super::dto::{DidResolutionMetadataResponseDto, VcApiDidDocumentRestDTO};

pub enum VcApiResponse<T> {
    Error(VcApiErrorResponseRestDTO),
    Ok(T),
}

impl<T> VcApiResponse<T> {
    pub fn from_result(result: Result<impl Into<T>, ServiceError>) -> Self {
        match result {
            Ok(value) => Self::Ok(value.into()),
            Err(error) => Self::Error(error.into()),
        }
    }
}

impl<T: Serialize> IntoResponse for VcApiResponse<T> {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Error(error) => (StatusCode::BAD_REQUEST, Json(error)).into_response(),
            Self::Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VcApiErrorResponseRestDTO {
    #[serde(rename = "@context")]
    context: Vec<String>,
    did_document: VcApiDidDocumentRestDTO,
    did_document_metadata: Option<DidResolutionMetadataResponseDto>,
    did_resolution_metadata: Option<DidResolutionMetadataResponseDto>,
}

impl From<ServiceError> for VcApiErrorResponseRestDTO {
    fn from(value: ServiceError) -> Self {
        let message = match value {
            ServiceError::MissingProvider(_) => "methodNotSupported".to_string(),
            ServiceError::DidMethodProviderError(e) => match e {
                DidMethodProviderError::MissingProvider(_) => "methodNotSupported".to_string(),
                DidMethodProviderError::DidMethod(e) => match e {
                    DidMethodError::ResolutionError(m) => match m {
                        _ if m.contains("Invalid multicodec") => "invalidDid".to_string(),
                        _ if m.contains("Unsupported key") => "invalidPublicKeyLength".to_string(),
                        _ => "invalidDid".to_string(),
                    },
                    _ => "invalidDid".to_string(),
                },
                _ => "invalidDid".to_string(),
            },
            _ => value.to_string(),
        };

        Self {
            context: vec!["https://w3id.org/did-resolution/v1".to_string()],
            did_document: VcApiDidDocumentRestDTO { document: None },
            did_resolution_metadata: Some(DidResolutionMetadataResponseDto {
                content_type: "application/did+ld+json".to_string(),
                error: Some(message),
            }),
            did_document_metadata: None,
        }
    }
}

impl IntoResponse for VcApiErrorResponseRestDTO {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

impl From<(StatusCode, String)> for VcApiErrorResponseRestDTO {
    fn from(value: (StatusCode, String)) -> Self {
        Self {
            context: vec!["https://w3id.org/did-resolution/v1".to_string()],
            did_document: VcApiDidDocumentRestDTO { document: None },
            did_document_metadata: None,
            did_resolution_metadata: Some(DidResolutionMetadataResponseDto {
                content_type: "application/did+ld+json".to_string(),
                error: Some(value.1.to_string()),
            }),
        }
    }
}

impl<T: for<'a> ToSchema<'a>> utoipa::IntoResponses for VcApiResponse<T> {
    fn responses() -> BTreeMap<String, utoipa::openapi::RefOr<utoipa::openapi::Response>> {
        #[derive(utoipa::IntoResponses)]
        #[response(status = 200, description = "Ok")]
        struct SuccessResponse<T: for<'a> ToSchema<'a>>(#[to_schema] T);

        with_error_responses::<SuccessResponse<T>>()
    }
}

fn with_error_responses<SuccessResponse: utoipa::IntoResponses>(
) -> BTreeMap<String, utoipa::openapi::RefOr<utoipa::openapi::Response>> {
    use utoipa::IntoResponses;
    let mut responses = SuccessResponse::responses();
    responses.append(&mut ErrorResponse::responses());
    responses
}

macro_rules! gen_from_rejection {
    ($from:ty, $rejection:ty ) => {
        impl From<$from> for $rejection {
            fn from(value: $from) -> Self {
                Self {
                    context: vec!["https://w3id.org/did-resolution/v1".to_string()],
                    did_document: VcApiDidDocumentRestDTO { document: None },
                    did_document_metadata: None,
                    did_resolution_metadata: Some(DidResolutionMetadataResponseDto {
                        content_type: "application/did+ld+json".to_string(),
                        error: Some(value.to_string()),
                    }),
                }
            }
        }
    };
}

gen_from_rejection!(JsonRejection, VcApiErrorResponseRestDTO);
gen_from_rejection!(QueryRejection, VcApiErrorResponseRestDTO);
gen_from_rejection!(PathRejection, VcApiErrorResponseRestDTO);
gen_from_rejection!(FormRejection, VcApiErrorResponseRestDTO);
