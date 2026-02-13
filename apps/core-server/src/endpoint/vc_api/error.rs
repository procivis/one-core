use one_core::error::{ErrorCode, ErrorCodeMixin};
use one_core::service::error::ServiceError;
use serde::Serialize;
use serde_with::skip_serializing_none;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum VcApiError {
    UnmappedError(String),
    DidResolverError(DidResolverError),
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum DidResolverError {
    MethodNotSupported(#[serde(skip_serializing)] String),
    InvalidDid(#[serde(skip_serializing)] String),
    InvalidPublicKeyLength(#[serde(skip_serializing)] String),
}

#[skip_serializing_none]
#[derive(Serialize, Debug)]
pub struct VcApiErrorRestDTO {
    pub status: Option<u16>,
    pub title: String,
    pub detail: Option<String>,
}

impl From<ServiceError> for VcApiError {
    fn from(value: ServiceError) -> Self {
        match value {
            error if matches!(error.error_code(), ErrorCode::BR_0363 | ErrorCode::BR_0031) => {
                Self::DidResolverError(DidResolverError::MethodNotSupported(error.to_string()))
            }
            error if error.error_code() == ErrorCode::BR_0364 => match error.to_string() {
                m if m.contains("Unsupported key") => {
                    Self::DidResolverError(DidResolverError::InvalidPublicKeyLength(m))
                }
                m => Self::DidResolverError(DidResolverError::InvalidDid(m)),
            },
            _ => Self::UnmappedError(value.to_string()),
        }
    }
}
