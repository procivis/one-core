use one_core::service::error::{MissingProviderError, ServiceError};
use one_providers::did::error::{DidMethodError, DidMethodProviderError};
use serde::Serialize;
use utoipa::{IntoResponses, ToSchema};

#[derive(Serialize, IntoResponses, ToSchema, Debug)]
#[serde(rename_all = "camelCase")]
pub enum VcApiError {
    #[response(status = 400)]
    UnmappedError(String),
    #[response(status = 400)]
    DidResolverError(DidResolverError),
}

#[derive(Serialize, IntoResponses, Debug)]
#[serde(rename_all = "camelCase")]
pub enum DidResolverError {
    #[response(status = 400)]
    MethodNotSupported(#[serde(skip_serializing)] String),
    #[response(status = 400)]
    InvalidDid(#[serde(skip_serializing)] String),
    #[response(status = 400)]
    InvalidPublicKeyLength(#[serde(skip_serializing)] String),
}

#[derive(Serialize, Debug, ToSchema)]
pub struct VcApiErrorRestDTO {
    pub status: Option<u16>,
    pub title: String,
    pub detail: Option<String>,
}

impl From<ServiceError> for VcApiError {
    fn from(value: ServiceError) -> Self {
        match value {
            ServiceError::MissingProvider(MissingProviderError::DidMethod(e)) => {
                Self::DidResolverError(DidResolverError::MethodNotSupported(e))
            }
            ServiceError::DidMethodProviderError(e) => match e {
                DidMethodProviderError::MissingProvider(e) => {
                    Self::DidResolverError(DidResolverError::MethodNotSupported(e))
                }
                DidMethodProviderError::DidMethod(DidMethodError::ResolutionError(m)) => match m {
                    _ if m.contains("Unsupported key") => {
                        Self::DidResolverError(DidResolverError::InvalidPublicKeyLength(m))
                    }
                    _ => Self::DidResolverError(DidResolverError::InvalidDid(m)),
                },
                DidMethodProviderError::DidMethod(e) => {
                    Self::DidResolverError(DidResolverError::InvalidDid(e.to_string()))
                }
                _ => Self::UnmappedError(e.to_string()),
            },
            _ => Self::UnmappedError(value.to_string()),
        }
    }
}
