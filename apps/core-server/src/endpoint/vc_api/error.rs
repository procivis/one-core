use one_core::provider::did_method::error::{DidMethodError, DidMethodProviderError};
use one_core::service::error::{MissingProviderError, ServiceError};
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
