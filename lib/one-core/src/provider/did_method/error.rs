//! Enumerates errors related to DID method provider.

use shared_types::{DidId, KeyId};
use thiserror::Error;

use crate::provider::caching_loader::CachingLoaderError;
use crate::provider::remote_entity_storage::RemoteEntityStorageError;

#[derive(Debug, Error)]
pub enum DidMethodError {
    #[error("Key algorithm not found")]
    KeyAlgorithmNotFound,
    #[error("Could not resolve: `{0}`")]
    ResolutionError(String),
    #[error("Could not create: `{0}`")]
    CouldNotCreate(String),
    #[error("Not supported")]
    NotSupported,
}

#[derive(Debug, Error)]
pub enum DidMethodProviderError {
    #[error("Did method error: `{0}`")]
    DidMethod(#[from] DidMethodError),
    #[error("Failed to resolve did: `{0}`")]
    FailedToResolve(String),
    #[error("Missing did method name in did value")]
    MissingDidMethodNameInDidValue,
    #[error("Missing did provider: `{0}`")]
    MissingProvider(String),

    #[error(
        "Verification method id of key `{key_id}` not found in did document for did '{did_id}"
    )]
    VerificationMethodIdNotFound { key_id: KeyId, did_id: DidId },

    #[error("Other: `{0}`")]
    Other(String),

    #[error("Caching loader error: `{0}`")]
    CachingLoader(#[from] CachingLoaderError),
    #[error("JSON parse error: `{0}`")]
    JsonParse(#[from] serde_json::Error),
    #[error("Remote entity storage error: `{0}`")]
    RemoteEntityStorage(#[from] RemoteEntityStorageError),
}
