use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use proc_macros::provider_mock;
use shared_types::DocumentSignerProviderId;

use crate::provider::Provider;
use crate::provider::document_signer::error::DocumentSignerError;
use crate::provider::document_signer::model::{
    Authorization, AuthorizationRequest, DocumentSignerCapabilities, SignRequest, SignedDocument,
};

pub mod decorators;
pub mod error;
pub mod model;
pub mod provider;
mod sign8;

#[provider_mock]
#[async_trait]
pub trait DocumentSigner: Provider + Send + Sync {
    fn config_name(&self) -> &DocumentSignerProviderId;

    fn get_capabilities(&self) -> DocumentSignerCapabilities;

    async fn get_authorization_request(
        &self,
        request: AuthorizationRequest,
    ) -> Result<Authorization, DocumentSignerError>;

    async fn sign(&self, request: SignRequest) -> Result<SignedDocument, DocumentSignerError>;
}

impl Display for dyn DocumentSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Document signer `{}`", self.config_name())
    }
}
