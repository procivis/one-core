use std::fmt::Display;
use std::sync::Arc;

use shared_types::DocumentSignerProviderId;

use crate::provider::Provider;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::document_signer::DocumentSigner;
use crate::provider::document_signer::error::DocumentSignerError;
use crate::provider::document_signer::model::{
    Authorization, AuthorizationRequest, DocumentSignerCapabilities, SignRequest, SignedDocument,
};
use crate::provider::provider_directory::WithDisabledDecorator;

impl WithDisabledDecorator for dyn DocumentSigner {
    fn decorate(self: Arc<dyn DocumentSigner>) -> Arc<dyn DocumentSigner> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait::async_trait]
impl<T: Provider + DocumentSigner + Display + ?Sized> DocumentSigner for DisabledProvider<T> {
    fn config_name(&self) -> &DocumentSignerProviderId {
        self.inner().config_name()
    }

    fn get_capabilities(&self) -> DocumentSignerCapabilities {
        self.inner().get_capabilities()
    }

    async fn get_authorization_request(
        &self,
        _request: AuthorizationRequest,
    ) -> Result<Authorization, DocumentSignerError> {
        self.disabled_error()
    }

    async fn sign(&self, _request: SignRequest) -> Result<SignedDocument, DocumentSignerError> {
        self.disabled_error()
    }
}
