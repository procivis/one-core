use std::sync::Arc;

use async_trait::async_trait;
use shared_types::DidValue;

use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, ExtractPresentationCtx, FormatPresentationCtx, FormattedPresentation,
    Presentation, VerificationFn,
};
use crate::provider::presentation_formatter::model::PresentationFormatterCapabilities;
use crate::provider::presentation_formatter::{CredentialToPresent, PresentationFormatter};

/// Temporary wrapper around a CredentialFormatter implementation to facilitate the transition to the new presentation formatter trait.
pub struct PresentationFormatterAdapter {
    inner: Arc<dyn CredentialFormatter>,
}

impl PresentationFormatterAdapter {
    pub(crate) fn new(inner: Arc<dyn CredentialFormatter>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl PresentationFormatter for PresentationFormatterAdapter {
    async fn format_presentation(
        &self,
        credentials_to_present: Vec<CredentialToPresent>,
        holder_binding_fn: AuthenticationFn,
        holder_did: &DidValue,
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, crate::provider::credential_formatter::error::FormatterError>
    {
        let algorithm = holder_binding_fn
            .get_key_algorithm()
            .map_err(FormatterError::Failed)?;

        let credentials_to_present = credentials_to_present
            .iter()
            .map(|cred| cred.raw_credential.clone())
            .collect::<Vec<_>>();

        self.inner
            .format_presentation(
                &credentials_to_present,
                holder_did,
                algorithm,
                holder_binding_fn,
                context,
            )
            .await
    }

    async fn extract_presentation(
        &self,
        presentation: &str,
        verification_fn: VerificationFn,
        context: ExtractPresentationCtx,
    ) -> Result<Presentation, crate::provider::credential_formatter::error::FormatterError> {
        self.inner
            .extract_presentation(presentation, verification_fn, context)
            .await
    }

    async fn extract_presentation_unverified(
        &self,
        presentation: &str,
        context: ExtractPresentationCtx,
    ) -> Result<Presentation, crate::provider::credential_formatter::error::FormatterError> {
        self.inner
            .extract_presentation_unverified(presentation, context)
            .await
    }

    fn get_leeway(&self) -> u64 {
        self.inner.get_leeway()
    }

    fn get_capabilities(&self) -> PresentationFormatterCapabilities {
        PresentationFormatterCapabilities {
            supported_credential_formats: vec![],
        }
    }
}
