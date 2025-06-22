use async_trait::async_trait;
use shared_types::DidValue;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, ExtractPresentationCtx, FormatPresentationCtx, FormattedPresentation,
    Presentation, VerificationFn,
};
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, PresentationFormatterCapabilities,
};

pub mod adapter;
pub mod model;
pub mod mso_mdoc;

/// PresentationFormatter is a trait that defines the methods for formatting and extracting presentations.
#[async_trait]
pub trait PresentationFormatter: Send + Sync {
    /// Formats a set of credentials into a presentation, signed by the holder.
    async fn format_presentation(
        &self,
        credentials_to_present: Vec<CredentialToPresent>,
        holder_binding_fn: AuthenticationFn,
        holder_did: &DidValue,
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError>;

    /// Extracts a presentation from a signed presentation.
    /// The holder binding function is used to verify the signature of the presentation.
    async fn extract_presentation(
        &self,
        presentation: &str,
        verification_fn: VerificationFn,
        context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError>;

    /// Extracts a presentation from a signed presentation, without verifying the signature.
    async fn extract_presentation_unverified(
        &self,
        presentation: &str,
        context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError>;

    fn get_leeway(&self) -> u64;

    fn get_capabilities(&self) -> PresentationFormatterCapabilities;
}
