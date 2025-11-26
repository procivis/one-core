use async_trait::async_trait;
use shared_types::DidValue;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{AuthenticationFn, VerificationFn};
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, ExtractPresentationCtx, ExtractedPresentation, FormatPresentationCtx,
    FormattedPresentation,
};

pub mod jwt_vp_json;
pub mod ldp_vp;
pub mod model;
pub mod mso_mdoc;
pub mod provider;
pub mod sdjwt;
pub mod sdjwt_vc;

/// PresentationFormatter is a trait that defines the methods for formatting and extracting presentations.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait PresentationFormatter: Send + Sync {
    /// Formats a set of credentials into a presentation, signed by the holder.
    async fn format_presentation(
        &self,
        credentials_to_present: Vec<CredentialToPresent>,
        holder_binding_fn: AuthenticationFn,
        holder_did: &Option<DidValue>,
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError>;

    /// Extracts a presentation from a signed presentation.
    /// The holder binding function is used to verify the signature of the presentation.
    async fn extract_presentation(
        &self,
        presentation: &str,
        verification_fn: VerificationFn,
        context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError>;

    /// Extracts a presentation from a signed presentation, without verifying the signature.
    async fn extract_presentation_unverified(
        &self,
        presentation: &str,
        context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError>;

    fn get_leeway(&self) -> u64;
}
