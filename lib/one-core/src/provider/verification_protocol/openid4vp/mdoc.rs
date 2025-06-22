use url::Url;

use crate::provider::credential_formatter::model::FormatPresentationCtx;
use crate::provider::presentation_formatter::mso_mdoc::model::{OID4VPHandover, SessionTranscript};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::common::to_cbor;

pub(crate) fn mdoc_presentation_context(
    client_id: &str,
    response_uri: &Url,
    verifier_nonce: &str,
    mdoc_generated_nonce: &str,
) -> Result<FormatPresentationCtx, VerificationProtocolError> {
    Ok(FormatPresentationCtx {
        mdoc_session_transcript: Some(
            to_cbor(&SessionTranscript {
                handover: Some(
                    OID4VPHandover::compute(
                        client_id.trim_end_matches('/'),
                        response_uri.as_str().trim_end_matches('/'),
                        verifier_nonce,
                        mdoc_generated_nonce,
                    )
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
                ),
                device_engagement_bytes: None,
                e_reader_key_bytes: None,
            })
            .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?,
        ),
        ..Default::default()
    })
}
