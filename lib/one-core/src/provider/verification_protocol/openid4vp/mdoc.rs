use url::Url;

use crate::provider::presentation_formatter::model::FormatPresentationCtx;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::iso_18013_7::OID4VPDraftHandover;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
    Handover, SessionTranscript,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::common::to_cbor;

pub(crate) fn mdoc_draft_handover(
    client_id: &str,
    response_uri: &Url,
    verifier_nonce: &str,
    mdoc_generated_nonce: &str,
) -> Result<Handover, VerificationProtocolError> {
    Ok(Handover::Iso18013_7AnnexB(
        OID4VPDraftHandover::compute(
            client_id,
            response_uri.as_str(),
            verifier_nonce,
            mdoc_generated_nonce,
        )
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
    ))
}

pub(crate) fn mdoc_presentation_context(
    handover: Handover,
) -> Result<FormatPresentationCtx, VerificationProtocolError> {
    Ok(FormatPresentationCtx {
        mdoc_session_transcript: Some(
            to_cbor(&SessionTranscript {
                handover: Some(handover),
                device_engagement_bytes: None,
                e_reader_key_bytes: None,
            })
            .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?,
        ),
        ..Default::default()
    })
}
