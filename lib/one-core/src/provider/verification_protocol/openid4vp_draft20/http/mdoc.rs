use url::Url;

use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    OID4VPHandover, SessionTranscript,
};
use crate::provider::credential_formatter::model::FormatPresentationCtx;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::common::to_cbor;
use crate::provider::verification_protocol::openid4vp_draft20::model::OpenID4VPHolderInteractionData;

pub(crate) fn mdoc_presentation_context(
    interaction_data: &OpenID4VPHolderInteractionData,
    response_uri: &Url,
    verifier_nonce: &str,
    mdoc_generated_nonce: &str,
) -> Result<FormatPresentationCtx, VerificationProtocolError> {
    Ok(FormatPresentationCtx {
        mdoc_session_transcript: Some(
            to_cbor(&SessionTranscript {
                handover: OID4VPHandover::compute(
                    interaction_data.client_id.as_str().trim_end_matches('/'),
                    response_uri.as_str().trim_end_matches('/'),
                    verifier_nonce,
                    mdoc_generated_nonce,
                )
                .into(),
                device_engagement_bytes: None,
                e_reader_key_bytes: None,
            })
            .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?,
        ),
        ..Default::default()
    })
}
