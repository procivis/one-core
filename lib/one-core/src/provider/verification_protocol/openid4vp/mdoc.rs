use crate::provider::presentation_formatter::model::FormatPresentationCtx;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
    Handover, SessionTranscript,
};
use crate::provider::transaction_data::processed_transaction_data::ProcessedTransactionData;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::common::to_cbor;

pub(crate) fn mdoc_presentation_context(
    handover: Handover,
    transaction_data: Option<ProcessedTransactionData>,
) -> Result<FormatPresentationCtx, VerificationProtocolError> {
    Ok(FormatPresentationCtx {
        mdoc_session_transcript: Some(to_cbor(&SessionTranscript {
            handover,
            device_engagement_bytes: None,
            e_reader_key_bytes: None,
        })?),
        transaction_data,
        ..Default::default()
    })
}
