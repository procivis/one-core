use super::error::OID4VPFinal1_0ServiceError;
use crate::provider::verification_protocol::openid4vp::model::OpenID4VPVerifierInteractionContent;

pub(super) fn parse_interaction_content(
    data: Option<&Vec<u8>>,
) -> Result<OpenID4VPVerifierInteractionContent, OID4VPFinal1_0ServiceError> {
    if let Some(interaction_data) = data {
        serde_json::from_slice(interaction_data)
            .map_err(|e| OID4VPFinal1_0ServiceError::MappingError(e.to_string()))
    } else {
        Err(OID4VPFinal1_0ServiceError::MappingError(
            "Interaction data is missing or incorrect".to_string(),
        ))
    }
}
