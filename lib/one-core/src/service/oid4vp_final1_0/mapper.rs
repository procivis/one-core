use crate::provider::verification_protocol::openid4vp::model::OpenID4VPVerifierInteractionContent;
use crate::service::error::ServiceError;

pub(super) fn parse_interaction_content(
    data: Option<&Vec<u8>>,
) -> Result<OpenID4VPVerifierInteractionContent, ServiceError> {
    if let Some(interaction_data) = data {
        serde_json::from_slice(interaction_data)
            .map_err(|e| ServiceError::MappingError(e.to_string()))
    } else {
        Err(ServiceError::MappingError(
            "Interaction data is missing or incorrect".to_string(),
        ))
    }
}
