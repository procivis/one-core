use crate::model::interaction::Interaction;
use crate::provider::issuance_protocol::openid4vci_draft13::model::OpenID4VCIIssuerInteractionDataDTO;
use crate::service::error::ServiceError;

pub(crate) fn interaction_data_to_dto(
    interaction: &Interaction,
) -> Result<OpenID4VCIIssuerInteractionDataDTO, ServiceError> {
    let interaction_data = interaction
        .data
        .to_owned()
        .ok_or(ServiceError::MappingError(
            "interaction data is missing".to_string(),
        ))?;

    serde_json::from_slice(&interaction_data).map_err(|e| ServiceError::MappingError(e.to_string()))
}
