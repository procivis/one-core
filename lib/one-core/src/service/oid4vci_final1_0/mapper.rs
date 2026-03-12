use super::error::OID4VCIFinal1_0ServiceError;
use crate::model::interaction::Interaction;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::OpenID4VCIIssuerInteractionDataDTO;

pub(crate) fn interaction_data_to_dto(
    interaction: &Interaction,
) -> Result<OpenID4VCIIssuerInteractionDataDTO, OID4VCIFinal1_0ServiceError> {
    let interaction_data =
        interaction
            .data
            .to_owned()
            .ok_or(OID4VCIFinal1_0ServiceError::MappingError(
                "interaction data is missing".to_string(),
            ))?;

    serde_json::from_slice(&interaction_data)
        .map_err(|e| OID4VCIFinal1_0ServiceError::MappingError(e.to_string()))
}
