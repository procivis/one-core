use super::error::OID4VCIFinal1_0ServiceError;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
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

// interactions created before multi-format support have no selection, all schema formats are offered
pub(crate) async fn offered_formats(
    credential_schema: &CredentialSchema,
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
) -> Result<Vec<CredentialSchemaFormat>, OID4VCIFinal1_0ServiceError> {
    let formats = credential_schema.formats.as_ref().await?;
    let Some(selected) = &interaction_data.formats else {
        return Ok(formats.to_owned());
    };

    Ok(formats
        .iter()
        .filter(|format| selected.contains(&format.id))
        .cloned()
        .collect())
}
