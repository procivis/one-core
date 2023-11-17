use crate::{
    config::{
        data_structure::CoreConfig,
        validator::{datatype::validate_value, exchange::validate_exchange_type},
    },
    model::credential_schema::CredentialSchema,
    service::{credential::dto::CredentialRequestClaimDTO, error::ServiceError},
};

pub(crate) fn validate_create_request(
    transport: &str,
    claims: &[CredentialRequestClaimDTO],
    schema: &CredentialSchema,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    validate_exchange_type(transport, &config.exchange)?;

    // ONE-843: cannot create credential based on deleted schema
    if schema.deleted_at.is_some() {
        return Err(ServiceError::NotFound);
    }

    let claim_schemas = &schema
        .claim_schemas
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "claim_schemas is None".to_string(),
        ))?;

    // check all claims have valid content
    claims
        .iter()
        .map(|claim| {
            let schema = claim_schemas
                .iter()
                .find(|schema| schema.schema.id == claim.claim_schema_id);
            match schema {
                None => Err(ServiceError::NotFound),
                Some(schema) => {
                    {
                        validate_value(&claim.value, &schema.schema.data_type, &config.datatype)
                            .map_err(ServiceError::ConfigValidationError)?
                    }
                    Ok(())
                }
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    // check all required claims are present
    claim_schemas
        .iter()
        .map(|claim_schema| {
            if claim_schema.required {
                claims
                    .iter()
                    .find(|claim| claim.claim_schema_id == claim_schema.schema.id)
                    .ok_or(ServiceError::IncorrectParameters)?;
            }
            Ok(())
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;

    Ok(())
}
