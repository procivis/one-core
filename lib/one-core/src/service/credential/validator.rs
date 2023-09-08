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

    let claim_schemas = &schema
        .claim_schemas
        .to_owned()
        .ok_or(ServiceError::MappingError(
            "claim_schemas is None".to_string(),
        ))?;

    claims
        .iter()
        .map(|claim| {
            let schema = claim_schemas
                .iter()
                .find(|schema| schema.id == claim.claim_schema_id);
            match schema {
                None => Err(ServiceError::NotFound),
                Some(schema) => {
                    {
                        validate_value(&claim.value, &schema.data_type, &config.datatype)
                            .map_err(ServiceError::ConfigValidationError)?
                    }
                    Ok(())
                }
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(())
}
