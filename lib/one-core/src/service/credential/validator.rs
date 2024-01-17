use crate::{
    config::{
        core_config::CoreConfig,
        validator::{datatype::validate_datatype_value, exchange::validate_exchange_type},
    },
    model::credential_schema::CredentialSchema,
    service::{
        credential::dto::CredentialRequestClaimDTO,
        error::{BusinessLogicError, ServiceError, ValidationError},
    },
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
        return Err(BusinessLogicError::MissingCredentialSchema.into());
    }

    let claim_schemas = &schema
        .claim_schemas
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "claim_schemas is None".to_string(),
        ))?;

    // check all claims have valid content
    for claim in claims {
        let claim_schema_id = claim.claim_schema_id;
        let schema = claim_schemas
            .iter()
            .find(|schema| schema.schema.id == claim_schema_id);

        match schema {
            None => return Err(BusinessLogicError::MissingClaimSchema { claim_schema_id }.into()),
            Some(schema) => {
                validate_datatype_value(&claim.value, &schema.schema.data_type, &config.datatype)
                    .map_err(|err| ValidationError::InvalidDatatype {
                    value: claim.value.clone(),
                    datatype: schema.schema.data_type.clone(),
                    source: err,
                })?;
            }
        }
    }

    // check all required claims are present
    claim_schemas
        .iter()
        .map(|claim_schema| {
            if claim_schema.required {
                claims
                    .iter()
                    .find(|claim| claim.claim_schema_id == claim_schema.schema.id)
                    .ok_or(ValidationError::CredentialMissingClaim {
                        claim_schema_id: claim_schema.schema.id,
                    })?;
            }
            Ok(())
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;

    Ok(())
}
