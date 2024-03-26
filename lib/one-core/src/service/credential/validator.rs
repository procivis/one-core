use crate::config::core_config::DatatypeType;
use crate::model::credential_schema::CredentialSchemaClaim;
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

    let claim_schemas =
        adapt_required_state_based_on_claim_presence(claim_schemas, claims, config)?;

    // check all required claims are present
    claim_schemas
        .iter()
        .map(|claim_schema| {
            let datatype = &claim_schema.schema.data_type;
            let config = config.datatype.get_fields(datatype)?;

            if claim_schema.required && config.r#type != DatatypeType::Object {
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

fn adapt_required_state_based_on_claim_presence(
    claim_schemas: &[CredentialSchemaClaim],
    claims: &[CredentialRequestClaimDTO],
    config: &CoreConfig,
) -> Result<Vec<CredentialSchemaClaim>, ServiceError> {
    let claims_with_names = claims
        .iter()
        .map(|claim| {
            let matching_claim_schema = claim_schemas
                .iter()
                .find(|claim_schema| claim_schema.schema.id == claim.claim_schema_id)
                .ok_or(ValidationError::CredentialSchemaMissingClaims)?;
            Ok((claim, matching_claim_schema.schema.key.to_owned()))
        })
        .collect::<Result<Vec<(&CredentialRequestClaimDTO, String)>, ValidationError>>()?;

    let mut result = claim_schemas.to_vec();
    claim_schemas.iter().try_for_each(|claim_schema| {
        let prefix = format!("{}/", claim_schema.schema.key);

        let is_parent_schema_of_provided_claim = claims_with_names
            .iter()
            .any(|(_, claim_name)| claim_name.starts_with(&prefix));

        let is_object = config
            .datatype
            .get_fields(&claim_schema.schema.data_type)?
            .r#type
            == DatatypeType::Object;

        let should_make_all_child_claims_non_required =
            !is_parent_schema_of_provided_claim && is_object && !claim_schema.required;

        if should_make_all_child_claims_non_required {
            result.iter_mut().for_each(|result_schema| {
                if result_schema.schema.key.starts_with(&prefix) {
                    result_schema.required = false;
                }
            });
        }

        Ok::<(), ServiceError>(())
    })?;

    Ok(result)
}
