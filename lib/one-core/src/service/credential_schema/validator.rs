use shared_types::OrganisationId;

use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::service::credential_schema::dto::CredentialClaimSchemaRequestDTO;
use crate::service::credential_schema::mapper::create_unique_name_check_request;
use crate::service::error::{BusinessLogicError, ValidationError};
use crate::{
    config::validator::{
        datatype::validate_datatypes, format::validate_format, revocation::validate_revocation,
    },
    service::{credential_schema::dto::CreateCredentialSchemaRequestDTO, error::ServiceError},
};
use std::sync::Arc;

pub(crate) async fn credential_schema_already_exists(
    repository: &Arc<dyn CredentialSchemaRepository>,
    name: &str,
    organisation_id: OrganisationId,
) -> Result<(), ServiceError> {
    let credential_schemas = repository
        .get_credential_schema_list(create_unique_name_check_request(name, organisation_id)?)
        .await?;
    if credential_schemas.total_items > 0 {
        return Err(BusinessLogicError::CredentialSchemaAlreadyExists.into());
    }
    Ok(())
}

pub(crate) fn validate_create_request(
    request: &CreateCredentialSchemaRequestDTO,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    // at least one claim must be declared
    if request.claims.is_empty() {
        return Err(ValidationError::CredentialSchemaMissingClaims.into());
    }

    validate_format(&request.format, &config.format)?;
    validate_revocation(&request.revocation_method, &config.revocation)?;
    validate_nested_claim_schemas(&request.claims, config)?;

    Ok(())
}

fn validate_nested_claim_schemas(
    claims: &[CredentialClaimSchemaRequestDTO],
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    for claim_schema in gather_claim_schemas(claims) {
        validate_claim_schema(claim_schema, config)?;
    }

    validate_datatypes(
        gather_claim_schemas(claims).map(|value| value.datatype.as_str()),
        &config.datatype,
    )
    .map_err(ServiceError::ConfigValidationError)
}

fn validate_claim_schema(
    claim_schema: &CredentialClaimSchemaRequestDTO,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    let claim_type = config.datatype.get_fields(&claim_schema.datatype)?.r#type();
    validate_claim_schema_name(claim_schema)?;
    validate_claim_schema_type(claim_schema, claim_type)?;

    Ok(())
}

fn validate_claim_schema_name(
    claim_schema: &CredentialClaimSchemaRequestDTO,
) -> Result<(), ValidationError> {
    if claim_schema.key.find(NESTED_CLAIM_MARKER).is_some() {
        Err(ValidationError::CredentialSchemaClaimSchemaSlashInKeyName(
            claim_schema.key.to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn validate_claim_schema_type(
    claim_schema: &CredentialClaimSchemaRequestDTO,
    claim_type: &DatatypeType,
) -> Result<(), ValidationError> {
    match claim_type {
        DatatypeType::Object => {
            if claim_schema.claims.is_empty() {
                return Err(ValidationError::CredentialSchemaMissingNestedClaims(
                    claim_schema.key.to_owned(),
                ));
            }
        }
        _ => {
            if !claim_schema.claims.is_empty() {
                return Err(ValidationError::CredentialSchemaNestedClaimsShouldBeEmpty(
                    claim_schema.key.to_owned(),
                ));
            }
        }
    }

    Ok(())
}

fn gather_claim_schemas<'a>(
    claim_schemas: &'a [CredentialClaimSchemaRequestDTO],
) -> Box<dyn Iterator<Item = &'a CredentialClaimSchemaRequestDTO> + 'a> {
    let nested = claim_schemas
        .iter()
        .flat_map(|f| gather_claim_schemas(&f.claims));

    Box::new(claim_schemas.iter().chain(nested))
}
