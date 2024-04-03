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
use std::collections::VecDeque;
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

pub(crate) fn check_background_properties(
    request: &CreateCredentialSchemaRequestDTO,
) -> Result<(), ServiceError> {
    let background = request
        .layout_properties
        .as_ref()
        .and_then(|p| p.background.as_ref());

    if let Some(background) = background {
        match (background.color.as_ref(), background.image.as_ref()) {
            (Some(_), None) | (None, Some(_)) => return Ok(()),
            _ => return Err(ValidationError::AttributeCombinationNotAllowed.into()),
        }
    }

    Ok(())
}

pub(crate) fn check_logo_properties(
    request: &CreateCredentialSchemaRequestDTO,
) -> Result<(), ServiceError> {
    let logo = request
        .layout_properties
        .as_ref()
        .and_then(|p| p.logo.as_ref());

    if let Some(logo) = logo {
        match (
            logo.background_color.as_ref(),
            logo.font_color.as_ref(),
            logo.image.as_ref(),
        ) {
            (Some(_), Some(_), None) | (None, None, Some(_)) => return Ok(()),
            _ => return Err(ValidationError::AttributeCombinationNotAllowed.into()),
        }
    }

    Ok(())
}

pub(crate) fn check_claims_presence_in_layout_properties(
    request: &CreateCredentialSchemaRequestDTO,
) -> Result<(), ServiceError> {
    let primary_attribute = request
        .layout_properties
        .as_ref()
        .and_then(|p| p.primary_attribute.as_ref());
    let secondary_attribute = request
        .layout_properties
        .as_ref()
        .and_then(|p| p.secondary_attribute.as_ref());
    let picture_attribute = request
        .layout_properties
        .as_ref()
        .and_then(|p| p.picture_attribute.as_ref());
    let code_attribute = request
        .layout_properties
        .as_ref()
        .and_then(|p| p.code.as_ref())
        .map(|c| &c.attribute);

    if primary_attribute.is_none()
        && secondary_attribute.is_none()
        && picture_attribute.is_none()
        && code_attribute.is_none()
    {
        return Ok(());
    }

    let mut claims_under_collection = VecDeque::from_iter(request.claims.iter());
    let mut claims = VecDeque::new();

    // Collect all claims
    while let Some(claim) = claims_under_collection.pop_front() {
        claims_under_collection.extend(claim.claims.iter());
        claims.push_back(claim);
    }

    handle_attribute_claim_validation(primary_attribute, &claims, "Primary")?;
    handle_attribute_claim_validation(secondary_attribute, &claims, "Secondary")?;
    handle_attribute_claim_validation(picture_attribute, &claims, "Picture")?;
    handle_attribute_claim_validation(code_attribute, &claims, "Code attribute")?;

    Ok(())
}

fn handle_attribute_claim_validation(
    primary_attribute: Option<&String>,
    claims: &VecDeque<&CredentialClaimSchemaRequestDTO>,
    attribute_name: &str,
) -> Result<(), ServiceError> {
    if let Some(attribute) = primary_attribute {
        if !claims.iter().any(|c| &c.key == attribute) {
            return Err(ValidationError::MissingLayoutAttribute(attribute_name.to_owned()).into());
        }
    }
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
