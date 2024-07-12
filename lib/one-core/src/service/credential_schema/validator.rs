use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;

use shared_types::OrganisationId;

use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::{CoreConfig, DatatypeType, FormatType};
use crate::config::validator::datatype::validate_datatypes;
use crate::config::validator::format::validate_format;
use crate::config::validator::revocation::validate_revocation;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaRequestDTO,
};
use crate::service::credential_schema::mapper::create_unique_name_check_request;
use crate::service::error::{
    BusinessLogicError, MissingProviderError, ServiceError, ValidationError,
};

pub(crate) async fn credential_schema_already_exists(
    repository: &Arc<dyn CredentialSchemaRepository>,
    name: &str,
    schema_id: Option<String>,
    organisation_id: OrganisationId,
) -> Result<(), ServiceError> {
    let credential_schemas = repository
        .get_credential_schema_list(
            create_unique_name_check_request(name, schema_id, organisation_id)?,
            &Default::default(),
        )
        .await?;
    if credential_schemas.total_items > 0 {
        return Err(BusinessLogicError::CredentialSchemaAlreadyExists.into());
    }
    Ok(())
}

pub(crate) fn validate_create_request(
    request: &CreateCredentialSchemaRequestDTO,
    config: &CoreConfig,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    during_import: bool,
) -> Result<(), ServiceError> {
    // at least one claim must be declared
    if request.claims.is_empty() {
        return Err(ValidationError::CredentialSchemaMissingClaims.into());
    }

    validate_key_lengths(&request.claims, 0)?;
    validate_format(&request.format, &config.format)?;
    validate_revocation(&request.revocation_method, &config.revocation)?;
    validate_nested_claim_schemas(&request.claims, config)?;
    validate_revocation_method_is_compatible_with_format(request, config, formatter_provider)?;
    validate_mdoc_claim_types(request, config)?;
    validate_schema_id(request, config, during_import)?;

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

    let claims = get_all_claim_paths(&request.claims);

    handle_attribute_claim_validation(primary_attribute, &claims, "Primary")?;
    handle_attribute_claim_validation(secondary_attribute, &claims, "Secondary")?;
    handle_attribute_claim_validation(picture_attribute, &claims, "Picture")?;
    handle_attribute_claim_validation(code_attribute, &claims, "Code attribute")?;

    Ok(())
}

fn get_all_claim_paths(claims: &[CredentialClaimSchemaRequestDTO]) -> Vec<String> {
    fn compute_paths<'a>(
        claims: &'a [CredentialClaimSchemaRequestDTO],
        current_path: &mut Vec<&'a str>,
        all_paths: &mut Vec<String>,
    ) {
        if claims.is_empty() {
            let path = current_path.join("/");
            all_paths.push(path);

            return;
        }

        for claim in claims {
            current_path.push(&claim.key);

            compute_paths(&claim.claims, current_path, all_paths);

            current_path.pop();
        }
    }

    let mut current_path = vec![];
    let mut all_paths = Vec::with_capacity(claims.len());

    compute_paths(claims, &mut current_path, &mut all_paths);

    all_paths
}

fn handle_attribute_claim_validation(
    attribute: Option<&String>,
    claims: &[String],
    attribute_name: &str,
) -> Result<(), ServiceError> {
    if let Some(attribute) = attribute {
        if !claims.iter().any(|c| c == attribute) {
            return Err(ValidationError::MissingLayoutAttribute(attribute_name.to_owned()).into());
        }
    }
    Ok(())
}

fn validate_nested_claim_schemas(
    claims: &[CredentialClaimSchemaRequestDTO],
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    validate_claim_schema_keys_unique(claims)?;

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
    if let Some(is_array) = claim_schema.array {
        if is_array {
            let _ = config.datatype.get_if_enabled("ARRAY")?;
        }
    }

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

fn validate_claim_schema_keys_unique(
    claims: &[CredentialClaimSchemaRequestDTO],
) -> Result<(), ValidationError> {
    let mut uniq = HashSet::new();
    if !claims
        .iter()
        .all(move |claim| uniq.insert(claim.key.to_owned()))
    {
        return Err(ValidationError::CredentialSchemaDuplicitClaim);
    }

    for claim in claims {
        validate_claim_schema_keys_unique(&claim.claims)?;
    }

    Ok(())
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

fn validate_revocation_method_is_compatible_with_format(
    request: &CreateCredentialSchemaRequestDTO,
    config: &CoreConfig,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
) -> Result<(), ServiceError> {
    let formatter = formatter_provider
        .get_formatter(&request.format)
        .ok_or(MissingProviderError::Formatter(request.format.to_owned()))?;

    let revocation_method = config.revocation.get_fields(&request.revocation_method)?;

    if !formatter
        .get_capabilities()
        .revocation_methods
        .contains(&revocation_method.r#type.to_string())
    {
        return Err(BusinessLogicError::RevocationMethodNotCompatibleWithSelectedFormat.into());
    }

    Ok(())
}

fn validate_mdoc_claim_types(
    request: &CreateCredentialSchemaRequestDTO,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    let format_type = config.format.get_fields(&request.format)?.r#type;
    if format_type != FormatType::Mdoc {
        return Ok(());
    }

    for claim in &request.claims {
        let data_type = config.datatype.get_fields(&claim.datatype)?.r#type;
        if data_type != DatatypeType::Object {
            return Err(BusinessLogicError::InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed.into());
        }
    }

    Ok(())
}

fn validate_schema_id(
    request: &CreateCredentialSchemaRequestDTO,
    config: &CoreConfig,
    during_import: bool,
) -> Result<(), ServiceError> {
    let capabilities = &config.format.get_fields(&request.format)?.capabilities;
    let mut is_schema_id_required = false;
    if let Some(Value::Object(c)) = capabilities {
        is_schema_id_required = if let Some(Value::Array(arr)) = c.get("features") {
            arr.iter().any(|v| v.as_str() == Some("REQUIRES_SCHEMA_ID"))
        } else {
            false
        };
    }
    if is_schema_id_required {
        let schema_id = request.schema_id.as_deref().filter(|s| !s.is_empty());
        if schema_id.is_none() {
            return Err(BusinessLogicError::MissingMdocDoctype.into());
        }

        if let Some(Value::Object(c)) = capabilities {
            if let Some(Value::Array(allowed_schema_ids)) = c.get("allowedSchemaIds") {
                if !allowed_schema_ids.is_empty()
                    && !allowed_schema_ids.iter().any(|v| v.as_str() == schema_id)
                {
                    return Err(ValidationError::SchemaIdNotAllowedForFormat.into());
                }
            }
        }
    } else if !during_import && request.schema_id.is_some() {
        return Err(BusinessLogicError::SchemaIdNotAllowed.into());
    }

    Ok(())
}

fn validate_key_lengths(
    claims: &[CredentialClaimSchemaRequestDTO],
    prefix_length: usize,
) -> Result<(), ServiceError> {
    const MAX_KEY_LENGTH: usize = 255;
    const NESTED_CLAIM_MARKER_LENGTH: usize = 1;

    claims.iter().try_for_each(|claim| {
        if claim.key.len() + prefix_length > MAX_KEY_LENGTH {
            return Err(BusinessLogicError::ClaimSchemaKeyTooLong.into());
        }

        validate_key_lengths(&claim.claims, claim.key.len() + NESTED_CLAIM_MARKER_LENGTH)
    })
}
