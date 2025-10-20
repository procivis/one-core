use std::collections::HashSet;

use shared_types::OrganisationId;

use crate::config::core_config::{ConfigExt, CoreConfig, DatatypeType, FormatType};
use crate::config::validator::datatype::validate_datatypes;
use crate::config::validator::format::validate_format;
use crate::config::validator::revocation::validate_revocation;
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::credential_schema::WalletStorageTypeEnum;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::Features;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::model::Operation;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaRequestDTO,
};
use crate::service::credential_schema::mapper::create_unique_name_check_request;
use crate::service::error::{
    BusinessLogicError, MissingProviderError, ServiceError, ValidationError,
};

pub(crate) async fn credential_schema_already_exists(
    repository: &dyn CredentialSchemaRepository,
    name: &str,
    schema_id: Option<String>,
    organisation_id: OrganisationId,
) -> Result<UniquenessCheckResult, ServiceError> {
    let credential_schemas = repository
        .get_credential_schema_list(
            create_unique_name_check_request(name, schema_id.clone(), organisation_id)?,
            &Default::default(),
        )
        .await?;

    if let Some(schema_id) = schema_id
        && credential_schemas
            .values
            .iter()
            .any(|cs| cs.schema_id == schema_id)
    {
        return Ok(UniquenessCheckResult::SchemaIdConflict);
    }
    if credential_schemas.values.iter().any(|cs| cs.name == name) {
        Ok(UniquenessCheckResult::NameConflict)
    } else {
        Ok(UniquenessCheckResult::Ok)
    }
}

pub(crate) enum UniquenessCheckResult {
    SchemaIdConflict,
    NameConflict,
    Ok,
}

pub(crate) fn validate_create_request(
    request: &CreateCredentialSchemaRequestDTO,
    config: &CoreConfig,
    formatter: &dyn CredentialFormatter,
    revocation_method_provider: &dyn RevocationMethodProvider,
    during_import: bool,
) -> Result<(), ServiceError> {
    // at least one claim must be declared
    if request.claims.is_empty() {
        return Err(ValidationError::CredentialSchemaMissingClaims.into());
    }

    validate_key_lengths(&request.claims, 0)?;
    validate_format(&request.format, &config.format)?;
    validate_revocation(&request.revocation_method, &config.revocation)?;
    validate_nested_claim_schemas(&request.claims, config, formatter)?;

    let revocation_method = revocation_method_provider
        .get_revocation_method(&request.revocation_method)
        .ok_or(MissingProviderError::RevocationMethod(
            request.revocation_method.to_owned(),
        ))?;

    validate_claim_names(request, formatter)?;
    validate_revocation_method_is_compatible_with_format(request, config, formatter)?;
    validate_revocation_method_is_compatible_with_suspension(request, &*revocation_method)?;
    validate_credential_design(request, formatter)?;
    validate_mdoc_claim_types(request, config)?;
    validate_schema_id(request, formatter, during_import)?;

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
        return match (background.color.as_ref(), background.image.as_ref()) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            _ => Err(ValidationError::AttributeCombinationNotAllowed.into()),
        };
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
        return match (
            logo.background_color.as_ref(),
            logo.font_color.as_ref(),
            logo.image.as_ref(),
        ) {
            (Some(_), Some(_), None) | (None, None, Some(_)) => Ok(()),
            _ => Err(ValidationError::AttributeCombinationNotAllowed.into()),
        };
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
    if let Some(attribute) = attribute
        && !claims.iter().any(|c| c == attribute)
    {
        return Err(ValidationError::MissingLayoutAttribute(attribute_name.to_owned()).into());
    }
    Ok(())
}

fn validate_claim_names(
    request: &CreateCredentialSchemaRequestDTO,
    formatter: &dyn CredentialFormatter,
) -> Result<(), ServiceError> {
    let forbidden_names = formatter.get_capabilities().forbidden_claim_names;

    if forbidden_names.into_iter().any(|forbidden_name| {
        validate_claims_names_are_not_forbidden(&forbidden_name, &request.claims)
    }) {
        return Err(ServiceError::Validation(
            ValidationError::ForbiddenClaimName,
        ));
    }

    Ok(())
}

fn validate_claims_names_are_not_forbidden(
    forbidden_name: &str,
    claims: &[CredentialClaimSchemaRequestDTO],
) -> bool {
    claims.iter().any(|claim| {
        claim.key == forbidden_name
            || validate_claims_names_are_not_forbidden(forbidden_name, &claim.claims)
    })
}

fn validate_nested_claim_schemas(
    claims: &[CredentialClaimSchemaRequestDTO],
    config: &CoreConfig,
    formatter: &dyn CredentialFormatter,
) -> Result<(), ServiceError> {
    validate_claim_schema_keys_unique(claims)?;

    for claim_schema in gather_claim_schemas(claims) {
        validate_claim_schema(claim_schema, config, formatter)?;
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
    formatter: &dyn CredentialFormatter,
) -> Result<(), ServiceError> {
    let claim_type = config.datatype.get_fields(&claim_schema.datatype)?.r#type();
    validate_claim_schema_name(claim_schema)?;
    validate_claim_schema_type(claim_schema, claim_type)?;
    if let Some(true) = claim_schema.array {
        config.datatype.get_if_enabled("ARRAY")?;
    }
    validate_claims_schema_type_supported_by_formatter(claim_schema, formatter)?;
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

fn validate_claims_schema_type_supported_by_formatter(
    claim_schema: &CredentialClaimSchemaRequestDTO,
    formatter: &dyn CredentialFormatter,
) -> Result<(), ValidationError> {
    if let Some(true) = claim_schema.array {
        validate_datatype_formatter_capabilities(
            &claim_schema.key,
            &"ARRAY".to_string(),
            formatter,
        )?;
    }
    validate_datatype_formatter_capabilities(&claim_schema.key, &claim_schema.datatype, formatter)
}

fn validate_datatype_formatter_capabilities(
    claim_name: &String,
    datatype: &String,
    formatter: &dyn CredentialFormatter,
) -> Result<(), ValidationError> {
    if !formatter.get_capabilities().datatypes.contains(datatype) {
        return Err(
            ValidationError::CredentialSchemaClaimSchemaUnsupportedDatatype {
                claim_name: claim_name.to_owned(),
                data_type: datatype.to_owned(),
            },
        );
    };
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

fn validate_revocation_method_is_compatible_with_suspension(
    request: &CreateCredentialSchemaRequestDTO,
    revocation_method: &dyn RevocationMethod,
) -> Result<(), ServiceError> {
    if request.allow_suspension == Some(true)
        && !revocation_method
            .get_capabilities()
            .operations
            .contains(&Operation::Suspend)
    {
        return Err(BusinessLogicError::SuspensionNotAvailableForSelectedRevocationMethod.into());
    }

    if revocation_method.get_capabilities().operations == vec![Operation::Suspend]
        && request.allow_suspension != Some(true)
    {
        return Err(BusinessLogicError::SuspensionNotEnabledForSuspendOnlyRevocationMethod.into());
    }

    Ok(())
}

fn validate_revocation_method_is_compatible_with_format(
    request: &CreateCredentialSchemaRequestDTO,
    config: &CoreConfig,
    formatter: &dyn CredentialFormatter,
) -> Result<(), ServiceError> {
    let revocation_method = config.revocation.get_fields(&request.revocation_method)?;

    if !formatter
        .get_capabilities()
        .revocation_methods
        .contains(&revocation_method.r#type)
    {
        return Err(BusinessLogicError::RevocationMethodNotCompatibleWithSelectedFormat.into());
    }

    Ok(())
}

fn validate_credential_design(
    request: &CreateCredentialSchemaRequestDTO,
    formatter: &dyn CredentialFormatter,
) -> Result<(), ServiceError> {
    if request.layout_properties.is_some()
        && !formatter
            .get_capabilities()
            .features
            .contains(&Features::SupportsCredentialDesign)
    {
        return Err(BusinessLogicError::LayoutPropertiesNotSupported.into());
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
    formatter: &dyn CredentialFormatter,
    during_import: bool,
) -> Result<(), ServiceError> {
    let format_features = formatter.get_capabilities().features;
    if format_features.contains(&Features::RequiresSchemaId)
        || (format_features.contains(&Features::RequiresSchemaIdForExternal)
            && request.external_schema)
    {
        let schema_id = request.schema_id.as_deref().filter(|s| !s.is_empty());
        let Some(schema_id) = schema_id else {
            return Err(BusinessLogicError::MissingSchemaId.into());
        };

        let allowed_schema_ids = formatter.get_capabilities().allowed_schema_ids;
        if !allowed_schema_ids.is_empty() && !allowed_schema_ids.iter().any(|v| v == schema_id) {
            return Err(ValidationError::SchemaIdNotAllowedForFormat.into());
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

pub(crate) fn validate_wallet_storage_type_supported(
    wallet_storage_type: Option<WalletStorageTypeEnum>,
    config: &CoreConfig,
) -> Result<(), ValidationError> {
    if let Some(wallet_storage_type) = wallet_storage_type
        && config
            .holder_key_storage
            .get(&wallet_storage_type)
            .is_none_or(|entry| entry.enabled == Some(false))
    {
        return Err(ValidationError::WalletStorageTypeDisabled(
            wallet_storage_type,
        ));
    }

    Ok(())
}
