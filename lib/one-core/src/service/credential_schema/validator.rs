use std::collections::HashSet;

use itertools::Itertools;
use shared_types::{CredentialFormat, OrganisationId};
use standardized_types::etsi_119_472::disclosure_policy::PolicyType;

use super::dto::{
    CreateCredentialSchemaV2RequestDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaFormatRequestDTO, CredentialSchemaLayoutPropertiesRequestDTO,
    CredentialSchemaTransactionCodeRequestDTO,
};
use super::error::CredentialSchemaServiceError;
use super::mapper::create_unique_name_check_request;
use crate::config::core_config::{ConfigExt, CoreConfig, DatatypeType, IdentifierType};
use crate::config::validator::datatype::validate_datatypes;
use crate::config::validator::format::validate_format;
use crate::error::{ContextWithErrorCode, NestedError};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::credential_schema::{GetCredentialSchemaList, KeyStorageSecurity};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{Features, FormatterCapabilities};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::model::Operation;
use crate::provider::verification_protocol::openid4vp::disclosure_policy::{
    parse_dn, parse_serial,
};
use crate::repository::credential_schema_repository::CredentialSchemaRepository;

pub(crate) async fn credential_schema_already_exists(
    repository: &dyn CredentialSchemaRepository,
    name: &str,
    ecosystem_schema_ids: Vec<String>,
    organisation_id: OrganisationId,
) -> Result<UniquenessCheckResult, CredentialSchemaServiceError> {
    let credential_schemas = repository
        .get_credential_schema_list(create_unique_name_check_request(
            name,
            ecosystem_schema_ids.clone(),
            organisation_id,
        )?)
        .await
        .error_while("getting credential schemas")?;

    if exists_credential_schema_with_same_ecosystem_schema_id(
        &credential_schemas,
        &ecosystem_schema_ids,
    )
    .await?
    {
        return Ok(UniquenessCheckResult::SchemaIdConflict);
    }
    if credential_schemas.values.iter().any(|cs| cs.name == name) {
        Ok(UniquenessCheckResult::NameConflict)
    } else {
        Ok(UniquenessCheckResult::Ok)
    }
}

async fn exists_credential_schema_with_same_ecosystem_schema_id(
    credential_schemas: &GetCredentialSchemaList,
    ecosystem_schema_ids: &[String],
) -> Result<bool, NestedError> {
    for value in &credential_schemas.values {
        if value.matches_schema_id(ecosystem_schema_ids).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) enum UniquenessCheckResult {
    SchemaIdConflict,
    NameConflict,
    Ok,
}

pub(crate) fn validate_create_v2_request(
    request: &CreateCredentialSchemaV2RequestDTO,
    config: &CoreConfig,
    formatter_provider: &dyn crate::provider::credential_formatter::provider::CredentialFormatterProvider,
) -> Result<(), CredentialSchemaServiceError> {
    if request.formats.is_empty() {
        return Err(CredentialSchemaServiceError::MissingFormats);
    }
    validate_unique_formats(&request.formats)?;

    if request.claims.is_empty() {
        return Err(CredentialSchemaServiceError::MissingClaimSchemas);
    }
    if let Some(batch_size) = request.batch_size
        && batch_size < 2
    {
        return Err(CredentialSchemaServiceError::BatchSizeTooSmall);
    }

    if let Some(expiration) = request.expiration
        && (expiration <= time::Duration::ZERO
            || expiration
                > config
                    .global_settings
                    .credential_schema
                    .max_expiration_seconds)
    {
        return Err(CredentialSchemaServiceError::InvalidExpiration);
    }

    if let Some(wallet_attestation) = &request.wallet_attestation
        && [
            wallet_attestation.preferred_key_storage_attestation_lifetime,
            wallet_attestation.preferred_instance_attestation_lifetime,
        ]
        .into_iter()
        .flatten()
        .any(|lifetime| lifetime <= time::Duration::ZERO)
    {
        return Err(CredentialSchemaServiceError::InvalidWalletAttestationLifetime);
    }

    if let Some(embedded_disclosure_policy) = &request.embedded_disclosure_policy {
        validate_disclosure_policy(&embedded_disclosure_policy.policy)?;
    }

    validate_key_lengths(&request.claims, 0)?;

    let mut common_capabilities: Option<FormatterCapabilities> = None;
    for format_req in &request.formats {
        validate_format(&format_req.format, &config.format).error_while("validating format")?;

        let formatter = formatter_provider.get_credential_formatter(&format_req.format)?;

        validate_nested_claim_schemas(&request.claims, config)?;
        validate_claim_names_for_formatter(&request.claims, &*formatter)?;
        validate_credential_design(request.layout_properties.as_ref(), &*formatter)?;
        validate_transaction_code(request.transaction_code.as_ref(), &*formatter)?;

        let capabilities = formatter.get_capabilities();
        if let Some(common_capabilities) = common_capabilities.as_mut() {
            common_capabilities.combine_constraints(&capabilities);
        } else {
            common_capabilities = Some(capabilities);
        }
    }

    let common_capabilities =
        common_capabilities.ok_or(CredentialSchemaServiceError::MissingFormats)?;
    validate_common_datatype_capabilities(&request.claims, &common_capabilities.datatypes)?;
    validate_common_identifier_capabilities(&common_capabilities)?;
    Ok(())
}

fn validate_common_identifier_capabilities(
    capabilities: &FormatterCapabilities,
) -> Result<(), CredentialSchemaServiceError> {
    // An empty DID method intersection is acceptable when another common identifier
    // type can be used, e.g. certificate issuance for SD-JWT VC and mdoc.
    let can_issue = capabilities
        .issuance_identifier_types
        .iter()
        .any(|identifier| {
            *identifier != IdentifierType::Did || !capabilities.issuance_did_methods.is_empty()
        })
        && !capabilities.signing_key_algorithms.is_empty();
    let can_hold = capabilities
        .holder_identifier_types
        .iter()
        .any(|identifier| {
            *identifier != IdentifierType::Did || !capabilities.holder_did_methods.is_empty()
        })
        && !capabilities.holder_key_algorithms.is_empty();
    let can_verify = !capabilities.verification_identifier_types.is_empty()
        && !capabilities.verification_key_algorithms.is_empty()
        && !capabilities.verification_key_storages.is_empty();

    if !can_issue || !can_hold || !can_verify {
        return Err(CredentialSchemaServiceError::IncompatibleFormats);
    }
    Ok(())
}

fn validate_unique_formats(
    formats: &[CredentialSchemaFormatRequestDTO],
) -> Result<(), CredentialSchemaServiceError> {
    if !formats.iter().map(|format| &format.format).all_unique() {
        return Err(CredentialSchemaServiceError::DuplicateFormats);
    }
    Ok(())
}

fn validate_claim_names_for_formatter(
    claims: &[CredentialClaimSchemaRequestDTO],
    formatter: &dyn CredentialFormatter,
) -> Result<(), CredentialSchemaServiceError> {
    let capabilities = formatter.get_capabilities();
    let format = formatter.config_name();

    for root_claim in claims {
        check_claim_against_forbidden_technical_keys(
            root_claim,
            format,
            &capabilities.forbidden_root_claim_technical_keys,
        )?;

        validate_technical_keys_are_not_forbidden_recursive(
            root_claim,
            format,
            &capabilities.forbidden_claim_technical_keys,
        )?;
    }

    Ok(())
}

fn validate_technical_keys_are_not_forbidden_recursive(
    claim: &CredentialClaimSchemaRequestDTO,
    format: &CredentialFormat,
    forbidden_technical_keys: &[String],
) -> Result<(), CredentialSchemaServiceError> {
    check_claim_against_forbidden_technical_keys(claim, format, forbidden_technical_keys)?;

    for child_claim in &claim.claims {
        validate_technical_keys_are_not_forbidden_recursive(
            child_claim,
            format,
            forbidden_technical_keys,
        )?;
    }

    Ok(())
}

fn check_claim_against_forbidden_technical_keys(
    claim: &CredentialClaimSchemaRequestDTO,
    format: &CredentialFormat,
    forbidden_technical_keys: &[String],
) -> Result<(), CredentialSchemaServiceError> {
    let mapping = claim
        .mappings
        .as_ref()
        .and_then(|mappings| mappings.iter().find(|mapping| &mapping.format == format));

    let technical_key = mapping
        .map(|mapping| &mapping.technical_key)
        .unwrap_or(&claim.key);

    if forbidden_technical_keys.contains(technical_key) {
        return Err(CredentialSchemaServiceError::ForbiddenClaimName);
    }

    Ok(())
}

fn validate_credential_design(
    layout_properties: Option<&CredentialSchemaLayoutPropertiesRequestDTO>,
    formatter: &dyn CredentialFormatter,
) -> Result<(), CredentialSchemaServiceError> {
    if layout_properties.is_some()
        && !formatter
            .get_capabilities()
            .features
            .contains(&Features::SupportsCredentialDesign)
    {
        return Err(CredentialSchemaServiceError::LayoutPropertiesNotSupported);
    }
    Ok(())
}

fn validate_transaction_code(
    transaction_code: Option<&CredentialSchemaTransactionCodeRequestDTO>,
    formatter: &dyn CredentialFormatter,
) -> Result<(), CredentialSchemaServiceError> {
    if let Some(transaction_code) = transaction_code {
        if !formatter
            .get_capabilities()
            .features
            .contains(&Features::SupportsTxCode)
        {
            return Err(CredentialSchemaServiceError::TransactionCodeNotSupported);
        }

        if let Some(description) = &transaction_code.description
            && (description.is_empty() || description.len() > 300)
        {
            return Err(CredentialSchemaServiceError::InvalidTransactionCodeDescriptionLength);
        }
    }

    Ok(())
}

pub(super) fn validate_revocation_method_is_compatible_with_suspension(
    allow_suspension: Option<bool>,
    revocation_method: Option<&dyn RevocationMethod>,
) -> Result<(), CredentialSchemaServiceError> {
    let operations = match revocation_method {
        Some(method) => method.get_capabilities().operations,
        None => vec![],
    };

    match allow_suspension {
        Some(true) => {
            if !operations.contains(&Operation::Suspend) {
                return Err(
                    CredentialSchemaServiceError::SuspensionNotAvailableForSelectedRevocationMethod,
                );
            }
        }
        _ => {
            if operations == vec![Operation::Suspend] {
                return Err(
                    CredentialSchemaServiceError::SuspensionNotEnabledForSuspendOnlyRevocationMethod,
                );
            }
        }
    }

    Ok(())
}

pub(super) fn validate_claim_mappings_for_format(
    flat_claims: &[CredentialClaimSchemaRequestDTO],
    formats: &[CredentialSchemaFormatRequestDTO],
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<(), CredentialSchemaServiceError> {
    let formats = formats.iter().map(|f| &f.format).collect::<Vec<_>>();
    for claim in flat_claims {
        if let Some(mappings) = &claim.mappings {
            if !mappings.iter().map(|m| &m.format).all_unique() {
                return Err(CredentialSchemaServiceError::DuplicateMappingFormats(
                    claim.key.clone(),
                ));
            }

            for mapping in mappings {
                if !formats.iter().any(|f| **f == mapping.format) {
                    return Err(CredentialSchemaServiceError::MappingFormatNotPartOfFormats(
                        claim.key.clone(),
                        mapping.format.clone(),
                    ));
                }
                let formatter = formatter_provider.get_credential_formatter(&mapping.format)?;
                let requires_namespaces = formatter
                    .get_capabilities()
                    .features
                    .contains(&Features::RequiresNamespaces);
                if requires_namespaces && mapping.namespace.is_none() {
                    return Err(CredentialSchemaServiceError::MappingNamespaceMissing(
                        claim.key.clone(),
                        mapping.format.clone(),
                    ));
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn check_background_properties(
    layout_properties: Option<&CredentialSchemaLayoutPropertiesRequestDTO>,
) -> Result<(), CredentialSchemaServiceError> {
    let background = layout_properties.and_then(|p| p.background.as_ref());

    if let Some(background) = background {
        return match (background.color.as_ref(), background.image.as_ref()) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            _ => Err(CredentialSchemaServiceError::AttributeCombinationNotAllowed),
        };
    }

    Ok(())
}

pub(crate) fn check_logo_properties(
    layout_properties: Option<&CredentialSchemaLayoutPropertiesRequestDTO>,
) -> Result<(), CredentialSchemaServiceError> {
    let logo = layout_properties.and_then(|p| p.logo.as_ref());

    if let Some(logo) = logo {
        return match (
            logo.background_color.as_ref(),
            logo.font_color.as_ref(),
            logo.image.as_ref(),
        ) {
            (Some(_), Some(_), None) | (None, None, Some(_)) => Ok(()),
            _ => Err(CredentialSchemaServiceError::AttributeCombinationNotAllowed),
        };
    }

    Ok(())
}

pub(crate) fn check_claims_presence_in_layout_properties(
    layout_properties: Option<&CredentialSchemaLayoutPropertiesRequestDTO>,
    claims: &[CredentialClaimSchemaRequestDTO],
) -> Result<(), CredentialSchemaServiceError> {
    let primary_attribute = layout_properties.and_then(|p| p.primary_attribute.as_ref());
    let secondary_attribute = layout_properties.and_then(|p| p.secondary_attribute.as_ref());
    let picture_attribute = layout_properties.and_then(|p| p.picture_attribute.as_ref());
    let code_attribute = layout_properties
        .and_then(|p| p.code.as_ref())
        .map(|c| &c.attribute);

    if primary_attribute.is_none()
        && secondary_attribute.is_none()
        && picture_attribute.is_none()
        && code_attribute.is_none()
    {
        return Ok(());
    }

    let claim_paths = get_all_claim_paths(claims);

    handle_attribute_claim_validation(primary_attribute, &claim_paths, "Primary")?;
    handle_attribute_claim_validation(secondary_attribute, &claim_paths, "Secondary")?;
    handle_attribute_claim_validation(picture_attribute, &claim_paths, "Picture")?;
    handle_attribute_claim_validation(code_attribute, &claim_paths, "Code attribute")?;

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
) -> Result<(), CredentialSchemaServiceError> {
    if let Some(attribute) = attribute
        && !claims.iter().any(|c| c == attribute)
    {
        return Err(CredentialSchemaServiceError::MissingLayoutAttribute(
            attribute_name.to_owned(),
        ));
    }
    Ok(())
}

fn validate_nested_claim_schemas(
    claims: &[CredentialClaimSchemaRequestDTO],
    config: &CoreConfig,
) -> Result<(), CredentialSchemaServiceError> {
    validate_claim_schema_keys_unique(claims)?;

    for claim_schema in gather_claim_schemas(claims) {
        validate_claim_schema(claim_schema, config)?;
    }

    Ok(validate_datatypes(
        gather_claim_schemas(claims).map(|value| value.datatype.as_str()),
        &config.datatype,
    )
    .error_while("validating datatypes")?)
}

fn validate_claim_schema(
    claim_schema: &CredentialClaimSchemaRequestDTO,
    config: &CoreConfig,
) -> Result<(), CredentialSchemaServiceError> {
    let claim_type = config
        .datatype
        .get_fields(&claim_schema.datatype)
        .error_while("getting datatype config")?
        .r#type();
    validate_claim_schema_name(claim_schema)?;
    validate_claim_schema_type(claim_schema, claim_type)?;
    if let Some(true) = claim_schema.array {
        config
            .datatype
            .get_if_enabled("ARRAY")
            .error_while("validating datatype")?;
    }
    Ok(())
}

fn validate_claim_schema_name(
    claim_schema: &CredentialClaimSchemaRequestDTO,
) -> Result<(), CredentialSchemaServiceError> {
    if claim_schema.key.find(NESTED_CLAIM_MARKER).is_some() {
        Err(CredentialSchemaServiceError::ClaimSchemaSlashInKeyName(
            claim_schema.key.to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn validate_claim_schema_keys_unique(
    claims: &[CredentialClaimSchemaRequestDTO],
) -> Result<(), CredentialSchemaServiceError> {
    let mut uniq = HashSet::new();
    if !claims
        .iter()
        .all(move |claim| uniq.insert(claim.key.to_owned()))
    {
        return Err(CredentialSchemaServiceError::DuplicitClaim);
    }

    for claim in claims {
        validate_claim_schema_keys_unique(&claim.claims)?;
    }

    Ok(())
}

fn validate_claim_schema_type(
    claim_schema: &CredentialClaimSchemaRequestDTO,
    claim_type: &DatatypeType,
) -> Result<(), CredentialSchemaServiceError> {
    match claim_type {
        DatatypeType::Object => {
            if claim_schema.claims.is_empty() {
                return Err(CredentialSchemaServiceError::MissingNestedClaims(
                    claim_schema.key.to_owned(),
                ));
            }
        }
        _ => {
            if !claim_schema.claims.is_empty() {
                return Err(CredentialSchemaServiceError::NestedClaimsShouldBeEmpty(
                    claim_schema.key.to_owned(),
                ));
            }
        }
    }

    Ok(())
}

fn validate_common_datatype_capabilities(
    claims: &[CredentialClaimSchemaRequestDTO],
    supported_datatypes: &[String],
) -> Result<(), CredentialSchemaServiceError> {
    for claim in gather_claim_schemas(claims) {
        if claim.array == Some(true) {
            validate_datatype_formatter_capabilities(&claim.key, "ARRAY", supported_datatypes)?;
        }
        validate_datatype_formatter_capabilities(&claim.key, &claim.datatype, supported_datatypes)?;
    }
    Ok(())
}

fn validate_datatype_formatter_capabilities(
    claim_name: &str,
    datatype: &str,
    supported_datatypes: &[String],
) -> Result<(), CredentialSchemaServiceError> {
    if !supported_datatypes
        .iter()
        .any(|supported| supported == datatype)
    {
        return Err(
            CredentialSchemaServiceError::DatatypeNotSupportedByAllFormats {
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

fn validate_key_lengths(
    claims: &[CredentialClaimSchemaRequestDTO],
    prefix_length: usize,
) -> Result<(), CredentialSchemaServiceError> {
    const MAX_KEY_LENGTH: usize = 255;
    const NESTED_CLAIM_MARKER_LENGTH: usize = 1;

    claims.iter().try_for_each(|claim| {
        if claim.key.len() + prefix_length > MAX_KEY_LENGTH {
            return Err(CredentialSchemaServiceError::ClaimSchemaKeyTooLong);
        }

        validate_key_lengths(&claim.claims, claim.key.len() + NESTED_CLAIM_MARKER_LENGTH)
    })
}

pub(crate) fn validate_key_storage_security_supported(
    key_storage_security: Option<KeyStorageSecurity>,
    config: &CoreConfig,
) -> Result<(), CredentialSchemaServiceError> {
    let Some(key_storage_security) = key_storage_security else {
        return Ok(());
    };
    config
        .key_security_level
        .get_if_enabled(&key_storage_security.into())
        .map_err(|_| {
            CredentialSchemaServiceError::KeyStorageSecurityDisabled(key_storage_security)
        })?;
    Ok(())
}

fn validate_disclosure_policy(policy: &PolicyType) -> Result<(), CredentialSchemaServiceError> {
    match policy {
        PolicyType::None => {}
        PolicyType::AllowList { options } => {
            for option in &options.values {
                if let Some(dn) = &option.dn {
                    parse_dn(dn).error_while("parsing disclosure policy")?;
                }
            }
        }
        PolicyType::RootOfTrust { options } => {
            for option in &options.values {
                parse_dn(&option.dn).error_while("parsing disclosure policy DN")?;
                parse_serial(&option.serial).map_err(|e| {
                    CredentialSchemaServiceError::MappingError(format!(
                        "parsing disclosure policy Serial: `{e}`"
                    ))
                })?;
            }
        }
    }

    Ok(())
}
