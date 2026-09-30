use std::collections::HashMap;
use std::str::FromStr;

use indexmap::IndexMap;
use one_crypto::utilities;
use secrecy::SecretString;
use shared_types::{ClaimSchemaId, IdentifierId, InteractionId};
use standardized_types::etsi_119_472::disclosure_policy::DisclosurePolicy;
use standardized_types::oauth2::TokenType;
use standardized_types::oauth2::token::{ExpiresIn, TokenRequest, TokenResponse};
use standardized_types::openid4vci::{
    BatchCredentialIssuance, ClaimDisplay, ClaimMetadata, CredentialConfiguration,
    CredentialDisplay, CredentialIssuerMetadata, CredentialMetadata, CredentialOffer,
    CredentialRequestEncryption, CredentialResponseEncryption, Grants, Image, IssuerDisplay,
    IssuerInfoAttestation, PreAuthorizedCodeGrant, ProofTypeSupported, SigningAlgValue, TxCode,
};
use standardized_types::openid4vp::dcql::{ClaimPath, PathSegment};
use time::Duration;
use uuid::Uuid;

use super::model::{
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign,
    PreparedMetadata,
};
use super::validator::{
    throw_if_credential_state_not_eq, throw_if_interaction_created_date,
    throw_if_interaction_pre_authorized_code_used, throw_if_token_request_invalid,
    throw_if_tx_code_invalid, validate_refresh_token,
};
use crate::config::ConfigValidationError;
use crate::config::core_config::{DatatypeConfig, DatatypeType, FormatType};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::model::localized_text::{LocalizedText, LocalizedTextField};
use crate::provider::issuance_protocol::error::{OpenID4VCIError, OpenIDIssuanceError};
use crate::provider::issuance_protocol::openid4vci_final1_0::model::PROCIVIS_DESIGN_KEY;

pub(crate) fn build_issuer_display(
    identifier_name: &str,
    translations: &[LocalizedText],
    logo_uri: Option<&str>,
    default_language: &str,
) -> Vec<IssuerDisplay> {
    let logo_for = |lang: &str| {
        logo_uri.map(|uri| Image {
            uri: uri.to_owned(),
            alt_text: translations
                .iter()
                .find(|text| text.field == LocalizedTextField::LogoAltText && text.lang == lang)
                .map(|text| text.value.clone()),
        })
    };

    let name_translations: Vec<&LocalizedText> = translations
        .iter()
        .filter(|text| text.field == LocalizedTextField::Name)
        .collect();

    if name_translations.is_empty() {
        return vec![IssuerDisplay {
            name: identifier_name.to_owned(),
            locale: Some(default_language.to_owned()),
            logo: logo_for(default_language),
        }];
    }

    name_translations
        .into_iter()
        .map(|text| IssuerDisplay {
            name: text.value.clone(),
            locale: Some(text.lang.clone()),
            logo: logo_for(&text.lang),
        })
        .collect()
}

pub(crate) fn create_issuer_metadata_response(
    protocol_id: &str,
    identifier: &Identifier,
    PreparedMetadata {
        protocol_base_url,
        schema,
        credential_configurations_supported,
    }: PreparedMetadata,
    issuer_info: Vec<IssuerInfoAttestation>,
    credential_request_encryption: Option<CredentialRequestEncryption>,
    credential_response_encryption: Option<CredentialResponseEncryption>,
    issuer_display: Vec<IssuerDisplay>,
) -> Result<CredentialIssuerMetadata, OpenID4VCIError> {
    let credential_schema_id = schema.id;
    let credential_issuer = format!(
        "{protocol_base_url}/{protocol_id}/{}/{credential_schema_id}",
        identifier.id
    );

    let batch_credential_issuance = if let Some(batch_size) = schema.batch_size
        && batch_size >= 2
    {
        Some(BatchCredentialIssuance {
            batch_size: batch_size as _,
        })
    } else {
        None
    };

    Ok(CredentialIssuerMetadata {
        credential_issuer,
        authorization_servers: None,
        credential_endpoint: format!("{protocol_base_url}/{credential_schema_id}/credential"),
        nonce_endpoint: Some(format!("{protocol_base_url}/{protocol_id}/nonce")),
        notification_endpoint: Some(format!(
            "{protocol_base_url}/{credential_schema_id}/notification"
        )),
        credential_configurations_supported,
        display: Some(issuer_display),
        issuer_info,
        batch_credential_issuance,
        credential_request_encryption,
        credential_response_encryption,
        preferred_client_status_period: schema
            .wallet_attestation
            .preferred_instance_attestation_lifetime
            .map(|lifetime| lifetime.whole_seconds() as u64),
    })
}

pub(crate) async fn credential_configuration_supported(
    format_type: &FormatType,
    format: &CredentialSchemaFormat,
    credential_schema: &CredentialSchema,
    datatype_config: &DatatypeConfig,
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: IndexMap<String, ProofTypeSupported>,
    credential_signing_alg_values_supported: Vec<String>,
) -> Result<CredentialConfiguration, OpenID4VCIError> {
    let credential_metadata_claims =
        create_claims_dtos_from_claims(credential_schema, format, datatype_config).await?;
    let display_dtos = create_display_dtos_from_schema(credential_schema, format).await?;

    let credential_metadata = CredentialMetadata {
        display: Some(display_dtos),
        claims: Some(credential_metadata_claims),
    };
    let proof_types_supported = Some(proof_types_supported);

    let disclosure_policy = match &credential_schema.embedded_disclosure_policy {
        None => None,
        Some(policy) => Some(
            serde_json::from_str(policy)
                .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?,
        ),
    };

    Ok(match format_type {
        FormatType::JsonLdClassic | FormatType::JsonLdBbsPlus => jsonld_configuration(
            "ldp_vc",
            credential_metadata,
            cryptographic_binding_methods_supported,
            proof_types_supported,
            disclosure_policy,
        ),
        FormatType::Jwt => jwt_configuration(
            "jwt_vc_json",
            credential_metadata,
            cryptographic_binding_methods_supported,
            proof_types_supported,
            credential_signing_alg_values_supported,
            disclosure_policy,
        ),
        FormatType::SdJwt => sdjwt_configuration(
            "vc+sd-jwt",
            credential_metadata,
            &format.ecosystem_schema_id,
            cryptographic_binding_methods_supported,
            proof_types_supported,
            credential_signing_alg_values_supported,
            disclosure_policy,
        ),
        FormatType::SdJwtVc => sdjwt_configuration(
            "dc+sd-jwt",
            credential_metadata,
            &format.ecosystem_schema_id,
            cryptographic_binding_methods_supported,
            proof_types_supported,
            credential_signing_alg_values_supported,
            disclosure_policy,
        ),
        FormatType::Mdoc => mdoc_configuration(
            format.ecosystem_schema_id.to_string(),
            credential_metadata,
            proof_types_supported,
            disclosure_policy,
        ),
    })
}

async fn create_claims_dtos_from_claims(
    credential_schema: &CredentialSchema,
    format: &CredentialSchemaFormat,
    datatype_config: &DatatypeConfig,
) -> Result<Vec<ClaimMetadata>, OpenID4VCIError> {
    let claim_schemas = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?;

    let claim_mappings = format
        .claim_mappings
        .as_ref()
        .await
        .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?;

    let mandatory_by_claim_id = calculate_mandatory_claims(&claim_schemas, datatype_config)
        .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?;
    let claim_mappings_by_claim_id: HashMap<_, _> = claim_mappings
        .iter()
        .map(|mapping| (mapping.claim_schema_id, mapping))
        .collect();
    let mut paths_by_claim_id = claim_metadata_paths(&claim_schemas, &claim_mappings_by_claim_id)?;

    let mut result = vec![];
    for claim_schema in &claim_schemas {
        if claim_schema.metadata {
            continue;
        }

        let path = paths_by_claim_id.remove(&claim_schema.id).ok_or_else(|| {
            OpenID4VCIError::RuntimeError("Missing claim metadata path".to_string())
        })?;

        let display = create_claim_display_dtos(claim_schema).await?;

        result.push(ClaimMetadata {
            path,
            mandatory: mandatory_by_claim_id.get(&claim_schema.id).copied(),
            additional_values: Default::default(),
            display: Some(display),
        });
    }
    Ok(result)
}

fn mapping_property_path(mapping: &CredentialSchemaFormatClaimSchema) -> Vec<String> {
    let mut path = Vec::new();
    if let Some(namespace) = &mapping.namespace {
        path.push(namespace.clone());
    }
    path.extend(mapping.technical_key.split('/').map(str::to_owned));
    path
}

struct MappedClaimPath<'a> {
    schema_key: &'a str,
    properties: Vec<String>,
    path: ClaimPath,
    array: bool,
}

/// Build paths from root to leaf. Each path carries the wildcards of its array ancestors, while
/// mapped technical names (including numeric property names) remain string segments.
fn claim_metadata_paths(
    claim_schemas: &[ClaimSchema],
    mappings_by_claim_id: &HashMap<ClaimSchemaId, &CredentialSchemaFormatClaimSchema>,
) -> Result<HashMap<ClaimSchemaId, ClaimPath>, OpenID4VCIError> {
    let mut ordered_schemas = claim_schemas
        .iter()
        .filter(|schema| !schema.metadata)
        .collect::<Vec<_>>();
    // Compare path components so a parent's entire subtree precedes the next sibling.
    ordered_schemas.sort_unstable_by(|left, right| {
        left.key
            .split(NESTED_CLAIM_MARKER)
            .cmp(right.key.split(NESTED_CLAIM_MARKER))
    });

    let mut ancestors: Vec<MappedClaimPath<'_>> = Vec::new();
    let mut paths_by_claim_id = HashMap::with_capacity(ordered_schemas.len());
    for schema in ordered_schemas {
        // Discard finished sibling branches, leaving the nearest mapped ancestor on top.
        while ancestors.last().is_some_and(|parent| {
            !schema
                .key
                .strip_prefix(parent.schema_key)
                .is_some_and(|suffix| suffix.starts_with(NESTED_CLAIM_MARKER))
        }) {
            ancestors.pop();
        }

        let mapping = mappings_by_claim_id.get(&schema.id).ok_or_else(|| {
            OpenID4VCIError::RuntimeError(format!("Missing claim mapping for `{}`", schema.key))
        })?;
        let properties = mapping_property_path(mapping);
        let segments = if let Some(parent) = ancestors.last() {
            let Some(child_properties) = properties
                .strip_prefix(parent.properties.as_slice())
                .filter(|suffix| !suffix.is_empty())
            else {
                return Err(OpenID4VCIError::RuntimeError(format!(
                    "Inconsistent claim mapping: `{}` does not extend its ancestor `{}`",
                    schema.key, parent.schema_key
                )));
            };
            let mut segments = parent.path.segments.clone();
            if parent.array {
                segments.push(PathSegment::ArrayAll);
            }
            segments.extend(
                child_properties
                    .iter()
                    .cloned()
                    .map(PathSegment::PropertyName),
            );
            segments
        } else {
            properties
                .iter()
                .cloned()
                .map(PathSegment::PropertyName)
                .collect()
        };
        let path = ClaimPath { segments };
        paths_by_claim_id.insert(schema.id, path.clone());
        ancestors.push(MappedClaimPath {
            schema_key: &schema.key,
            properties,
            path,
            array: schema.array,
        });
    }
    Ok(paths_by_claim_id)
}

pub(super) fn calculate_mandatory_claims(
    claim_schemas: &[ClaimSchema],
    datatype_config: &DatatypeConfig,
) -> Result<HashMap<ClaimSchemaId, bool>, ConfigValidationError> {
    let claim_schemas_by_key: HashMap<_, _> = claim_schemas
        .iter()
        .filter(|claim| !claim.metadata)
        .map(|claim| (claim.key.as_str(), claim))
        .collect();
    let mut children_by_parent: HashMap<&str, Vec<&ClaimSchema>> = HashMap::new();
    let mut root_claims = Vec::new();

    for claim_schema in claim_schemas_by_key.values() {
        match claim_schema.key.rsplit_once(NESTED_CLAIM_MARKER) {
            Some((parent_key, _)) if claim_schemas_by_key.contains_key(parent_key) => {
                children_by_parent
                    .entry(parent_key)
                    .or_default()
                    .push(claim_schema);
            }
            _ => root_claims.push(*claim_schema),
        }
    }

    let mut mandatory_by_claim_id = HashMap::with_capacity(claim_schemas_by_key.len());
    for root_claim in root_claims {
        is_claim_always_present(
            root_claim,
            true,
            &children_by_parent,
            datatype_config,
            &mut mandatory_by_claim_id,
        )?;
    }

    Ok(mandatory_by_claim_id)
}

fn is_claim_always_present(
    claim_schema: &ClaimSchema,
    ancestors_required: bool,
    children_by_parent: &HashMap<&str, Vec<&ClaimSchema>>,
    datatype_config: &DatatypeConfig,
    mandatory_by_claim_id: &mut HashMap<ClaimSchemaId, bool>,
) -> Result<bool, ConfigValidationError> {
    let claim_and_ancestors_required = ancestors_required && claim_schema.required;
    let mut has_mandatory_non_object_descendant = false;

    if let Some(children) = children_by_parent.get(claim_schema.key.as_str()) {
        for child in children {
            has_mandatory_non_object_descendant |= is_claim_always_present(
                child,
                claim_and_ancestors_required,
                children_by_parent,
                datatype_config,
                mandatory_by_claim_id,
            )?;
        }
    }

    let is_object =
        datatype_config.get_fields(&claim_schema.data_type)?.r#type == DatatypeType::Object;
    let mandatory =
        claim_and_ancestors_required && (!is_object || has_mandatory_non_object_descendant);
    mandatory_by_claim_id.insert(claim_schema.id, mandatory);

    Ok(mandatory)
}

async fn create_display_dto_from_schema(
    credential_schema: &CredentialSchema,
    format: &CredentialSchemaFormat,
) -> Result<CredentialDisplay, OpenID4VCIError> {
    let mut display = CredentialDisplay {
        name: credential_schema.name.clone(),
        ..Default::default()
    };

    if let Some(layout_properties) = credential_schema.layout_properties.to_owned() {
        // Extract background
        if let Some(background) = layout_properties.background {
            display.background_color = background.color;
            display.background_image = background.image.map(|uri| Image {
                uri,
                alt_text: None,
            });
        }

        // Extract logo
        if let Some(logo) = layout_properties.logo {
            display.text_color = logo.font_color;
            display.logo = logo.image.map(|uri| Image {
                uri,
                alt_text: Some(format!("{} logo", credential_schema.name)),
            });
        }

        // procivis custom attributes
        let claim_schemas = credential_schema
            .claim_schemas
            .as_ref()
            .await
            .map_err(|err| OpenID4VCIError::RuntimeError(err.to_string()))?;
        let claim_mappings = format
            .claim_mappings
            .as_ref()
            .await
            .map_err(|err| OpenID4VCIError::RuntimeError(err.to_string()))?;
        let attribute_to_claim_path =
            move |attribute: Option<String>| -> Result<Option<String>, OpenID4VCIError> {
                let Some(attribute) = attribute else {
                    return Ok(None);
                };

                let claim_schema_id = claim_schemas
                    .iter()
                    .find(|cs| cs.key == attribute)
                    .ok_or(OpenID4VCIError::RuntimeError(format!(
                        "No claim schema found for attribute: {attribute}"
                    )))?
                    .id;

                let mapping = claim_mappings
                    .iter()
                    .find(|m| m.claim_schema_id == claim_schema_id)
                    .ok_or(OpenID4VCIError::RuntimeError(format!(
                        "No mapping for claim schema ID: {claim_schema_id}"
                    )))?;

                let attribute_path = match (&mapping.namespace, &mapping.technical_key) {
                    (Some(namespace), technical_key) => {
                        // We need to prepend namespace on server side for 2 reasons:
                        // 1. mdoc formatter prepends namespace into the technical key on holder side
                        // 2. technical keys are not unique, combinations with namespace are
                        format!("{namespace}_{technical_key}")
                    }
                    (&None, technical_key) => technical_key.to_owned(),
                };

                Ok(Some(attribute_path))
            };

        let procivis_design = OpenID4VCIIssuerMetadataCredentialMetadataProcivisDesign {
            primary_attribute: attribute_to_claim_path(layout_properties.primary_attribute)?,
            secondary_attribute: attribute_to_claim_path(layout_properties.secondary_attribute)?,
            picture_attribute: attribute_to_claim_path(layout_properties.picture_attribute)?,
            code_type: layout_properties.code.as_ref().map(|code| code.r#type),
            code_attribute: attribute_to_claim_path(
                layout_properties.code.map(|code| code.attribute),
            )?,
        };
        display.additional_values.insert(
            PROCIVIS_DESIGN_KEY.to_string(),
            serde_json::to_value(procivis_design)
                .map_err(|err| OpenID4VCIError::RuntimeError(err.to_string()))?,
        );
    }

    Ok(display)
}

async fn create_display_dtos_from_schema(
    credential_schema: &CredentialSchema,
    format: &CredentialSchemaFormat,
) -> Result<Vec<CredentialDisplay>, OpenID4VCIError> {
    let translations = credential_schema
        .translations
        .as_ref()
        .await
        .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?;

    if translations.is_empty() {
        return Ok(vec![
            create_display_dto_from_schema(credential_schema, format).await?,
        ]);
    }

    let visual_base = create_display_dto_from_schema(credential_schema, format).await?;

    let mut by_lang: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
    for translation in &translations {
        let entry = by_lang.entry(translation.lang.clone()).or_default();
        match translation.field {
            LocalizedTextField::Name => entry.0 = Some(translation.value.clone()),
            LocalizedTextField::Description => entry.1 = Some(translation.value.clone()),
            _ => {
                return Err(OpenID4VCIError::RuntimeError(
                    "invalid localized text field".to_string(),
                ));
            }
        }
    }

    let displays = by_lang
        .into_iter()
        .map(|(lang, (name, description))| CredentialDisplay {
            name: name.unwrap_or_else(|| credential_schema.name.clone()),
            locale: Some(lang),
            description,
            ..visual_base.clone()
        })
        .collect();

    Ok(displays)
}

async fn create_claim_display_dtos(
    claim: &ClaimSchema,
) -> Result<Vec<ClaimDisplay>, OpenID4VCIError> {
    let translations = claim
        .translations
        .as_ref()
        .await
        .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?;

    if translations.is_empty() {
        return Err(OpenID4VCIError::RuntimeError(
            "Claim schema should have at least one translation".to_string(),
        ));
    }

    Ok(translations
        .iter()
        .filter(|t| t.field == LocalizedTextField::Name)
        .map(|t| ClaimDisplay {
            name: Some(t.value.clone()),
            locale: Some(t.lang.clone()),
        })
        .collect())
}

fn jsonld_configuration(
    oidc_format: &str,
    credential_metadata: CredentialMetadata,
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: Option<IndexMap<String, ProofTypeSupported>>,
    disclosure_policy: Option<DisclosurePolicy>,
) -> CredentialConfiguration {
    CredentialConfiguration {
        format: oidc_format.into(),
        credential_definition: None, //TODO! Fill for json_ld
        credential_metadata: Some(credential_metadata),
        cryptographic_binding_methods_supported: Some(cryptographic_binding_methods_supported),
        proof_types_supported,
        disclosure_policy,
        ..Default::default()
    }
}

fn jwt_configuration(
    oidc_format: &str,
    credential_metadata: CredentialMetadata,
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: Option<IndexMap<String, ProofTypeSupported>>,
    credential_signing_alg_values_supported: Vec<String>,
    disclosure_policy: Option<DisclosurePolicy>,
) -> CredentialConfiguration {
    CredentialConfiguration {
        format: oidc_format.into(),
        credential_definition: None, //TODO! Fill with W3C types
        cryptographic_binding_methods_supported: Some(cryptographic_binding_methods_supported),
        credential_metadata: Some(credential_metadata),
        proof_types_supported,
        credential_signing_alg_values_supported: Some(
            credential_signing_alg_values_supported
                .into_iter()
                .map(SigningAlgValue::String)
                .collect(),
        ),
        disclosure_policy,
        ..Default::default()
    }
}

fn sdjwt_configuration(
    oidc_format: &str,
    credential_metadata: CredentialMetadata,
    vct: &str,
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: Option<IndexMap<String, ProofTypeSupported>>,
    credential_signing_alg_values_supported: Vec<String>,
    disclosure_policy: Option<DisclosurePolicy>,
) -> CredentialConfiguration {
    CredentialConfiguration {
        format: oidc_format.into(),
        credential_metadata: Some(credential_metadata),
        cryptographic_binding_methods_supported: Some(cryptographic_binding_methods_supported),
        vct: Some(vct.to_string()),
        scope: Some(vct.to_string()),
        proof_types_supported,
        credential_signing_alg_values_supported: Some(
            credential_signing_alg_values_supported
                .into_iter()
                .map(SigningAlgValue::String)
                .collect(),
        ),
        disclosure_policy,
        ..Default::default()
    }
}

fn mdoc_configuration(
    doctype: String,
    credential_metadata: CredentialMetadata,
    proof_types_supported: Option<IndexMap<String, ProofTypeSupported>>,
    disclosure_policy: Option<DisclosurePolicy>,
) -> CredentialConfiguration {
    CredentialConfiguration {
        format: "mso_mdoc".to_string(),
        doctype: Some(doctype.to_string()),
        credential_metadata: Some(credential_metadata),
        cryptographic_binding_methods_supported: Some(vec!["cose_key".to_string()]),
        proof_types_supported,
        scope: Some(doctype),
        disclosure_policy,
        ..Default::default()
    }
}

pub(crate) fn get_protocol_base_url(base_url: &str, swiyu_mode: bool) -> String {
    let version = if swiyu_mode {
        "final-1.0-swiyu"
    } else {
        "final-1.0"
    };
    format!("{base_url}/ssi/openid4vci/{version}")
}

pub(crate) fn create_credential_offer(
    protocol_base_url: &str,
    protocol_id: &str,
    pre_authorized_code: &str,
    credential_schema: &CredentialSchema,
    offered_formats: &[CredentialSchemaFormat],
    identifier_id: IdentifierId,
) -> Result<CredentialOffer, OpenIDIssuanceError> {
    if offered_formats.is_empty() {
        return Err(OpenIDIssuanceError::ValidationError(format!(
            "Credential schema {} has no offered credential schema format",
            credential_schema.id
        )));
    }

    let tx_code = credential_schema
        .transaction_code
        .as_ref()
        .map(|code| TxCode {
            input_mode: code.r#type.into(),
            length: Some(code.length as _),
            description: code.description.to_owned(),
        });

    let credential_issuer = format!(
        "{protocol_base_url}/{protocol_id}/{identifier_id}/{}",
        credential_schema.id
    );

    Ok(CredentialOffer {
        credential_issuer,
        credential_configuration_ids: offered_formats
            .iter()
            .map(|format| format.ecosystem_schema_id.to_owned())
            .collect(),
        grants: Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
            pre_authorized_code: pre_authorized_code.to_owned(),
            tx_code,
            authorization_server: None,
        }),
    })
}

pub(crate) fn oidc_issuer_create_token(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
    credentials: &[Credential],
    interaction: &Interaction,
    request: &TokenRequest,
    pre_authorization_expires_in: Duration,
    access_token_expires_in: Duration,
    refresh_token_expires_in: Duration,
) -> Result<TokenResponse, OpenIDIssuanceError> {
    throw_if_token_request_invalid(request)?;
    throw_if_tx_code_invalid(interaction_data.transaction_code.as_ref(), request)?;

    let generate_new_token = || {
        SecretString::from(format!(
            "{}.{}",
            interaction.id,
            utilities::generate_alphanumeric(32)
        ))
    };

    let now = crate::clock::now_utc();
    Ok(match request {
        TokenRequest::PreAuthorizedCode { .. } => {
            throw_if_interaction_created_date(pre_authorization_expires_in, interaction)?;
            throw_if_interaction_pre_authorized_code_used(interaction_data)?;

            credentials.iter().try_for_each(|credential| {
                throw_if_credential_state_not_eq(credential, CredentialStateEnum::Pending)
            })?;

            TokenResponse {
                access_token: generate_new_token(),
                token_type: TokenType::Bearer,
                expires_in: ExpiresIn((now + access_token_expires_in).unix_timestamp()),
                refresh_token: None,
                refresh_token_expires_in: None,
            }
        }

        TokenRequest::RefreshToken { refresh_token } => {
            validate_refresh_token(interaction_data, refresh_token)?;
            // we update both the access token and the refresh token
            TokenResponse {
                access_token: generate_new_token(),
                token_type: TokenType::Bearer,
                expires_in: ExpiresIn((now + access_token_expires_in).unix_timestamp()),
                refresh_token: Some(generate_new_token()),
                refresh_token_expires_in: Some(ExpiresIn(
                    (now + refresh_token_expires_in).unix_timestamp(),
                )),
            }
        }
        TokenRequest::AuthorizationCode { .. } => {
            return Err(OpenIDIssuanceError::OpenID4VCI(
                OpenID4VCIError::InvalidGrant,
            ));
        }
    })
}

pub(crate) fn parse_refresh_token(token: &str) -> Result<InteractionId, OpenID4VCIError> {
    parse_access_token(token)
}

pub(crate) fn parse_access_token(access_token: &str) -> Result<InteractionId, OpenID4VCIError> {
    let mut splitted_token = access_token.split('.');
    if splitted_token.to_owned().count() != 2 {
        return Err(OpenID4VCIError::InvalidToken);
    }

    Ok(
        Uuid::from_str(splitted_token.next().ok_or(OpenID4VCIError::InvalidToken)?)
            .map_err(|_| OpenID4VCIError::RuntimeError("Could not parse UUID".to_owned()))?
            .into(),
    )
}

#[cfg(test)]
mod metadata_path_tests {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::service::test_utilities::dummy_claim_schema;

    fn claim(key: &str, array: bool) -> ClaimSchema {
        ClaimSchema {
            key: key.to_owned(),
            array,
            ..dummy_claim_schema()
        }
    }

    fn mapping(
        claim_schema_id: ClaimSchemaId,
        technical_key: &str,
        namespace: Option<&str>,
    ) -> CredentialSchemaFormatClaimSchema {
        let now = crate::clock::now_utc();
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            credential_schema_format_id: Uuid::new_v4().into(),
            claim_schema_id,
            technical_key: technical_key.to_owned(),
            namespace: namespace.map(str::to_owned),
        }
    }

    #[test]
    fn metadata_path_uses_array_ancestors_and_keeps_numeric_property_names() {
        let education = claim("education", true);
        let degrees = claim("education/degrees", true);
        let numeric_property = claim("education/degrees/0", false);
        let mappings = [
            mapping(education.id, "edu", Some("ns")),
            mapping(degrees.id, "edu/records", Some("ns")),
            mapping(numeric_property.id, "edu/records/0", Some("ns")),
        ];
        let schemas = [numeric_property, degrees, education];
        let mappings_by_id = mappings
            .iter()
            .map(|mapping| (mapping.claim_schema_id, mapping))
            .collect();

        let paths = claim_metadata_paths(&schemas, &mappings_by_id).unwrap();
        assert_eq!(
            serde_json::to_value(&paths[&schemas[0].id]).unwrap(),
            json!(["ns", "edu", null, "records", null, "0"])
        );
        assert_eq!(
            serde_json::to_value(&paths[&schemas[1].id]).unwrap(),
            json!(["ns", "edu", null, "records"])
        );
        assert_eq!(
            serde_json::to_value(&paths[&schemas[2].id]).unwrap(),
            json!(["ns", "edu"])
        );
    }

    #[test]
    fn metadata_path_keeps_parent_for_child_after_lexically_earlier_sibling() {
        let parent = claim("a", true);
        let sibling = claim("a-child", false);
        let child = claim("a/child", false);
        let mappings = [
            mapping(parent.id, "a", None),
            mapping(sibling.id, "a-child", None),
            mapping(child.id, "a/child", None),
        ];
        let mappings_by_id = mappings
            .iter()
            .map(|mapping| (mapping.claim_schema_id, mapping))
            .collect();

        let paths =
            claim_metadata_paths(&[child.clone(), sibling, parent], &mappings_by_id).unwrap();
        assert_eq!(
            serde_json::to_value(&paths[&child.id]).unwrap(),
            json!(["a", null, "child"])
        );
    }

    #[test]
    fn metadata_path_without_array_ancestors_remains_property_only() {
        let numeric_property = claim("address/0", false);
        let mapping = mapping(numeric_property.id, "address/0", None);

        let paths = claim_metadata_paths(
            std::slice::from_ref(&numeric_property),
            &HashMap::from([(numeric_property.id, &mapping)]),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&paths[&numeric_property.id]).unwrap(),
            json!(["address", "0"])
        );
    }
}
