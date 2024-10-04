use std::collections::HashMap;

use anyhow::{anyhow, Context};
use itertools::Itertools;
use one_dto_mapper::convert_inner;
use regex::Regex;
use serde::{Deserialize, Deserializer};
use shared_types::{ClaimSchemaId, CredentialId, CredentialSchemaId, DidValue, KeyId, ProofId};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::error::OpenID4VCIError;
use super::model::{
    CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesRequestDTO,
    CredentialSchemaCodeTypeEnum, CredentialSchemaLayoutPropertiesRequestDTO,
    CredentialSchemaLogoPropertiesRequestDTO, DidListItemResponseDTO, OpenID4VCIInteractionDataDTO,
    OpenID4VCITokenResponseDTO, OpenID4VPInteractionContent, OpenID4VPPresentationDefinition,
    OpenID4VPPresentationDefinitionConstraint, OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor, ProvedCredential, Timestamp,
};
use super::service::create_open_id_for_vp_client_metadata;
use crate::common_mapper::{remove_first_nesting_layer, NESTED_CLAIM_MARKER};
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{
    BackgroundProperties, CodeProperties, CodeTypeEnum, CredentialSchema, CredentialSchemaClaim,
    LayoutProperties, LogoProperties,
};
use crate::model::did::Did;
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofState, ProofStateEnum};
use crate::model::proof_schema::ProofInputClaimSchema;
use crate::provider::credential_formatter::model::ExtractPresentationCtx;
use crate::provider::exchange_protocol::dto::{
    CredentialGroup, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use crate::provider::exchange_protocol::mapper::{
    create_presentation_definition_field, credential_model_to_credential_dto,
};
use crate::provider::exchange_protocol::openid4vc::error::OpenID4VCError;
use crate::provider::exchange_protocol::openid4vc::model::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaDetailResponseDTO, NestedPresentationSubmissionDescriptorDTO,
    OpenID4VCICredentialOfferClaim, OpenID4VCICredentialOfferClaimValue,
    OpenID4VCICredentialOfferCredentialDTO, OpenID4VCICredentialValueDetails,
    OpenID4VCIIssuerMetadataMdocClaimsValuesDTO, OpenID4VPFormat,
    OpenID4VPPresentationDefinitionInputDescriptorFormat, PresentationSubmissionDescriptorDTO,
    PresentationSubmissionMappingDTO, PresentedCredential,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::IdentityRequest;
use crate::provider::exchange_protocol::openid4vc::{
    ExchangeProtocolError, FormatMapper, TypeToDescriptorMapper,
};
use crate::service::credential::dto::DetailCredentialSchemaResponseDTO;
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::util::oidc::map_core_to_oidc_format;

pub(super) fn presentation_definition_from_interaction_data(
    proof_id: ProofId,
    credentials: Vec<Credential>,
    credential_groups: Vec<CredentialGroup>,
    config: &CoreConfig,
) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
    Ok(PresentationDefinitionResponseDTO {
        request_groups: vec![PresentationDefinitionRequestGroupResponseDTO {
            id: proof_id.to_string(),
            name: None,
            purpose: None,
            rule: PresentationDefinitionRuleDTO {
                r#type: PresentationDefinitionRuleTypeEnum::All,
                min: None,
                max: None,
                count: None,
            },
            requested_credentials: credential_groups
                .into_iter()
                .map(|group| {
                    Ok(PresentationDefinitionRequestedCredentialResponseDTO {
                        id: group.id,
                        name: group.name,
                        purpose: group.purpose,
                        fields: convert_inner(
                            group
                                .claims
                                .into_iter()
                                .map(|field| {
                                    create_presentation_definition_field(
                                        field,
                                        &convert_inner(group.applicable_credentials.clone()),
                                    )
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                        ),
                        applicable_credentials: group
                            .applicable_credentials
                            .into_iter()
                            .map(|credential| credential.id.to_string())
                            .collect(),
                        validity_credential_nbf: group.validity_credential_nbf,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        }],
        credentials: credential_model_to_credential_dto(
            convert_inner(credentials),
            config,
            // organisation,
        )?,
    })
}

pub(crate) fn get_claim_name_by_json_path(
    path: &[String],
) -> Result<String, ExchangeProtocolError> {
    const VC_CREDENTIAL_PREFIX: &str = "$.vc.credentialSubject.";

    match path.first() {
        Some(vc) if vc.starts_with(VC_CREDENTIAL_PREFIX) => {
            Ok(vc[VC_CREDENTIAL_PREFIX.len()..].to_owned())
        }

        Some(subscript_path) if subscript_path.starts_with("$['") => {
            let path: Vec<&str> = subscript_path
                .split(['$', '[', ']', '\''])
                .filter(|s| !s.is_empty())
                .collect();

            let json_pointer_path = path.join("/");

            if json_pointer_path.is_empty() {
                return Err(ExchangeProtocolError::Failed(format!(
                    "Invalid json path: {subscript_path}"
                )));
            }

            Ok(json_pointer_path)
        }
        Some(other) => Err(ExchangeProtocolError::Failed(format!(
            "Invalid json path: {other}"
        ))),

        None => Err(ExchangeProtocolError::Failed("No path".to_string())),
    }
}

// TODO: This method needs to be refactored as soon as we have a new config value access and remove the static values from this method
pub(crate) fn create_open_id_for_vp_formats() -> HashMap<String, OpenID4VPFormat> {
    let mut formats = HashMap::new();
    let algorithms = OpenID4VPFormat {
        alg: vec!["EdDSA".to_owned(), "ES256".to_owned()],
    };
    formats.insert("jwt_vp_json".to_owned(), algorithms.clone());
    formats.insert("jwt_vc_json".to_owned(), algorithms.clone());
    formats.insert("ldp_vp".to_owned(), algorithms.clone());
    formats.insert(
        "ldp_vc".to_owned(),
        OpenID4VPFormat {
            alg: vec![
                "EdDSA".to_owned(),
                "ES256".to_owned(),
                "BLS12-381G1-SHA256".to_owned(),
            ],
        },
    );
    formats.insert("vc+sd-jwt".to_owned(), algorithms.clone());
    formats.insert("mso_mdoc".to_owned(), algorithms);
    formats
}

pub(crate) fn credentials_format_mdoc(
    credential_schema: &CredentialSchema,
    claims: &[Claim],
    config: &CoreConfig,
) -> Result<Vec<OpenID4VCICredentialOfferCredentialDTO>, OpenID4VCError> {
    let claims = prepare_claims(credential_schema, claims, config)?;

    Ok(vec![OpenID4VCICredentialOfferCredentialDTO {
        wallet_storage_type: credential_schema.wallet_storage_type.clone(),
        format: map_core_to_oidc_format(&credential_schema.format)
            .map_err(|e| OpenID4VCError::Other(e.to_string()))?,
        credential_definition: None,
        doctype: Some(credential_schema.schema_id.to_owned()),
        claims: Some(claims),
    }])
}

pub(super) fn prepare_claims(
    credential_schema: &CredentialSchema,
    claims: &[Claim],
    config: &CoreConfig,
) -> Result<HashMap<String, OpenID4VCICredentialOfferClaim>, OpenID4VCError> {
    let object_types = config
        .datatype
        .iter()
        .filter_map(|(name, fields)| {
            if fields.r#type == DatatypeType::Object {
                Some(name)
            } else {
                None
            }
        })
        .collect::<Vec<&str>>();

    // Copy value claims to result
    let mut result = claims
        .iter()
        .map(|claim| {
            let schema = claim
                .schema
                .as_ref()
                .ok_or(OpenID4VCError::Other("claim_schema is None".to_string()))?;
            Ok((
                schema.key.to_owned(),
                OpenID4VCICredentialOfferClaim {
                    value: OpenID4VCICredentialOfferClaimValue::String(claim.value.to_owned()),
                    value_type: schema.data_type.to_owned(),
                },
            ))
        })
        .collect::<Result<HashMap<String, OpenID4VCICredentialOfferClaim>, OpenID4VCError>>()?;

    // Copy object claims from credential schema
    let object_claims = credential_schema
        .claim_schemas
        .as_ref()
        .ok_or(OpenID4VCError::Other("claim_schemas is None".to_string()))?
        .iter()
        .filter_map(|schema| {
            let is_object = object_types.contains(&schema.schema.data_type.as_str());
            if is_object {
                Some(Ok((
                    schema.schema.key.to_owned(),
                    OpenID4VCICredentialOfferClaim {
                        value: OpenID4VCICredentialOfferClaimValue::Nested(Default::default()),
                        value_type: schema.schema.data_type.to_owned(),
                    },
                )))
            } else {
                None
            }
        })
        .collect::<Result<HashMap<String, OpenID4VCICredentialOfferClaim>, OpenID4VCError>>()?;
    result.extend(object_claims);

    nest_claims(result)
}

fn nest_claims(
    claims: HashMap<String, OpenID4VCICredentialOfferClaim>,
) -> Result<HashMap<String, OpenID4VCICredentialOfferClaim>, OpenID4VCError> {
    // Copy unnested claims
    let mut result = claims
        .iter()
        .filter_map(|(key, value)| {
            if key.find(NESTED_CLAIM_MARKER).is_none() {
                Some((key.to_owned(), value.to_owned()))
            } else {
                None
            }
        })
        .collect::<HashMap<String, OpenID4VCICredentialOfferClaim>>();

    // Copy nested claims into parent claims
    claims.into_iter().try_for_each(|(key, value)| {
        if let Some(index) = key.find(NESTED_CLAIM_MARKER) {
            let prefix = &key[0..index];
            let entry = result.get_mut(prefix).ok_or(OpenID4VCError::Other(
                "failed to find parent claim".to_string(),
            ))?;
            match &mut entry.value {
                OpenID4VCICredentialOfferClaimValue::Nested(map) => {
                    map.insert(remove_first_nesting_layer(&key), value);
                }
                OpenID4VCICredentialOfferClaimValue::String(_) => {
                    return Err(OpenID4VCError::Other(
                        "found parent OBJECT claim of String value type".to_string(),
                    ));
                }
            }
        }

        Ok::<(), OpenID4VCError>(())
    })?;

    // Repeat for each nested claim
    result
        .into_iter()
        .map(|(key, value)| match value.value {
            OpenID4VCICredentialOfferClaimValue::Nested(map) => Ok((
                key,
                OpenID4VCICredentialOfferClaim {
                    value: OpenID4VCICredentialOfferClaimValue::Nested(nest_claims(map)?),
                    value_type: value.value_type,
                },
            )),
            OpenID4VCICredentialOfferClaimValue::String(_) => Ok((key, value)),
        })
        .collect::<Result<HashMap<_, _>, _>>()
}

pub(super) fn create_claims_from_credential_definition(
    credential_id: CredentialId,
    claim_keys: &HashMap<String, OpenID4VCICredentialValueDetails>,
) -> Result<(Vec<CredentialSchemaClaim>, Vec<Claim>), ExchangeProtocolError> {
    let now = OffsetDateTime::now_utc();
    let mut claim_schemas: Vec<CredentialSchemaClaim> = vec![];
    let mut claims: Vec<Claim> = vec![];
    let mut object_claim_schemas: Vec<&str> = vec![];

    for (key, value_details) in claim_keys {
        let new_schema_claim = CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: key.to_string(),
                data_type: value_details.value_type.to_string(),
                created_date: now,
                last_modified: now,
                array: false,
            },
            required: false,
        };

        let claim = Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: value_details.value.to_string(),
            path: new_schema_claim.schema.key.to_owned(),
            schema: Some(new_schema_claim.schema.to_owned()),
        };

        claim_schemas.push(new_schema_claim);
        claims.push(claim);

        if key.contains(NESTED_CLAIM_MARKER) {
            for parent_claim in get_parent_claim_paths(key) {
                if !object_claim_schemas.contains(&parent_claim) {
                    object_claim_schemas.push(parent_claim);
                }
            }
        }
    }

    for object_claim in object_claim_schemas {
        claim_schemas.push(CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: object_claim.into(),
                data_type: DatatypeType::Object.to_string(),
                created_date: now,
                last_modified: now,
                array: false,
            },
            required: false,
        })
    }

    Ok((claim_schemas, claims))
}

pub(crate) fn get_parent_claim_paths(path: &str) -> Vec<&str> {
    path.char_indices()
        .filter_map(|(index, value)| {
            if value == NESTED_CLAIM_MARKER {
                Some(index)
            } else {
                None
            }
        })
        .map(|index| &path[0..index])
        .collect::<Vec<&str>>()
}

pub(crate) fn parse_procivis_schema_claim(
    claim: CredentialClaimSchemaDTO,
) -> CredentialClaimSchemaRequestDTO {
    CredentialClaimSchemaRequestDTO {
        key: claim.key,
        datatype: claim.datatype,
        required: claim.required,
        array: Some(claim.array),
        claims: claim
            .claims
            .into_iter()
            .map(parse_procivis_schema_claim)
            .collect(),
    }
}

fn parse_mdoc_schema_elements(
    values: HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    values
        .into_iter()
        .map(|(key, claim)| {
            let mut claims = parse_mdoc_schema_elements(claim.value);

            if let Some(order) = claim.order {
                claims.sort_by_key(|claim| {
                    order
                        .iter()
                        .position(|item| item == &claim.key)
                        .unwrap_or_default()
                });
            }

            CredentialClaimSchemaRequestDTO {
                key,
                datatype: claim.value_type,
                required: claim.mandatory.unwrap_or(false),
                array: Some(false), // TODO: Needs to be covered with ONE-2261
                claims,
            }
        })
        .collect()
}

pub(crate) fn parse_mdoc_schema_claims(
    values: HashMap<String, HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>>,
    element_order: Option<Vec<String>>,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    let mut claims_by_namespace: Vec<_> = values
        .into_iter()
        .map(|(namespace, elements)| CredentialClaimSchemaRequestDTO {
            key: namespace,
            datatype: "OBJECT".to_string(),
            required: true,
            array: Some(false), // TODO: Needs to be covered with ONE-2261
            claims: parse_mdoc_schema_elements(elements),
        })
        .collect();

    if let Some(order) = element_order {
        claims_by_namespace.iter_mut().for_each(|namespace| {
            namespace.claims.sort_by_key(|claim| {
                order
                    .iter()
                    .position(|element| element == &format!("{}~{}", namespace.key, claim.key))
                    .unwrap_or_default()
            })
        });

        claims_by_namespace.sort_by_key(|claim| {
            order
                .iter()
                .position(|element| element.starts_with(&format!("{}~", claim.key)))
                .unwrap_or_default()
        });
    }

    claims_by_namespace
}

fn from_jwt_request_claim_schema(
    now: OffsetDateTime,
    id: ClaimSchemaId,
    key: String,
    datatype: String,
    required: bool,
    array: Option<bool>,
) -> CredentialSchemaClaim {
    CredentialSchemaClaim {
        schema: ClaimSchema {
            id,
            key,
            data_type: datatype,
            created_date: now,
            last_modified: now,
            array: array.unwrap_or(false),
        },
        required,
    }
}

pub(crate) async fn fetch_procivis_schema(
    schema_id: &str,
) -> Result<CredentialSchemaDetailResponseDTO, reqwest::Error> {
    reqwest::get(schema_id)
        .await?
        .error_for_status()?
        .json()
        .await
}

pub fn from_create_request(
    request: CreateCredentialSchemaRequestDTO,
    organisation: Organisation,
    core_base_url: &str,
    format_type: &str,
    schema_type: Option<String>,
) -> Result<CredentialSchema, ExchangeProtocolError> {
    from_create_request_with_id(
        Uuid::new_v4().into(),
        request,
        organisation,
        core_base_url,
        format_type,
        schema_type,
    )
}

pub fn from_create_request_with_id(
    id: CredentialSchemaId,
    request: CreateCredentialSchemaRequestDTO,
    organisation: Organisation,
    core_base_url: &str,
    format_type: &str,
    schema_type: Option<String>,
) -> Result<CredentialSchema, ExchangeProtocolError> {
    if request.claims.is_empty() {
        return Err(ExchangeProtocolError::Failed(
            "Claim schemas cannot be empty".to_string(),
        ));
    }

    let now = OffsetDateTime::now_utc();

    let claim_schemas = unnest_claim_schemas(request.claims);

    let url = format!("{core_base_url}/ssi/schema/v1/{id}");
    let schema_id = request.schema_id.unwrap_or(url.clone());
    let schema_type = schema_type.unwrap_or(match format_type {
        "MDOC" => "mdoc".to_owned(),
        _ => "ProcivisOneSchema2024".to_owned(),
    });

    Ok(CredentialSchema {
        id,
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: request.name,
        format: request.format,
        wallet_storage_type: request.wallet_storage_type,
        revocation_method: request.revocation_method,
        claim_schemas: Some(
            claim_schemas
                .into_iter()
                .map(|claim_schema| {
                    from_jwt_request_claim_schema(
                        now,
                        Uuid::new_v4().into(),
                        claim_schema.key,
                        claim_schema.datatype,
                        claim_schema.required,
                        claim_schema.array,
                    )
                })
                .collect(),
        ),
        layout_type: request.layout_type,
        layout_properties: request.layout_properties.map(Into::into),
        schema_type: schema_type.into(),
        imported_source_url: url,
        schema_id,
        organisation: Some(organisation),
        allow_suspension: false,
    })
}

pub(crate) fn unnest_claim_schemas(
    claim_schemas: Vec<CredentialClaimSchemaRequestDTO>,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    unnest_claim_schemas_inner(claim_schemas, "".to_string())
}

fn unnest_claim_schemas_inner(
    claim_schemas: Vec<CredentialClaimSchemaRequestDTO>,
    prefix: String,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    let mut result = vec![];

    for claim_schema in claim_schemas {
        let key = format!("{prefix}{}", claim_schema.key);

        let nested =
            unnest_claim_schemas_inner(claim_schema.claims, format!("{key}{NESTED_CLAIM_MARKER}"));

        result.push(CredentialClaimSchemaRequestDTO {
            key,
            claims: vec![],
            ..claim_schema
        });

        result.extend(nested);
    }

    result
}

pub fn create_format_map(
    format_type: &str,
) -> Result<
    HashMap<String, OpenID4VPPresentationDefinitionInputDescriptorFormat>,
    ExchangeProtocolError,
> {
    match format_type {
        "JWT" | "SDJWT" | "MDOC" => {
            let key = map_core_to_oidc_format(format_type)
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
            Ok(HashMap::from([(
                key,
                OpenID4VPPresentationDefinitionInputDescriptorFormat {
                    alg: vec!["EdDSA".to_string(), "ES256".to_string()],
                    proof_type: vec![],
                },
            )]))
        }
        "PHYSICAL_CARD" => {
            unimplemented!()
        }
        "JSON_LD_CLASSIC" | "JSON_LD_BBSPLUS" => Ok(HashMap::from([(
            "ldp_vc".to_string(),
            OpenID4VPPresentationDefinitionInputDescriptorFormat {
                alg: vec![],
                proof_type: vec!["DataIntegrityProof".to_string()],
            },
        )])),
        _ => unimplemented!(),
    }
}

pub fn map_offered_claims_to_credential_schema(
    credential_schema: &CredentialSchema,
    credential_id: CredentialId,
    claim_keys: &HashMap<String, OpenID4VCICredentialValueDetails>,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    let claim_schemas =
        credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "Missing claim schemas for existing credential schema".to_string(),
            ))?;

    let now = OffsetDateTime::now_utc();
    let mut claims = vec![];

    let claim_schemas = adapt_required_state_based_on_claim_presence(claim_schemas, claim_keys)?;

    for claim_schema in claim_schemas
        .iter()
        .filter(|claim| claim.schema.data_type != "OBJECT")
    {
        let matcher = claim_schema_key_to_claim_matcher(&claim_schema.schema.key, &claim_schemas)?;

        let credential_value_details = claim_keys
            .iter()
            .filter(|(claim_key, _)| matcher.is_match(claim_key))
            .collect::<Vec<(_, _)>>();

        if credential_value_details.is_empty() && claim_schema.required {
            return Err(ExchangeProtocolError::Failed(format!(
                "Validation Error. Claim key {} missing",
                &claim_schema.schema.key
            )));
        }

        for (key, value_details) in credential_value_details {
            let claim = Claim {
                id: Uuid::new_v4(),
                credential_id,
                created_date: now,
                last_modified: now,
                value: value_details.value.to_owned(),
                path: key.to_string(),
                schema: Some(claim_schema.schema.to_owned()),
            };

            claims.push(claim);
        }
    }

    Ok(claims)
}

fn adapt_required_state_based_on_claim_presence(
    claim_schemas: &[CredentialSchemaClaim],
    claims: &HashMap<String, OpenID4VCICredentialValueDetails>,
) -> Result<Vec<CredentialSchemaClaim>, ExchangeProtocolError> {
    let claim_schema_matchers = claim_schemas
        .iter()
        .map(|schema| {
            Ok((
                schema.schema.key.to_owned(),
                claim_schema_key_to_claim_matcher(&schema.schema.key, claim_schemas)?,
            ))
        })
        .collect::<Result<HashMap<_, _>, ExchangeProtocolError>>()?;

    let claims_with_names = claims
        .iter()
        .map(|(key, claim)| {
            let matching_claim_schema = claim_schemas
                .iter()
                .find(|claim_schema| {
                    let matcher = claim_schema_matchers.get(&claim_schema.schema.key);
                    matcher.is_some_and(|matcher| matcher.is_match(key))
                })
                .ok_or(ExchangeProtocolError::Failed(
                    "Credential schema missing claims".to_string(),
                ))?;
            Ok((claim, matching_claim_schema.schema.key.to_owned()))
        })
        .collect::<Result<Vec<(&OpenID4VCICredentialValueDetails, String)>, ExchangeProtocolError>>(
        )?;

    let mut result = claim_schemas.to_vec();
    claim_schemas.iter().try_for_each(|claim_schema| {
        let prefix = format!("{}/", claim_schema.schema.key);

        let is_parent_schema_of_provided_claim = claims_with_names
            .iter()
            .any(|(_, claim_name)| claim_name.starts_with(&prefix));

        let is_object = !claim_schema.schema.array && claim_schema.schema.data_type == "OBJECT";

        let should_make_all_child_claims_non_required =
            !is_parent_schema_of_provided_claim && is_object && !claim_schema.required;

        if should_make_all_child_claims_non_required {
            result.iter_mut().for_each(|result_schema| {
                if result_schema.schema.key.starts_with(&prefix) {
                    result_schema.required = false;
                }
            });
        }

        Ok::<(), ExchangeProtocolError>(())
    })?;

    Ok(result)
}

/// Construct a regex matcher that will match all claim keys that are based on the specified claim schema
///
/// Params:
/// * `claim_schema_key` key of the specific claim schema to construct the regex for
/// * `all_claim_schemas` all claim schemas inside the credential schema
fn claim_schema_key_to_claim_matcher(
    claim_schema_key: &str,
    all_claim_schemas: &[CredentialSchemaClaim],
) -> Result<Regex, ExchangeProtocolError> {
    // collect all array claim schema keys related to the target
    let related_array_claim_keys = all_claim_schemas
        .iter()
        .filter_map(|schema| {
            if schema.schema.array
                && (
                    // either itself
                    claim_schema_key == schema.schema.key
                    // or parent
                    || claim_schema_key.starts_with(&format!("{}/", schema.schema.key))
                )
            {
                Some(regex::escape(&schema.schema.key))
            } else {
                None
            }
        })
        // sorted from the deepest
        .sorted()
        .rev()
        .collect::<Vec<_>>();

    let mut pattern = regex::escape(claim_schema_key);
    for related_array_claim_key in related_array_claim_keys {
        pattern = format!(
            "{related_array_claim_key}/\\d+{}",
            pattern.split_at(related_array_claim_key.len()).1
        );
    }

    Regex::new(&format!("^{pattern}$")).map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn proof_from_handle_invitation(
    proof_id: &ProofId,
    protocol: &str,
    redirect_uri: Option<String>,
    verifier_did: Option<Did>,
    interaction: Interaction,
    now: OffsetDateTime,
    verifier_key: Option<Key>,
    transport: &str,
) -> Proof {
    Proof {
        id: proof_id.to_owned(),
        created_date: now,
        last_modified: now,
        issuance_date: now,
        exchange: protocol.to_owned(),
        redirect_uri,
        transport: transport.to_owned(),
        state: Some(vec![ProofState {
            created_date: now,
            last_modified: now,
            state: ProofStateEnum::Pending,
        }]),
        schema: None,
        claims: None,
        verifier_did,
        holder_did: None,
        interaction: Some(interaction),
        verifier_key,
    }
}

pub fn interaction_from_handle_invitation(
    host: Url,
    data: Option<Vec<u8>>,
    now: OffsetDateTime,
) -> Interaction {
    Interaction {
        id: Uuid::new_v4(),
        created_date: now,
        host: Some(host),
        data,
        last_modified: now,
    }
}

pub fn create_credential(
    credential_id: CredentialId,
    credential_schema: CredentialSchema,
    claims: Vec<Claim>,
    interaction: Interaction,
    redirect_uri: Option<String>,
) -> Credential {
    let now = OffsetDateTime::now_utc();

    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: "OPENID4VC".to_string(),
        redirect_uri,
        role: CredentialRole::Holder,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Pending,
            suspend_end_date: None,
        }]),
        claims: Some(claims),
        issuer_did: None,
        holder_did: None,
        schema: Some(credential_schema),
        key: None,
        interaction: Some(interaction),
        revocation_list: None,
    }
}

pub(crate) fn get_credential_offer_url(
    base_url: Option<String>,
    credential: &Credential,
) -> Result<String, ExchangeProtocolError> {
    let credential_schema = credential
        .schema
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "Missing credential schema".to_owned(),
        ))?;
    let base_url = get_url(base_url)?;
    Ok(format!(
        "{base_url}/ssi/oidc-issuer/v1/{}/offer/{}",
        credential_schema.id, credential.id
    ))
}

fn get_url(base_url: Option<String>) -> Result<String, ExchangeProtocolError> {
    base_url.ok_or(ExchangeProtocolError::Failed("Missing base_url".to_owned()))
}

pub fn create_open_id_for_vp_presentation_definition(
    interaction_id: InteractionId,
    proof: &Proof,
    format_type_to_input_descriptor_format: TypeToDescriptorMapper,
    format_to_type_mapper: FormatMapper, // Credential schema format to format type mapper
) -> Result<OpenID4VPPresentationDefinition, ExchangeProtocolError> {
    let proof_schema = proof.schema.as_ref().ok_or(ExchangeProtocolError::Failed(
        "Proof schema not found".to_string(),
    ))?;
    // using vec to keep the original order of claims/credentials in the proof request
    let requested_credentials: Vec<(CredentialSchema, Option<Vec<ProofInputClaimSchema>>)> =
        match proof_schema.input_schemas.as_ref() {
            Some(proof_input) if !proof_input.is_empty() => proof_input
                .iter()
                .filter_map(|input| {
                    let credential_schema = input.credential_schema.as_ref()?;

                    let claims = input.claim_schemas.as_ref().map(|schemas| {
                        schemas
                            .iter()
                            .map(|claim_schema| ProofInputClaimSchema {
                                order: claim_schema.order,
                                required: claim_schema.required,
                                schema: claim_schema.schema.to_owned(),
                            })
                            .collect()
                    });

                    Some((credential_schema.to_owned(), claims))
                })
                .collect(),

            _ => {
                return Err(ExchangeProtocolError::Failed(
                    "Missing proof input schemas".to_owned(),
                ))
            }
        };

    Ok(OpenID4VPPresentationDefinition {
        id: interaction_id,
        input_descriptors: requested_credentials
            .into_iter()
            .enumerate()
            .map(|(index, (credential_schema, claim_schemas))| {
                let format_type = format_to_type_mapper(&credential_schema.format)?;
                create_open_id_for_vp_presentation_definition_input_descriptor(
                    index,
                    credential_schema,
                    claim_schemas.unwrap_or_default(),
                    &format_type,
                    format_type_to_input_descriptor_format.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub fn create_open_id_for_vp_presentation_definition_input_descriptor(
    index: usize,
    credential_schema: CredentialSchema,
    claim_schemas: Vec<ProofInputClaimSchema>,
    presentation_format_type: &str,
    format_to_type_mapper: TypeToDescriptorMapper,
) -> Result<OpenID4VPPresentationDefinitionInputDescriptor, ExchangeProtocolError> {
    let schema_id_field = OpenID4VPPresentationDefinitionConstraintField {
        id: None,
        name: None,
        purpose: None,
        path: vec!["$.credentialSchema.id".to_string()],
        optional: None,
        filter: Some(OpenID4VPPresentationDefinitionConstraintFieldFilter {
            r#type: "string".to_string(),
            r#const: credential_schema.schema_id,
        }),
        intent_to_retain: None,
    };

    let intent_to_retain = match presentation_format_type {
        "MDOC" => Some(true),
        _ => None,
    };

    let constraint_fields = claim_schemas
        .iter()
        .map(|claim| {
            Ok(OpenID4VPPresentationDefinitionConstraintField {
                id: Some(claim.schema.id),
                name: None,
                purpose: None,
                path: vec![format_path(&claim.schema.key, presentation_format_type)?],
                optional: Some(!claim.required),
                filter: None,
                intent_to_retain,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut fields = vec![schema_id_field];
    fields.extend(constraint_fields);

    Ok(OpenID4VPPresentationDefinitionInputDescriptor {
        id: format!("input_{index}"),
        name: Some(credential_schema.name),
        purpose: None,
        format: format_to_type_mapper(presentation_format_type)?,
        constraints: OpenID4VPPresentationDefinitionConstraint {
            fields,
            validity_credential_nbf: None,
        },
    })
}

fn format_path(claim_key: &str, format_type: &str) -> Result<String, ExchangeProtocolError> {
    match format_type {
        "MDOC" => match claim_key.split_once(NESTED_CLAIM_MARKER) {
            None => Ok(format!("$['{claim_key}']")),
            Some((namespace, key)) => Ok(format!("$['{namespace}']['{key}']")),
        },
        _ => Ok(format!("$.vc.credentialSubject.{}", claim_key)),
    }
}

pub fn create_presentation_submission(
    presentation_definition_id: Uuid,
    credential_presentations: Vec<PresentedCredential>,
    format: &str,
    format_map: HashMap<String, String>,
) -> Result<PresentationSubmissionMappingDTO, ExchangeProtocolError> {
    Ok(PresentationSubmissionMappingDTO {
        id: Uuid::new_v4().to_string(),
        definition_id: presentation_definition_id.to_string(),
        descriptor_map: credential_presentations
            .into_iter()
            .enumerate()
            .map(|(index, presented_credential)| {
                Ok(PresentationSubmissionDescriptorDTO {
                    id: presented_credential.request.id,
                    format: format.to_owned(),
                    path: "$".to_string(),
                    path_nested: Some(NestedPresentationSubmissionDescriptorDTO {
                        format: format_map
                            .get(&presented_credential.credential_schema.format)
                            .ok_or_else(|| {
                                ExchangeProtocolError::Failed("format not found".to_string())
                            })?
                            .to_owned(),
                        path: format!("$.vp.verifiableCredential[{index}]"),
                    }),
                })
            })
            .collect::<Result<_, _>>()?,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_open_id_for_vp_sharing_url_encoded(
    base_url: &str,
    client_id: String,
    response_uri: String,
    interaction_id: InteractionId,
    nonce: String,
    proof: &Proof,
    client_metadata_by_value: bool,
    presentation_definition_by_value: bool,
    key_id: KeyId,
    encryption_key_jwk: PublicKeyJwkDTO,
    vp_formats: HashMap<String, OpenID4VPFormat>,
    type_to_descriptor: TypeToDescriptorMapper,
    format_to_type_mapper: FormatMapper,
) -> Result<String, ExchangeProtocolError> {
    let client_metadata = serde_json::to_string(&create_open_id_for_vp_client_metadata(
        key_id,
        encryption_key_jwk,
        vp_formats,
    ))
    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
    let presentation_definition =
        serde_json::to_string(&create_open_id_for_vp_presentation_definition(
            interaction_id,
            proof,
            type_to_descriptor,
            format_to_type_mapper,
        )?)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let mut params: Vec<(&str, String)> = vec![
        ("response_type", "vp_token".to_string()),
        ("state", interaction_id.to_string()),
        ("nonce", nonce),
        ("client_id_scheme", "redirect_uri".to_string()),
        ("client_id", client_id),
        ("response_mode", "direct_post".to_string()),
        ("response_uri", response_uri),
    ];

    match client_metadata_by_value {
        true => params.push(("client_metadata", client_metadata)),
        false => params.push((
            "client_metadata_uri",
            format!(
                "{}/ssi/oidc-verifier/v1/{}/client-metadata",
                base_url, proof.id
            ),
        )),
    }

    match presentation_definition_by_value {
        true => params.push(("presentation_definition", presentation_definition)),
        false => params.push((
            "presentation_definition_uri",
            format!(
                "{}/ssi/oidc-verifier/v1/{}/presentation-definition",
                base_url, proof.id
            ),
        )),
    }

    let encoded_params = serde_urlencoded::to_string(params)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    Ok(encoded_params)
}

pub fn deserialize_with_serde_json<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: for<'a> Deserialize<'a>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value.as_str() {
        None => serde_json::from_value(value).map_err(serde::de::Error::custom),
        Some(buffer) => serde_json::from_str(buffer).map_err(serde::de::Error::custom),
    }
}

impl TryFrom<OpenID4VCIInteractionDataDTO> for OpenID4VCITokenResponseDTO {
    type Error = OpenID4VCIError;
    fn try_from(value: OpenID4VCIInteractionDataDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            access_token: value.access_token.to_string(),
            token_type: "bearer".to_string(),
            expires_in: Timestamp(
                value
                    .access_token_expires_at
                    .ok_or(OpenID4VCIError::RuntimeError(
                        "access_token_expires_at missing".to_string(),
                    ))?
                    .unix_timestamp(),
            ),
            refresh_token: value.refresh_token,
            refresh_token_expires_in: value
                .refresh_token_expires_at
                .map(|dt| Timestamp(dt.unix_timestamp())),
        })
    }
}

pub(super) fn parse_interaction_content(
    data: &[u8],
) -> Result<OpenID4VPInteractionContent, OpenID4VCError> {
    serde_json::from_slice(data).map_err(|e| OpenID4VCError::MappingError(e.to_string()))
}

pub(crate) fn vec_last_position_from_token_path(path: &str) -> Result<usize, OpenID4VCError> {
    // Find the position of '[' and ']'
    if let Some(open_bracket) = path.rfind('[') {
        if let Some(close_bracket) = path.rfind(']') {
            // Extract the substring between '[' and ']'
            let value = &path[open_bracket + 1..close_bracket];

            let parsed_value = value.parse().map_err(|_| {
                OpenID4VCError::MappingError("Could not parse vec position".to_string())
            })?;

            Ok(parsed_value)
        } else {
            Err(OpenID4VCError::MappingError(
                "Credential path is incorrect".to_string(),
            ))
        }
    } else {
        Ok(0)
    }
}

pub fn extract_presentation_ctx_from_interaction_content(
    content: OpenID4VPInteractionContent,
) -> ExtractPresentationCtx {
    ExtractPresentationCtx {
        nonce: Some(content.nonce),
        client_id: content.client_id,
        response_uri: content.response_uri,
        ..Default::default()
    }
}

pub fn extracted_credential_to_model(
    claim_schemas: &[CredentialSchemaClaim],
    credential_schema: CredentialSchema,
    claims: Vec<(serde_json::Value, ClaimSchema)>,
    issuer_did: &DidValue,
    holder_did: &DidValue,
) -> Result<ProvedCredential, OpenID4VCError> {
    let now = OffsetDateTime::now_utc();
    let credential_id = Uuid::new_v4().into();

    let mut model_claims = vec![];
    for (value, claim_schema) in claims {
        model_claims.extend(value_to_model_claims(
            credential_id,
            claim_schemas,
            &value,
            now,
            &claim_schema,
            &claim_schema.key,
        )?);
    }

    Ok(ProvedCredential {
        credential: Credential {
            id: credential_id,
            created_date: now,
            issuance_date: now,
            last_modified: now,
            deleted_at: None,
            credential: vec![],
            exchange: "OPENID4VC".to_string(),
            state: Some(vec![CredentialState {
                created_date: now,
                state: CredentialStateEnum::Accepted,
                suspend_end_date: None,
            }]),
            claims: Some(model_claims.to_owned()),
            issuer_did: None,
            holder_did: None,
            schema: Some(credential_schema),
            redirect_uri: None,
            key: None,
            role: CredentialRole::Verifier,
            interaction: None,
            revocation_list: None,
        },
        issuer_did_value: issuer_did.to_owned(),
        holder_did_value: holder_did.to_owned(),
    })
}

fn value_to_model_claims(
    credential_id: CredentialId,
    claim_schemas: &[CredentialSchemaClaim],
    json_value: &serde_json::Value,
    now: OffsetDateTime,
    claim_schema: &ClaimSchema,
    path: &str,
) -> Result<Vec<Claim>, OpenID4VCError> {
    let mut model_claims = vec![];

    match json_value {
        serde_json::Value::String(_)
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_) => {
            let value = match json_value {
                serde_json::Value::String(v) => v.to_owned(),
                serde_json::Value::Bool(v) => {
                    if *v {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    }
                }
                serde_json::Value::Number(v) => v.to_string(),
                _ => {
                    return Err(OpenID4VCError::MappingError(
                        "invalid value type".to_string(),
                    ));
                }
            };

            model_claims.push(Claim {
                id: Uuid::new_v4(),
                credential_id,
                created_date: now,
                last_modified: now,
                value,
                path: path.to_owned(),
                schema: Some(claim_schema.to_owned()),
            });
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                let this_name = &claim_schema.key;
                let child_schema_name = format!("{this_name}/{key}");
                let child_credential_schema_claim = claim_schemas
                    .iter()
                    .find(|claim_schema| claim_schema.schema.key == child_schema_name)
                    .ok_or(OpenID4VCError::MissingClaimSchemas)?;
                model_claims.extend(value_to_model_claims(
                    credential_id,
                    claim_schemas,
                    value,
                    now,
                    &child_credential_schema_claim.schema,
                    &format!("{path}/{key}"),
                )?);
            }
        }
        serde_json::Value::Array(array) => {
            for (index, value) in array.iter().enumerate() {
                let child_schema_path = format!("{path}/{index}");

                model_claims.extend(value_to_model_claims(
                    credential_id,
                    claim_schemas,
                    value,
                    now,
                    claim_schema,
                    &child_schema_path,
                )?);
            }
        }
        _ => {
            return Err(OpenID4VCError::MappingError(
                "value type is not supported".to_string(),
            ));
        }
    }

    Ok(model_claims)
}

impl From<CredentialSchemaBackgroundPropertiesRequestDTO> for BackgroundProperties {
    fn from(value: CredentialSchemaBackgroundPropertiesRequestDTO) -> Self {
        Self {
            color: value.color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaLogoPropertiesRequestDTO> for LogoProperties {
    fn from(value: CredentialSchemaLogoPropertiesRequestDTO) -> Self {
        Self {
            font_color: value.font_color,
            background_color: value.background_color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaCodePropertiesRequestDTO> for CodeProperties {
    fn from(value: CredentialSchemaCodePropertiesRequestDTO) -> Self {
        Self {
            attribute: value.attribute,
            r#type: value.r#type.into(),
        }
    }
}

impl From<CredentialSchemaCodeTypeEnum> for CodeTypeEnum {
    fn from(value: CredentialSchemaCodeTypeEnum) -> Self {
        match value {
            CredentialSchemaCodeTypeEnum::Barcode => Self::Barcode,
            CredentialSchemaCodeTypeEnum::Mrz => Self::Mrz,
            CredentialSchemaCodeTypeEnum::QrCode => Self::QrCode,
        }
    }
}

impl From<Did> for DidListItemResponseDTO {
    fn from(value: Did) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            did: value.did,
            did_type: value.did_type,
            did_method: value.did_method,
            deactivated: value.deactivated,
        }
    }
}

impl From<LayoutProperties> for CredentialSchemaLayoutPropertiesRequestDTO {
    fn from(value: LayoutProperties) -> Self {
        Self {
            background: value.background.map(|value| {
                CredentialSchemaBackgroundPropertiesRequestDTO {
                    color: value.color,
                    image: value.image,
                }
            }),
            logo: value
                .logo
                .map(|v| CredentialSchemaLogoPropertiesRequestDTO {
                    font_color: v.font_color,
                    background_color: v.background_color,
                    image: v.image,
                }),
            primary_attribute: value.primary_attribute,
            secondary_attribute: value.secondary_attribute,
            picture_attribute: value.picture_attribute,
            code: value
                .code
                .map(|v| CredentialSchemaCodePropertiesRequestDTO {
                    attribute: v.attribute,
                    r#type: match v.r#type {
                        CodeTypeEnum::Barcode => CredentialSchemaCodeTypeEnum::Barcode,
                        CodeTypeEnum::Mrz => CredentialSchemaCodeTypeEnum::Mrz,
                        CodeTypeEnum::QrCode => CredentialSchemaCodeTypeEnum::QrCode,
                    },
                }),
        }
    }
}

impl TryFrom<CredentialSchema> for DetailCredentialSchemaResponseDTO {
    type Error = ExchangeProtocolError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
        let organisation_id = match value.organisation {
            None => Err(ExchangeProtocolError::Failed(
                "Organisation has not been fetched".to_string(),
            )),
            Some(value) => Ok(value.id),
        }?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            deleted_at: value.deleted_at,
            last_modified: value.last_modified,
            imported_source_url: value.imported_source_url,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            wallet_storage_type: value.wallet_storage_type,
            organisation_id,
            schema_type: value.schema_type.into(),
            schema_id: value.schema_id,
            layout_type: value.layout_type.into(),
            layout_properties: value.layout_properties.map(Into::into),
            allow_suspension: value.allow_suspension,
        })
    }
}

impl From<CredentialSchemaClaim> for CredentialClaimSchemaDTO {
    fn from(value: CredentialSchemaClaim) -> Self {
        Self {
            id: value.schema.id,
            created_date: value.schema.created_date,
            last_modified: value.schema.last_modified,
            key: value.schema.key,
            datatype: value.schema.data_type,
            required: value.required,
            array: value.schema.array,
            claims: vec![],
        }
    }
}

pub fn parse_identity_request(data: Vec<u8>) -> anyhow::Result<IdentityRequest> {
    let arr: [u8; 44] = data
        .try_into()
        .map_err(|_| anyhow!("Failed to convert vec to [u8; 44]"))?;

    let (key, nonce) = arr.split_at(32);

    Ok(IdentityRequest {
        key: key
            .try_into()
            .context("Failed to parse key from identity request")?,
        nonce: nonce
            .try_into()
            .context("Failed to parse nonce from identity request")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_schema_key_to_claim_matcher() {
        // single non-array claim
        let matcher = claim_schema_key_to_claim_matcher(
            "key",
            &[CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "key".to_string(),
                    data_type: "irrelevant".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    array: false,
                },
                required: false,
            }],
        )
        .unwrap();
        assert!(matcher.is_match("key"));
        assert!(!matcher.is_match("key/0"));

        // single array claim
        let matcher = claim_schema_key_to_claim_matcher(
            "key",
            &[CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "key".to_string(),
                    data_type: "irrelevant".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    array: true,
                },
                required: false,
            }],
        )
        .unwrap();
        assert!(!matcher.is_match("key"));
        assert!(matcher.is_match("key/0"));
        assert!(matcher.is_match("key/11"));

        // nested claim, no arrays
        let matcher = claim_schema_key_to_claim_matcher(
            "root/nested",
            &[
                CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "root".to_string(),
                        data_type: "OBJECT".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        array: false,
                    },
                    required: true,
                },
                CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "root/nested".to_string(),
                        data_type: "irrelevant".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        array: false,
                    },
                    required: true,
                },
            ],
        )
        .unwrap();
        assert!(!matcher.is_match("root"));
        assert!(!matcher.is_match("nested"));
        assert!(matcher.is_match("root/nested"));
        assert!(!matcher.is_match("root/nested/0"));

        // nested claim, with arrays
        let matcher = claim_schema_key_to_claim_matcher(
            "root/nested",
            &[
                CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "root".to_string(),
                        data_type: "OBJECT".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        array: true,
                    },
                    required: true,
                },
                CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "root/nested".to_string(),
                        data_type: "irrelevant".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        array: true,
                    },
                    required: true,
                },
            ],
        )
        .unwrap();
        assert!(!matcher.is_match("root"));
        assert!(!matcher.is_match("nested"));
        assert!(!matcher.is_match("root/nested"));
        assert!(!matcher.is_match("root/nested/0"));
        assert!(!matcher.is_match("root/0/nested"));
        assert!(matcher.is_match("root/0/nested/0"));
        assert!(matcher.is_match("root/1/nested/10"));
    }
}
