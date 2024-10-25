use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Context};
use itertools::Itertools;
use one_dto_mapper::convert_inner;
use serde::{Deserialize, Deserializer};
use shared_types::{ClaimSchemaId, CredentialId, CredentialSchemaId, DidValue, KeyId, ProofId};
use time::OffsetDateTime;
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
use crate::common_mapper::{NESTED_CLAIM_MARKER, NESTED_CLAIM_MARKER_STR};
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{
    Arrayed, BackgroundProperties, CodeProperties, CodeTypeEnum, CredentialSchema,
    CredentialSchemaClaim, CredentialSchemaClaimsNestedObjectView,
    CredentialSchemaClaimsNestedTypeView, CredentialSchemaClaimsNestedView, LayoutProperties,
    LogoProperties,
};
use crate::model::did::Did;
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofState, ProofStateEnum};
use crate::model::proof_schema::ProofInputClaimSchema;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::MobileSecurityObject;
use crate::provider::credential_formatter::model::ExtractPresentationCtx;
use crate::provider::exchange_protocol::dto::{
    CredentialGroup, CredentialGroupItem, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use crate::provider::exchange_protocol::mapper::{
    create_presentation_definition_field, credential_model_to_credential_dto,
    gather_object_datatypes_from_config, get_relevant_credentials_to_credential_schemas,
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
use crate::provider::exchange_protocol::StorageAccess;
use crate::service::credential::dto::DetailCredentialSchemaResponseDTO;
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::error::ServiceError;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::util::oidc::{map_core_to_oidc_format, map_from_oidc_format_to_core};

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
    claims: Vec<Claim>,
) -> Result<Vec<OpenID4VCICredentialOfferCredentialDTO>, OpenID4VCError> {
    let claims = from_vec_claim(claims, credential_schema)?;

    Ok(vec![OpenID4VCICredentialOfferCredentialDTO {
        wallet_storage_type: credential_schema.wallet_storage_type.clone(),
        format: map_core_to_oidc_format(&credential_schema.format)
            .map_err(|e| OpenID4VCError::Other(e.to_string()))?,
        credential_definition: None,
        doctype: Some(credential_schema.schema_id.to_owned()),
        claims: Some(claims),
    }])
}

pub(crate) fn from_vec_claim(
    claims: Vec<Claim>,
    credential_schema: &CredentialSchema,
) -> Result<HashMap<String, OpenID4VCICredentialOfferClaim>, OpenID4VCError> {
    let claim_schemas = credential_schema
        .claim_schemas
        .as_ref()
        .ok_or(OpenID4VCError::Other("claim_schema is None".to_string()))?;

    claims
        .into_iter()
        .try_fold(Default::default(), |state, claim| {
            insert_claim(state, claim, claim_schemas)
        })
}

fn insert_claim(
    mut root: HashMap<String, OpenID4VCICredentialOfferClaim>,
    claim: Claim,
    claim_schemas: &[CredentialSchemaClaim],
) -> Result<HashMap<String, OpenID4VCICredentialOfferClaim>, OpenID4VCError> {
    match claim.path.rsplit_once(NESTED_CLAIM_MARKER) {
        Some((head, tail)) => {
            let claim_schema = claim
                .schema
                .as_ref()
                .ok_or_else(|| OpenID4VCError::Other("claim.schema is missing".into()))?;

            let parent_claim = get_or_insert(&mut root, head, claim_schemas, &claim_schema.key)?;

            let OpenID4VCICredentialOfferClaimValue::Nested(claims) = &mut parent_claim.value
            else {
                return Err(OpenID4VCError::Other(
                    "Parent claim should be nested".into(),
                ));
            };

            let credential_claim_schema = claim_schemas
                .iter()
                .find(|value| value.schema.key == claim_schema.key)
                .ok_or_else(|| OpenID4VCError::Other("claim.schema is unknown".into()))?;

            claims.insert(
                tail.to_owned(),
                OpenID4VCICredentialOfferClaim {
                    value_type: credential_claim_schema.schema.data_type.clone(),
                    value: OpenID4VCICredentialOfferClaimValue::String(claim.value.to_owned()),
                },
            );
        }
        None => {
            let claim_schema = claim
                .schema
                .as_ref()
                .ok_or_else(|| OpenID4VCError::Other("claim.schema is missing".into()))?;

            let claim_schema = claim_schemas
                .iter()
                .find(|value| value.schema.key == claim_schema.key)
                .ok_or_else(|| OpenID4VCError::Other("claim.schema is unknown".into()))?;

            root.insert(
                claim.path.to_owned(),
                OpenID4VCICredentialOfferClaim {
                    value_type: claim_schema.schema.data_type.clone(),
                    value: OpenID4VCICredentialOfferClaimValue::String(claim.value.to_owned()),
                },
            );
        }
    };

    Ok(root)
}

fn get_or_insert<'a>(
    root: &'a mut HashMap<String, OpenID4VCICredentialOfferClaim>,
    path: &str,
    claim_schemas: &[CredentialSchemaClaim],
    original_key: &str,
) -> Result<&'a mut OpenID4VCICredentialOfferClaim, OpenID4VCError> {
    match path.rsplit_once(NESTED_CLAIM_MARKER) {
        Some((head, tail)) => {
            let parent_claim = get_or_insert(root, head, claim_schemas, original_key)?;

            let OpenID4VCICredentialOfferClaimValue::Nested(claims) = &mut parent_claim.value
            else {
                return Err(OpenID4VCError::MappingError(
                    "Parent claim should be nested".into(),
                ));
            };

            Ok(match claims.entry(tail.to_string()) {
                Entry::Occupied(occupied_entry) => occupied_entry.into_mut(),
                Entry::Vacant(vacant_entry) => {
                    let key = from_path_to_key(path, original_key);
                    let item_schema = claim_schemas
                        .iter()
                        .find(|schema| schema.schema.key == key)
                        .ok_or_else(|| OpenID4VCError::Other("missing claim schema".into()))?;

                    vacant_entry.insert(OpenID4VCICredentialOfferClaim {
                        value_type: item_schema.schema.data_type.to_owned(),
                        value: OpenID4VCICredentialOfferClaimValue::Nested(Default::default()),
                    })
                }
            })
        }
        None => Ok(match root.entry(path.to_string()) {
            Entry::Occupied(occupied_entry) => occupied_entry.into_mut(),
            Entry::Vacant(vacant_entry) => vacant_entry.insert(OpenID4VCICredentialOfferClaim {
                value_type: claim_schemas
                    .iter()
                    .find(|schema| schema.schema.key == path)
                    .ok_or_else(|| OpenID4VCError::Other("missing claim schema".into()))?
                    .schema
                    .data_type
                    .to_owned(),
                value: OpenID4VCICredentialOfferClaimValue::Nested(Default::default()),
            }),
        }),
    }
}

fn from_path_to_key(path: &str, original_key: &str) -> String {
    let mut key_parts = original_key.split(NESTED_CLAIM_MARKER).peekable();

    path.split(NESTED_CLAIM_MARKER)
        .filter(move |part| {
            if Some(part) == key_parts.peek() {
                key_parts.next();
                true
            } else {
                false
            }
        })
        .join(NESTED_CLAIM_MARKER_STR)
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
                array: Some(claim.array.unwrap_or(false)),
                claims,
            }
        })
        .collect()
}

pub(crate) fn parse_mdoc_schema_claims(
    values: HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>,
    element_order: Option<Vec<String>>,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    let mut claims_by_namespace: Vec<_> = values
        .into_iter()
        .map(|(namespace, element)| CredentialClaimSchemaRequestDTO {
            key: namespace,
            datatype: "OBJECT".to_string(),
            required: element.mandatory.unwrap_or(false),
            array: Some(false),
            claims: parse_mdoc_schema_elements(element.value),
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

    let nested_schema_claim_view: CredentialSchemaClaimsNestedView = claim_schemas
        .clone()
        .try_into()
        .map_err(|err: ServiceError| ExchangeProtocolError::Other(err.into()))?;

    let nested_claim_view: ClaimsNestedView = claim_keys.clone().try_into()?;

    validate_and_collect_claims(
        credential_id,
        now,
        &nested_schema_claim_view,
        &nested_claim_view,
    )
}

fn validate_and_collect_claims(
    credential_id: CredentialId,
    now: OffsetDateTime,
    nested_schema_claim_view: &CredentialSchemaClaimsNestedView,
    nested_claim_view: &ClaimsNestedView,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    nested_schema_claim_view
        .fields
        .iter()
        .try_fold(vec![], |claims, (key, field)| {
            let nested_claim = nested_claim_view.claims.get(key);

            match nested_claim {
                Some(nested_claim) => {
                    let nested_claims = match field {
                        Arrayed::Single(CredentialSchemaClaimsNestedTypeView::Field(claim)) => {
                            visit_nested_field_field(credential_id, now, claim, nested_claim)
                        }
                        Arrayed::Single(CredentialSchemaClaimsNestedTypeView::Object(object)) => {
                            visit_nested_object_field(credential_id, now, object, nested_claim)
                        }
                        Arrayed::InArray(array) => {
                            visit_nested_array_field(credential_id, now, array, nested_claim)
                        }
                    }?;
                    Ok([claims, nested_claims].concat())
                }
                None if field.required() => Err(ExchangeProtocolError::Failed(format!(
                    "Validation Error. Claim key {} missing",
                    field.key(),
                ))),
                None => Ok(claims),
            }
        })
}

fn visit_nested_field_field(
    credential_id: CredentialId,
    now: OffsetDateTime,
    claim: &CredentialSchemaClaim,
    nested_claim_view: &ClaimsNestedFieldView,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    match nested_claim_view {
        ClaimsNestedFieldView::Leaf { key, value } => Ok(vec![Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: value.value.clone(),
            path: key.clone(),
            schema: Some(claim.schema.clone()),
        }]),
        ClaimsNestedFieldView::Nodes(_) => Err(ExchangeProtocolError::Failed(format!(
            "Validation Error. Claim key {} has wrong type",
            claim.schema.key,
        ))),
    }
}

fn visit_nested_object_field(
    credential_id: CredentialId,
    now: OffsetDateTime,
    object: &CredentialSchemaClaimsNestedObjectView,
    nested_claim_view: &ClaimsNestedFieldView,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    let claims_view = match nested_claim_view {
        ClaimsNestedFieldView::Leaf { .. } => {
            return Err(ExchangeProtocolError::Failed(format!(
                "Validation Error. Claim key {} has wrong type",
                object.claim.schema.key,
            )))
        }
        ClaimsNestedFieldView::Nodes(claims) => claims,
    };

    object
        .fields
        .iter()
        .try_fold(vec![], |claims, (key, field)| {
            let claim = claims_view.get(key);

            match &claim {
                Some(nested_claim) => {
                    let nested_claims = match field {
                        Arrayed::Single(CredentialSchemaClaimsNestedTypeView::Field(claim)) => {
                            visit_nested_field_field(credential_id, now, claim, nested_claim)
                        }
                        Arrayed::Single(CredentialSchemaClaimsNestedTypeView::Object(object)) => {
                            visit_nested_object_field(credential_id, now, object, nested_claim)
                        }
                        Arrayed::InArray(array) => {
                            visit_nested_array_field(credential_id, now, array, nested_claim)
                        }
                    }?;
                    Ok([claims, nested_claims].concat())
                }
                None if field.required() => Err(ExchangeProtocolError::Failed(format!(
                    "Validation Error. Claim key {} missing",
                    field.key(),
                ))),
                None => Ok(claims),
            }
        })
}

fn visit_nested_array_field(
    credential_id: CredentialId,
    now: OffsetDateTime,
    array: &CredentialSchemaClaimsNestedTypeView,
    nested_claim_view: &ClaimsNestedFieldView,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    let claims_view = match nested_claim_view {
        ClaimsNestedFieldView::Leaf { .. } => {
            return Err(ExchangeProtocolError::Failed(format!(
                "Validation Error. Claim key {} has wrong type",
                array.key(),
            )))
        }
        ClaimsNestedFieldView::Nodes(claims) => claims,
    };

    if claims_view.is_empty() && array.required() {
        return Err(ExchangeProtocolError::Failed(format!(
            "Validation Error. Required array claim key {} has no elements",
            array.key(),
        )));
    }

    (0..claims_view.len()).try_fold(vec![], |claims, index| {
        let claim = claims_view
            .get(&index.to_string())
            .ok_or(ExchangeProtocolError::Failed(format!(
                "Validation Error. Index {index} is missing for claim key {}",
                array.key(),
            )))?;

        let nested_claims = match array {
            CredentialSchemaClaimsNestedTypeView::Field(field) => {
                visit_nested_field_field(credential_id, now, field, claim)
            }
            CredentialSchemaClaimsNestedTypeView::Object(object) => {
                visit_nested_object_field(credential_id, now, object, claim)
            }
        }?;
        Ok([claims, nested_claims].concat())
    })
}

#[derive(Debug)]
struct ClaimsNestedView {
    claims: HashMap<String, ClaimsNestedFieldView>,
}

#[derive(Debug)]
enum ClaimsNestedFieldView {
    Leaf {
        key: String,
        value: OpenID4VCICredentialValueDetails,
    },
    Nodes(HashMap<String, ClaimsNestedFieldView>),
}

impl TryFrom<HashMap<String, OpenID4VCICredentialValueDetails>> for ClaimsNestedView {
    type Error = ExchangeProtocolError;

    fn try_from(
        value: HashMap<String, OpenID4VCICredentialValueDetails>,
    ) -> Result<Self, Self::Error> {
        let mut claims = HashMap::<String, ClaimsNestedFieldView>::new();

        for (key, value) in value {
            match key.rsplit_once(NESTED_CLAIM_MARKER) {
                Some((head, tail)) => {
                    let parent = get_or_insert_view(&mut claims, head)?;
                    let ClaimsNestedFieldView::Nodes(nodes) = parent else {
                        return Err(ExchangeProtocolError::Failed(
                            "Parent claim should be nested".into(),
                        ));
                    };

                    nodes.insert(tail.to_owned(), ClaimsNestedFieldView::Leaf { key, value });
                }
                None => {
                    claims.insert(key.clone(), ClaimsNestedFieldView::Leaf { key, value });
                }
            }
        }

        Ok(ClaimsNestedView { claims })
    }
}

fn get_or_insert_view<'a>(
    root: &'a mut HashMap<String, ClaimsNestedFieldView>,
    path: &str,
) -> Result<&'a mut ClaimsNestedFieldView, ExchangeProtocolError> {
    match path.split_once(NESTED_CLAIM_MARKER) {
        Some((head, tail)) => {
            let value = root
                .entry(head.to_owned())
                .or_insert_with(|| ClaimsNestedFieldView::Nodes(Default::default()));

            let ClaimsNestedFieldView::Nodes(nodes) = value else {
                return Err(ExchangeProtocolError::Failed(
                    "Parent claim should be nested".into(),
                ));
            };

            get_or_insert_view(nodes, tail)
        }
        None => Ok(root
            .entry(path.to_owned())
            .or_insert_with(|| ClaimsNestedFieldView::Nodes(Default::default()))),
    }
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
    mdoc_mso: Option<MobileSecurityObject>,
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
        mdoc_mso,
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

pub async fn holder_ble_mqtt_get_presentation_definition(
    config: &CoreConfig,
    proof: &Proof,
    presentation_definition: OpenID4VPPresentationDefinition,
    storage_access: &StorageAccess,
) -> anyhow::Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
    let mut credential_groups: Vec<CredentialGroup> = vec![];
    let mut group_id_to_schema_id: HashMap<String, String> = HashMap::new();

    let mut allowed_oidc_formats = HashSet::new();

    for input_descriptor in presentation_definition.input_descriptors {
        input_descriptor.format.keys().for_each(|key| {
            allowed_oidc_formats.insert(key.to_owned());
        });
        let validity_credential_nbf = input_descriptor.constraints.validity_credential_nbf;

        let mut fields = input_descriptor.constraints.fields;

        let schema_id_filter_index = fields
            .iter()
            .position(|field| {
                field.filter.is_some() && field.path.contains(&"$.credentialSchema.id".to_string())
            })
            .ok_or(ExchangeProtocolError::Failed(
                "schema_id filter not found".to_string(),
            ))?;

        let schema_id_filter =
            fields
                .remove(schema_id_filter_index)
                .filter
                .ok_or(ExchangeProtocolError::Failed(
                    "schema_id filter not found".to_string(),
                ))?;

        group_id_to_schema_id.insert(input_descriptor.id.clone(), schema_id_filter.r#const);
        credential_groups.push(CredentialGroup {
            id: input_descriptor.id,
            name: input_descriptor.name,
            purpose: input_descriptor.purpose,
            claims: fields
                .iter()
                .filter(|requested| requested.id.is_some())
                .map(|requested_claim| {
                    Ok(CredentialGroupItem {
                        id: requested_claim
                            .id
                            .ok_or(ExchangeProtocolError::Failed(
                                "requested_claim id is None".to_string(),
                            ))?
                            .to_string(),
                        key: get_claim_name_by_json_path(&requested_claim.path)?,
                        required: !requested_claim.optional.is_some_and(|optional| optional),
                    })
                })
                .collect::<anyhow::Result<Vec<_>, _>>()?,
            applicable_credentials: vec![],
            validity_credential_nbf,
        });
    }

    let mut allowed_schema_formats = HashSet::new();
    allowed_oidc_formats
        .iter()
        .try_for_each(|oidc_format| {
            let schema_type = map_from_oidc_format_to_core(oidc_format)?;

            config.format.iter().for_each(|(key, fields)| {
                if fields.r#type.to_string().starts_with(&schema_type) {
                    allowed_schema_formats.insert(key);
                }
            });
            Ok(())
        })
        .map_err(|e: ServiceError| ExchangeProtocolError::Failed(e.to_string()))?;

    let (credentials, credential_groups) = get_relevant_credentials_to_credential_schemas(
        storage_access,
        convert_inner(credential_groups),
        group_id_to_schema_id,
        &allowed_schema_formats,
        &gather_object_datatypes_from_config(&config.datatype),
    )
    .await?;
    presentation_definition_from_interaction_data(
        proof.id,
        convert_inner(credentials),
        convert_inner(credential_groups),
        config,
    )
    .map(Into::into)
}
