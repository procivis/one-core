use std::collections::HashMap;

use dto_mapper::convert_inner;
use one_providers::common_models::claim::OpenClaim;
use one_providers::common_models::claim_schema::{ClaimSchemaId, OpenClaimSchema};
use one_providers::common_models::credential::CredentialId;
use one_providers::common_models::credential_schema::{
    CredentialSchemaId, OpenCredentialSchema, OpenCredentialSchemaClaim,
};

use one_providers::exchange_protocol::openid4vc::error::OpenID4VCError;
use one_providers::exchange_protocol::openid4vc::model::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaDetailResponseDTO, OpenID4VCICredentialOfferClaim,
    OpenID4VCICredentialOfferClaimValue, OpenID4VCICredentialOfferCredentialDTO,
    OpenID4VCICredentialValueDetails, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO, OpenID4VPFormat,
    OpenID4VPPresentationDefinitionInputDescriptorFormat,
};
use shared_types::ProofId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common_mapper::{remove_first_nesting_layer, NESTED_CLAIM_MARKER};
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::model::credential::Credential;
use crate::model::organisation::Organisation;
use crate::provider::exchange_protocol::dto::{
    CredentialGroup, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use crate::provider::exchange_protocol::mapper::{
    create_presentation_definition_field, credential_model_to_credential_dto,
};
use crate::provider::exchange_protocol::ExchangeProtocolError;
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
                                        field.into(),
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
    credential_schema: &OpenCredentialSchema,
    claims: &[OpenClaim],
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
    credential_schema: &OpenCredentialSchema,
    claims: &[OpenClaim],
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
) -> Result<(Vec<OpenCredentialSchemaClaim>, Vec<OpenClaim>), ExchangeProtocolError> {
    let now = OffsetDateTime::now_utc();
    let mut claim_schemas: Vec<OpenCredentialSchemaClaim> = vec![];
    let mut claims: Vec<OpenClaim> = vec![];
    let mut object_claim_schemas: Vec<&str> = vec![];

    for (key, value_details) in claim_keys {
        let new_schema_claim = OpenCredentialSchemaClaim {
            schema: OpenClaimSchema {
                id: Uuid::new_v4().into(),
                key: key.to_string(),
                data_type: value_details.value_type.to_string(),
                created_date: now,
                last_modified: now,
                array: false,
            },
            required: false,
        };

        let claim = OpenClaim {
            id: Uuid::new_v4().into(),
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
        claim_schemas.push(OpenCredentialSchemaClaim {
            schema: OpenClaimSchema {
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
) -> OpenCredentialSchemaClaim {
    OpenCredentialSchemaClaim {
        schema: OpenClaimSchema {
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
    client: &reqwest::Client,
) -> Result<CredentialSchemaDetailResponseDTO, reqwest::Error> {
    client
        .get(schema_id)
        .send()
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
) -> Result<OpenCredentialSchema, ExchangeProtocolError> {
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
) -> Result<OpenCredentialSchema, ExchangeProtocolError> {
    if request.claims.is_empty() {
        return Err(ExchangeProtocolError::Failed(
            "Claim schemas cannot be empty".to_string(),
        ));
    }

    let now = OffsetDateTime::now_utc();

    let claim_schemas = unnest_claim_schemas(request.claims);

    let schema_id = request
        .schema_id
        .unwrap_or(format!("{core_base_url}/ssi/schema/v1/{id}"));
    let schema_type = schema_type.unwrap_or(match format_type {
        "MDOC" => "mdoc".to_owned(),
        _ => "ProcivisOneSchema2024".to_owned(),
    });

    Ok(OpenCredentialSchema {
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
        schema_type,
        schema_id,
        organisation: Some(organisation.into()),
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
