use std::collections::{BTreeMap, HashMap};

use shared_types::{CredentialId, ProofId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::provider::exchange_protocol::dto::{
    CredentialGroup, CredentialGroupItem, PresentationDefinitionFieldDTO,
    PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use crate::provider::exchange_protocol::openid4vc::mapper::get_parent_claim_paths;
use crate::provider::exchange_protocol::openid4vc::model::{
    DatatypeType, NestedPresentationSubmissionDescriptorDTO, OpenID4VCICredentialValueDetails,
    PresentationSubmissionDescriptorDTO, PresentationSubmissionMappingDTO, PresentedCredential,
};
use crate::provider::exchange_protocol::openid4vc::ExchangeProtocolError;
use crate::service::credential::dto::{
    CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO,
};
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;

pub fn create_claims_from_credential_definition(
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
                data_type: "OBJECT".to_string(),
                created_date: now,
                last_modified: now,
                array: false, // FIXME!
            },
            required: false,
        })
    }

    Ok((claim_schemas, claims))
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

pub fn create_presentation_definition_field(
    field: CredentialGroupItem,
    credentials: &[Credential],
) -> Result<PresentationDefinitionFieldDTO, ExchangeProtocolError> {
    let mut key_map: HashMap<String, String> = HashMap::new();
    let key = field.key;
    for credential in credentials {
        for claim in credential
            .claims
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "credential claims is None".to_string(),
            ))?
        {
            let claim_schema = claim.schema.as_ref().ok_or(ExchangeProtocolError::Failed(
                "claim schema is None".to_string(),
            ))?;

            if claim_schema.key.starts_with(&key) {
                key_map.insert(credential.id.to_string(), key.clone());
                break;
            }
        }
    }
    Ok(PresentationDefinitionFieldDTO {
        id: field.id,
        name: Some(key),
        purpose: None,
        required: Some(field.required),
        key_map,
    })
}

pub fn credential_model_to_credential_dto(
    credentials: Vec<Credential>,
    types: &HashMap<String, DatatypeType>,
) -> Result<Vec<CredentialDetailResponseDTO>, ExchangeProtocolError> {
    credentials
        .into_iter()
        .map(|credential| credential_detail_response_from_model(credential, types))
        .collect()
}

pub fn credential_detail_response_from_model(
    value: Credential,
    types: &HashMap<String, DatatypeType>,
) -> Result<CredentialDetailResponseDTO, ExchangeProtocolError> {
    let schema = value.schema.ok_or(ExchangeProtocolError::Failed(
        "credential_schema is None".to_string(),
    ))?;
    let claims = value
        .claims
        .ok_or(ExchangeProtocolError::Failed("claims is None".to_string()))?;
    let states = value
        .state
        .ok_or(ExchangeProtocolError::Failed("state is None".to_string()))?;
    let latest_state = states
        .first()
        .ok_or(ExchangeProtocolError::Failed(
            "latest state not found".to_string(),
        ))?
        .to_owned();

    Ok(CredentialDetailResponseDTO {
        id: value.id,
        created_date: value.created_date,
        issuance_date: value.issuance_date,
        revocation_date: get_revocation_date(&latest_state),
        state: latest_state.state.into(),
        last_modified: value.last_modified,
        claims: from_vec_claim(claims, &schema, types)?,
        schema: schema.try_into()?,
        issuer_did: value.issuer_did.map(Into::into),
        redirect_uri: value.redirect_uri,
        role: value.role.into(),
        lvvc_issuance_date: None,
        suspend_end_date: latest_state.suspend_end_date,
        mdoc_mso_validity: None,
        holder_did: value.holder_did.map(Into::into),
    })
}

fn get_revocation_date(latest_state: &CredentialState) -> Option<OffsetDateTime> {
    if latest_state.state == CredentialStateEnum::Revoked {
        Some(latest_state.created_date)
    } else {
        None
    }
}

pub fn from_vec_claim(
    claims: Vec<Claim>,
    credential_schema: &CredentialSchema,
    types: &HashMap<String, DatatypeType>,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ExchangeProtocolError> {
    let claim_schemas =
        credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "claim_schemas is None".to_string(),
            ))?;
    let result = claim_schemas
        .iter()
        .map(|claim_schema| {
            let claims = claims
                .iter()
                .filter(|claim| {
                    let schema = claim.schema.as_ref().ok_or(ExchangeProtocolError::Failed(
                        "claim_schema is None".to_string(),
                    ));
                    if let Ok(schema) = schema {
                        schema.id == claim_schema.schema.id
                    } else {
                        false
                    }
                })
                .collect::<Vec<_>>();

            if claims.is_empty() {
                Ok(vec![DetailCredentialClaimResponseDTO {
                    path: claim_schema.schema.key.to_owned(),
                    schema: claim_schema.to_owned().into(),
                    value: DetailCredentialClaimValueResponseDTO::Nested(vec![]),
                }])
            } else {
                claims
                    .into_iter()
                    .map(|claim| claim_to_dto(claim, claim_schema, types))
                    .collect::<Result<_, _>>()
            }
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();

    let nested = renest_claims(result)?;
    let arrays_nested = renest_arrays(nested, "", claim_schemas, types)?;
    let sorted = sort_arrays(arrays_nested);
    Ok(sorted)
}

pub fn renest_claims(
    claims: Vec<DetailCredentialClaimResponseDTO>,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ExchangeProtocolError> {
    let mut result = vec![];

    // Iterate over all and copy all unnested non-array claims to new vec
    for claim in claims.iter() {
        if claim.schema.key.find(NESTED_CLAIM_MARKER).is_none() {
            result.push(claim.to_owned());
        }
    }

    // Find all nested claims and move them to related entries in result vec
    for mut claim in claims.into_iter() {
        if claim.schema.key.find(NESTED_CLAIM_MARKER).is_some() {
            let matching_entry = result
                .iter_mut()
                .find(|result_schema| {
                    claim.schema.key.starts_with(&format!(
                        "{}{NESTED_CLAIM_MARKER}",
                        result_schema.schema.key
                    ))
                })
                .ok_or(ExchangeProtocolError::Failed(
                    "missing parent claim schema".into(),
                ))?;
            claim.schema.key = remove_first_nesting_layer(&claim.schema.key);

            match &mut matching_entry.value {
                DetailCredentialClaimValueResponseDTO::Nested(nested) => {
                    nested.push(claim);
                }
                _ => {
                    matching_entry.value =
                        DetailCredentialClaimValueResponseDTO::Nested(vec![claim]);
                }
            }
        }
    }

    // Repeat for all claims to nest all subclaims
    let mut nested = result
        .into_iter()
        .map(|mut claim_schema| {
            if let DetailCredentialClaimValueResponseDTO::Nested(nested) = &claim_schema.value {
                claim_schema.value = DetailCredentialClaimValueResponseDTO::Nested(renest_claims(
                    nested.to_owned(),
                )?);
            }

            Ok(claim_schema)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Remove empty non-required object claims
    nested.retain(|element| match &element.value {
        DetailCredentialClaimValueResponseDTO::Nested(value) => {
            element.schema.required || !value.is_empty()
        }
        _ => true,
    });

    Ok(nested)
}

fn remove_first_nesting_layer(name: &str) -> String {
    match name.find(NESTED_CLAIM_MARKER) {
        Some(marker_pos) => name[marker_pos + 1..].to_string(),
        None => name.to_string(),
    }
}

pub fn claim_to_dto(
    claim: &Claim,
    claim_schema: &CredentialSchemaClaim,
    types: &HashMap<String, DatatypeType>,
) -> Result<DetailCredentialClaimResponseDTO, ExchangeProtocolError> {
    let value = match types
        .get(&claim_schema.schema.data_type)
        .ok_or_else(|| ExchangeProtocolError::Failed("unknown type".into()))?
    {
        DatatypeType::Number => {
            if let Ok(number) = claim.value.parse::<i64>() {
                DetailCredentialClaimValueResponseDTO::Integer(number)
            } else {
                DetailCredentialClaimValueResponseDTO::Float(
                    claim
                        .value
                        .parse::<f64>()
                        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?,
                )
            }
        }
        DatatypeType::Boolean => DetailCredentialClaimValueResponseDTO::Boolean(
            claim
                .value
                .parse::<bool>()
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?,
        ),
        _ => DetailCredentialClaimValueResponseDTO::String(claim.value.to_owned()),
    };

    Ok(DetailCredentialClaimResponseDTO {
        path: claim.path.to_owned(),
        schema: claim_schema.to_owned().into(),
        value,
    })
}

pub fn sort_arrays(
    claims: Vec<DetailCredentialClaimResponseDTO>,
) -> Vec<DetailCredentialClaimResponseDTO> {
    claims
        .into_iter()
        .map(|mut claim| {
            if claim.schema.array {
                if let DetailCredentialClaimValueResponseDTO::Nested(values) = &mut claim.value {
                    let prefix = format!("{}{NESTED_CLAIM_MARKER}", claim.path);
                    values.sort_by(|v1, v2| {
                        let v1_index = extract_index_from_path(&v1.path, &prefix).parse::<u64>();
                        let v2_index = extract_index_from_path(&v2.path, &prefix).parse::<u64>();

                        match (v1_index, v2_index) {
                            (Ok(i1), Ok(i2)) => i1.cmp(&i2),
                            _ => v1.path.cmp(&v2.path),
                        }
                    });

                    *values = sort_arrays(values.to_owned());
                }
            }
            claim
        })
        .collect()
}

pub(super) fn extract_index_from_path<'a>(path: &'a str, prefix: &'a str) -> &'a str {
    if path.len() <= prefix.len() {
        return path;
    }

    let path = &path[prefix.len()..];
    match path.find(NESTED_CLAIM_MARKER) {
        None => path,
        Some(value) => &path[0..value],
    }
}

pub(super) fn renest_arrays(
    claims: Vec<DetailCredentialClaimResponseDTO>,
    prefix: &str,
    claim_schemas: &[CredentialSchemaClaim],
    types: &HashMap<String, DatatypeType>,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ExchangeProtocolError> {
    let object_datatypes = types
        .iter()
        .filter_map(|(key, r#type)| {
            if r#type == &DatatypeType::Object {
                Some(key.to_owned())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    // Copy non-arrays & array objects directly to result
    let mut result = claims
        .iter()
        .filter(|claim| !claim.schema.array || object_datatypes.contains(&claim.schema.datatype))
        .cloned()
        .collect::<Vec<_>>();

    // Collect list of array prefixes and use them to insert items to result
    claims
        .iter()
        .filter_map(|claim| {
            if claim.schema.array && !object_datatypes.contains(&claim.schema.datatype) {
                Some((claim.schema.key.to_owned(), claim.schema.to_owned()))
            } else {
                None
            }
        })
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .for_each(|(key, schema)| {
            let mut values = vec![];

            claims.iter().for_each(|claim| {
                if claim.schema.id == schema.id {
                    values.push(claim.to_owned());
                }
            });

            match result.iter_mut().find(|item| item.schema.id == schema.id) {
                None => {
                    if schema.array
                        && values.first().is_some_and(|f| match &f.value {
                            DetailCredentialClaimValueResponseDTO::Nested(value) => {
                                f.schema.array && value.is_empty()
                            }
                            _ => f.schema.array,
                        })
                    {
                        result.push(DetailCredentialClaimResponseDTO {
                            path: format!("{prefix}{key}"),
                            schema: schema.to_owned(),
                            value: DetailCredentialClaimValueResponseDTO::Nested(
                                values
                                    .into_iter()
                                    .map(|mut value| {
                                        value.schema.array = false;
                                        value
                                    })
                                    .collect(),
                            ),
                        })
                    } else {
                        result.extend(values);
                    }
                }
                Some(item) => {
                    if item.schema.array {
                        item.value = DetailCredentialClaimValueResponseDTO::Nested(
                            values
                                .into_iter()
                                .map(|mut value| {
                                    value.schema.array = false;
                                    value
                                })
                                .collect(),
                        );
                    } else {
                        item.value = DetailCredentialClaimValueResponseDTO::Nested(values);
                    }
                }
            };
        });

    // Repeat for all object claims
    result
        .into_iter()
        .map(|mut claim| {
            if object_datatypes.contains(&claim.schema.datatype) {
                match &mut claim.value {
                    DetailCredentialClaimValueResponseDTO::Nested(value) => {
                        let prefix = format!("{}{NESTED_CLAIM_MARKER}", claim.path);

                        *value = group_subitems(value.to_owned(), &prefix, claim_schemas, types)?;
                        *value = renest_arrays(value.to_owned(), &prefix, claim_schemas, types)?;

                        Ok(claim)
                    }
                    _ => Ok(claim),
                }
            } else {
                Ok(claim)
            }
        })
        .collect()
}

fn group_subitems(
    items: Vec<DetailCredentialClaimResponseDTO>,
    prefix: &str,
    claim_schemas: &[CredentialSchemaClaim],
    types: &HashMap<String, DatatypeType>,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ExchangeProtocolError> {
    let mut current_index = 0;

    let mut result = vec![];

    loop {
        let expected_path = format!("{prefix}{current_index}");
        let expected_prefix = format!("{expected_path}{NESTED_CLAIM_MARKER}");

        let current_items: Vec<DetailCredentialClaimResponseDTO> = items
            .iter()
            .filter_map(|item| {
                if item.path.starts_with(&expected_prefix) {
                    Some(item.to_owned())
                } else {
                    None
                }
            })
            .collect();

        if current_items.is_empty() {
            break;
        }

        let current_items = renest_arrays(current_items, &expected_prefix, claim_schemas, types)?;

        let schema = find_schema_for_path(&expected_path, claim_schemas)?;

        result.push(DetailCredentialClaimResponseDTO {
            path: expected_path,
            schema: CredentialClaimSchemaDTO {
                id: schema.schema.id,
                created_date: schema.schema.created_date,
                last_modified: schema.schema.last_modified,
                key: schema.schema.key,
                datatype: schema.schema.data_type,
                required: schema.required,
                array: false,
                claims: vec![],
            },
            value: DetailCredentialClaimValueResponseDTO::Nested(current_items),
        });

        current_index += 1;
    }

    if result.is_empty() {
        Ok(items)
    } else {
        Ok(result)
    }
}

fn find_schema_for_path(
    path: &str,
    claim_schemas: &[CredentialSchemaClaim],
) -> Result<CredentialSchemaClaim, ExchangeProtocolError> {
    let result = claim_schemas
        .iter()
        .find(|schema| schema.schema.key == path);

    match result {
        None => match path.rfind(NESTED_CLAIM_MARKER) {
            None => Err(ExchangeProtocolError::Failed(
                "schema not found".to_string(),
            )),
            Some(value) => find_schema_for_path(&path[0..value], claim_schemas),
        },
        Some(value) => Ok(value.to_owned()),
    }
}

pub fn map_credential_formats_to_presentation_format(
    formats: &HashMap<&str, &str>,
    credential_formats: &HashMap<String, String>,
) -> Result<(bool, String, String), ExchangeProtocolError> {
    let mut has_mdoc = false;
    if let Some(value) = formats.get("mso_mdoc") {
        has_mdoc = true;
        if formats.len() == 1 {
            return Ok((has_mdoc, value.to_string(), "mso_mdoc".to_owned()));
        }
    };

    if let Some(&value) = formats.get("ldp_vc") {
        Ok((has_mdoc, value.to_owned(), "ldp_vp".to_owned()))
    } else {
        credential_formats
            .iter()
            .find(|(_, v)| v.as_str() == "jwt_vc_json" || v.as_str() == "vc+sd-jwt")
            .map(|(k, _)| (has_mdoc, k.to_owned(), "jwt_vp_json".to_owned()))
            .ok_or_else(|| ExchangeProtocolError::Failed("no jwt_vp_json format in map".into()))
    }
}

pub(super) fn presentation_definition_from_interaction_data(
    proof_id: ProofId,
    credentials: Vec<Credential>,
    credential_groups: Vec<CredentialGroup>,
    types: &HashMap<String, DatatypeType>,
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
                        fields: group
                            .claims
                            .into_iter()
                            .map(|field| {
                                create_presentation_definition_field(
                                    field,
                                    &group
                                        .applicable_credentials
                                        .iter()
                                        .chain(group.inapplicable_credentials.iter())
                                        .cloned()
                                        .collect::<Vec<_>>(),
                                )
                            })
                            .collect::<Result<_, _>>()?,

                        applicable_credentials: group
                            .applicable_credentials
                            .into_iter()
                            .map(|credential| credential.id.to_string())
                            .collect(),
                        inapplicable_credentials: group
                            .inapplicable_credentials
                            .into_iter()
                            .map(|credential| credential.id.to_string())
                            .collect(),
                        validity_credential_nbf: group.validity_credential_nbf,
                    })
                })
                .collect::<Result<_, _>>()?,
        }],
        credentials: credential_model_to_credential_dto(credentials, types)?,
    })
}
