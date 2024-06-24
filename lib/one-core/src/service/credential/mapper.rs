use dto_mapper::convert_inner;
use shared_types::CredentialId;
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common_mapper::{remove_first_nesting_layer, NESTED_CLAIM_MARKER};
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::model::claim::Claim;
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::did::Did;
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::provider::revocation::CredentialRevocationState;
use crate::service::credential::dto::{
    CreateCredentialRequestDTO, CredentialDetailResponseDTO, CredentialListItemResponseDTO,
    CredentialRequestClaimDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO, DetailCredentialSchemaResponseDTO,
};
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::error::{BusinessLogicError, ServiceError};

pub fn credential_detail_response_from_model(
    value: Credential,
    config: &CoreConfig,
) -> Result<CredentialDetailResponseDTO, ServiceError> {
    let schema = value.schema.ok_or(ServiceError::MappingError(
        "credential_schema is None".to_string(),
    ))?;
    let claims = value
        .claims
        .ok_or(ServiceError::MappingError("claims is None".to_string()))?;
    let states = value
        .state
        .ok_or(ServiceError::MappingError("state is None".to_string()))?;
    let latest_state = states
        .first()
        .ok_or(ServiceError::MappingError(
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
        claims: from_vec_claim(claims, &schema, config)?,
        schema: schema.try_into()?,
        issuer_did: convert_inner(value.issuer_did),
        redirect_uri: value.redirect_uri,
        role: value.role.into(),
        lvvc_issuance_date: None,
        suspend_end_date: latest_state.suspend_end_date,
    })
}

impl TryFrom<CredentialSchema> for DetailCredentialSchemaResponseDTO {
    type Error = ServiceError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
        let organisation_id = match value.organisation {
            None => Err(ServiceError::MappingError(
                "Organisation has not been fetched".to_string(),
            )),
            Some(value) => Ok(value.id),
        }?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            deleted_at: value.deleted_at,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            wallet_storage_type: value.wallet_storage_type,
            organisation_id,
            schema_type: value.schema_type.into(),
            schema_id: value.schema_id,
            layout_type: value.layout_type.into(),
            layout_properties: convert_inner(value.layout_properties),
        })
    }
}

pub(super) fn renest_claims(
    claims: Vec<DetailCredentialClaimResponseDTO>,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError> {
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
                .ok_or(ServiceError::BusinessLogic(
                    BusinessLogicError::MissingParentClaimSchema {
                        claim_schema_id: claim.schema.id,
                    },
                ))?;
            claim.schema.key = remove_first_nesting_layer(&claim.schema.key);

            match &mut matching_entry.value {
                DetailCredentialClaimValueResponseDTO::String(_value) => {
                    matching_entry.value =
                        DetailCredentialClaimValueResponseDTO::Nested(vec![claim]);
                }
                DetailCredentialClaimValueResponseDTO::Nested(nested) => {
                    nested.push(claim);
                }
            }
        }
    }

    // Repeat for all claims to nest all subclaims
    let mut nested = result
        .into_iter()
        .map(|mut claim_schema| {
            match &claim_schema.value {
                DetailCredentialClaimValueResponseDTO::String(_value) => {}
                DetailCredentialClaimValueResponseDTO::Nested(nested) => {
                    claim_schema.value = DetailCredentialClaimValueResponseDTO::Nested(
                        renest_claims(nested.to_owned())?,
                    );
                }
            }
            Ok(claim_schema)
        })
        .collect::<Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError>>()?;

    // Remove empty non-required object claims
    nested.retain(|element| match &element.value {
        DetailCredentialClaimValueResponseDTO::Nested(value) => {
            element.schema.required || !value.is_empty()
        }
        _ => true,
    });

    Ok(nested)
}

pub(crate) fn from_vec_claim(
    claims: Vec<Claim>,
    credential_schema: &CredentialSchema,
    config: &CoreConfig,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError> {
    let claim_schemas =
        credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?;
    let result = claim_schemas
        .iter()
        .flat_map(|claim_schema| {
            let claims = claims
                .iter()
                .filter(|claim| {
                    let schema = claim.schema.as_ref().ok_or(ServiceError::MappingError(
                        "claim_schema is None".to_string(),
                    ));
                    if let Ok(schema) = schema {
                        schema.id == claim_schema.schema.id
                    } else {
                        false
                    }
                })
                .collect::<Vec<&Claim>>();

            if claims.is_empty() {
                vec![DetailCredentialClaimResponseDTO {
                    path: claim_schema.schema.key.to_owned(),
                    schema: claim_schema.to_owned().into(),
                    value: DetailCredentialClaimValueResponseDTO::Nested(vec![]),
                }]
            } else {
                claims
                    .into_iter()
                    .map(|claim| DetailCredentialClaimResponseDTO {
                        path: claim.path.to_owned(),
                        schema: claim_schema.to_owned().into(),
                        value: DetailCredentialClaimValueResponseDTO::String(
                            claim.value.to_owned(),
                        ),
                    })
                    .collect()
            }
        })
        .collect::<Vec<DetailCredentialClaimResponseDTO>>();

    let nested = renest_claims(result)?;
    let arrays_nested = renest_arrays(nested, "", claim_schemas, config)?;
    let sorted = sort_arrays(arrays_nested);
    Ok(sorted)
}

pub fn sort_arrays(
    claims: Vec<DetailCredentialClaimResponseDTO>,
) -> Vec<DetailCredentialClaimResponseDTO> {
    claims
        .into_iter()
        .map(|mut claim| {
            if claim.schema.array {
                match &mut claim.value {
                    DetailCredentialClaimValueResponseDTO::String(_) => {}
                    DetailCredentialClaimValueResponseDTO::Nested(values) => {
                        let prefix = format!("{}{NESTED_CLAIM_MARKER}", claim.path);
                        values.sort_by(|v1, v2| {
                            let v1_index =
                                extract_index_from_path(&v1.path, &prefix).parse::<u64>();
                            let v2_index =
                                extract_index_from_path(&v2.path, &prefix).parse::<u64>();

                            match (v1_index, v2_index) {
                                (Ok(i1), Ok(i2)) => i1.cmp(&i2),
                                _ => v1.path.cmp(&v2.path),
                            }
                        });

                        *values = sort_arrays(values.to_owned());
                    }
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
    config: &CoreConfig,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError> {
    let object_datatypes = config
        .datatype
        .iter()
        .filter_map(|(key, fields)| {
            if fields.r#type == DatatypeType::Object {
                Some(key)
            } else {
                None
            }
        })
        .collect::<Vec<&str>>();

    // Copy non-arrays & array objects directly to result
    let mut result = claims
        .iter()
        .filter(|claim| {
            !claim.schema.array || object_datatypes.contains(&claim.schema.datatype.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();

    // Collect list of array prefixes and use them to insert items to result
    claims
        .iter()
        .filter_map(|claim| {
            if claim.schema.array && !object_datatypes.contains(&claim.schema.datatype.as_str()) {
                Some((claim.schema.key.to_owned(), claim.schema.to_owned()))
            } else {
                None
            }
        })
        .collect::<BTreeMap<String, CredentialClaimSchemaDTO>>()
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
                            DetailCredentialClaimValueResponseDTO::String(_) => f.schema.array,
                            DetailCredentialClaimValueResponseDTO::Nested(value) => {
                                f.schema.array && value.first().is_none()
                            }
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
            if object_datatypes.contains(&claim.schema.datatype.as_str()) {
                match &mut claim.value {
                    DetailCredentialClaimValueResponseDTO::String(_) => Ok(claim),
                    DetailCredentialClaimValueResponseDTO::Nested(value) => {
                        let prefix = format!("{}{NESTED_CLAIM_MARKER}", claim.path);

                        *value = group_subitems(value.to_owned(), &prefix, claim_schemas, config)?;
                        *value = renest_arrays(value.to_owned(), &prefix, claim_schemas, config)?;

                        Ok(claim)
                    }
                }
            } else {
                Ok(claim)
            }
        })
        .collect::<Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError>>()
}

fn group_subitems(
    items: Vec<DetailCredentialClaimResponseDTO>,
    prefix: &str,
    claim_schemas: &[CredentialSchemaClaim],
    config: &CoreConfig,
) -> Result<Vec<DetailCredentialClaimResponseDTO>, ServiceError> {
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

        let current_items = renest_arrays(current_items, &expected_prefix, claim_schemas, config)?;

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
) -> Result<CredentialSchemaClaim, ServiceError> {
    let result = claim_schemas
        .iter()
        .find(|schema| schema.schema.key == path);

    match result {
        None => match path.rfind(NESTED_CLAIM_MARKER) {
            None => Err(ServiceError::MappingError("schema not found".to_string())),
            Some(value) => find_schema_for_path(&path[0..value], claim_schemas),
        },
        Some(value) => Ok(value.to_owned()),
    }
}

impl TryFrom<Credential> for CredentialListItemResponseDTO {
    type Error = ServiceError;

    fn try_from(value: Credential) -> Result<Self, ServiceError> {
        let schema = value.schema.ok_or(ServiceError::MappingError(
            "credential_schema is None".to_string(),
        ))?;

        let states = value
            .state
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = states
            .first()
            .ok_or(ServiceError::MappingError(
                "latest state not found".to_string(),
            ))?
            .to_owned();

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            revocation_date: get_revocation_date(&latest_state),
            state: latest_state.state.into(),
            last_modified: value.last_modified,
            schema: schema.into(),
            issuer_did: convert_inner(value.issuer_did),
            credential: value.credential,
            role: value.role.into(),
            suspend_end_date: latest_state.suspend_end_date,
        })
    }
}

fn get_revocation_date(latest_state: &CredentialState) -> Option<OffsetDateTime> {
    if latest_state.state == CredentialStateEnum::Revoked {
        Some(latest_state.created_date)
    } else {
        None
    }
}

pub(super) fn from_create_request(
    request: CreateCredentialRequestDTO,
    credential_id: CredentialId,
    claims: Vec<Claim>,
    issuer_did: Did,
    schema: CredentialSchema,
    key: Key,
) -> Credential {
    let now = OffsetDateTime::now_utc();

    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
        }]),
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: request.exchange,
        claims: Some(claims),
        issuer_did: Some(issuer_did),
        holder_did: None,
        schema: Some(schema),
        interaction: None,
        revocation_list: None,
        key: Some(key),
        redirect_uri: request.redirect_uri,
        role: CredentialRole::Issuer,
    }
}

pub(super) fn claims_from_create_request(
    credential_id: CredentialId,
    claims: Vec<CredentialRequestClaimDTO>,
    claim_schemas: &[CredentialSchemaClaim],
) -> Result<Vec<Claim>, ServiceError> {
    let now = OffsetDateTime::now_utc();

    claims
        .into_iter()
        .map(|claim| {
            let claim_schema_id = claim.claim_schema_id;
            let schema = claim_schemas
                .iter()
                .find(|schema| schema.schema.id == claim_schema_id)
                .ok_or(BusinessLogicError::MissingClaimSchema { claim_schema_id })?;
            Ok(Claim {
                id: Uuid::new_v4(),
                credential_id,
                created_date: now,
                last_modified: now,
                value: claim.value,
                path: claim.path,
                schema: Some(schema.schema.clone()),
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

pub(super) fn credential_created_history_event(
    credential: Credential,
) -> Result<History, ServiceError> {
    Ok(History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Issued,
        entity_id: Some(credential.id.into()),
        entity_type: HistoryEntityType::Credential,
        metadata: None,
        organisation: credential
            .schema
            .ok_or(ServiceError::MappingError(
                "organisation is None".to_string(),
            ))?
            .organisation,
    })
}

pub(super) fn credential_offered_history_event(credential: Credential) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Offered,
        entity_id: Some(credential.id.into()),
        entity_type: HistoryEntityType::Credential,
        metadata: None,
        organisation: credential.schema.and_then(|c| c.organisation),
    }
}

pub(crate) fn credential_revocation_history_event(
    id: CredentialId,
    new_state: CredentialRevocationState,
    organisation: Option<Organisation>,
) -> History {
    let action = match new_state {
        CredentialRevocationState::Revoked => HistoryAction::Revoked,
        CredentialRevocationState::Valid => HistoryAction::Reactivated,
        CredentialRevocationState::Suspended { .. } => HistoryAction::Suspended,
    };

    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: Some(id.into()),
        entity_type: HistoryEntityType::Credential,
        metadata: None,
        organisation,
    }
}

pub(super) fn credential_revocation_state_to_model_state(
    revocation_state: CredentialRevocationState,
) -> CredentialStateEnum {
    match revocation_state {
        CredentialRevocationState::Revoked => CredentialStateEnum::Revoked,
        CredentialRevocationState::Valid => CredentialStateEnum::Accepted,
        CredentialRevocationState::Suspended { .. } => CredentialStateEnum::Suspended,
    }
}
