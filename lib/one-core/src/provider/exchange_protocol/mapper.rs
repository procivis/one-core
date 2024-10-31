use std::collections::{HashMap, HashSet};

use shared_types::{CredentialId, DidId, ProofId};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::dto::{CredentialGroup, CredentialGroupItem, PresentationDefinitionFieldDTO};
use super::{ExchangeProtocolError, StorageAccess};
use crate::config::core_config::{CoreConfig, DatatypeConfig, DatatypeType};
use crate::model::credential::{
    Credential, CredentialState, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::did::Did;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofState, ProofStateEnum};
use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::service::credential::mapper::credential_detail_response_from_model;

pub(super) fn get_issued_credential_update(
    credential_id: &CredentialId,
    token: &str,
    holder_did_id: DidId,
) -> UpdateCredentialRequest {
    UpdateCredentialRequest {
        id: credential_id.to_owned(),
        credential: Some(token.bytes().collect()),
        state: Some(CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: crate::model::credential::CredentialStateEnum::Accepted,
            suspend_end_date: None,
        }),
        key: None,
        holder_did_id: Some(holder_did_id),
        issuer_did_id: None,
        interaction: None,
        redirect_uri: None,
    }
}

pub fn interaction_from_handle_invitation(
    host: Url,
    data: Option<Vec<u8>>,
    now: OffsetDateTime,
    organisation: Option<Organisation>,
) -> Interaction {
    Interaction {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        host: Some(host),
        data,
        organisation,
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
    state: ProofStateEnum,
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
            state,
        }]),
        schema: None,
        claims: None,
        verifier_did,
        holder_did: None,
        interaction: Some(interaction),
        verifier_key,
    }
}

pub fn credential_model_to_credential_dto(
    credentials: Vec<Credential>,
    config: &CoreConfig,
) -> Result<Vec<CredentialDetailResponseDTO>, ExchangeProtocolError> {
    // Missing organisation here.
    credentials
        .into_iter()
        .map(|credential| credential_detail_response_from_model(credential, config, None))
        .collect::<Result<Vec<CredentialDetailResponseDTO>, _>>()
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
}

pub async fn get_relevant_credentials_to_credential_schemas(
    storage_access: &StorageAccess,
    mut credential_groups: Vec<CredentialGroup>,
    group_id_to_schema_id_mapping: HashMap<String, String>,
    allowed_schema_formats: &HashSet<&str>,
    object_datatypes: &HashSet<&str>,
) -> Result<(Vec<Credential>, Vec<CredentialGroup>), ExchangeProtocolError> {
    let mut relevant_credentials: Vec<Credential> = Vec::new();
    for group in &mut credential_groups {
        let credential_schema_id =
            group_id_to_schema_id_mapping
                .get(&group.id)
                .ok_or(ExchangeProtocolError::Failed(
                    "Incorrect group id to credential schema id mapping".to_owned(),
                ))?;

        let relevant_credentials_inner = storage_access
            .get_credentials_by_credential_schema_id(credential_schema_id)
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        for credential in &relevant_credentials_inner {
            let schema = credential
                .schema
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed("schema missing".to_string()))?;

            if !allowed_schema_formats
                .iter()
                // In case of JSON_LD we could have different crypto suits as separate formats.
                // This will work as long as we have common part as allowed format. In this case
                // it translates ldp_vc to JSON_LD that could be a common part of JSON_LD_CS1 and JSON_LD_CS2
                .any(|allowed_schema_format| schema.format.starts_with(allowed_schema_format))
            {
                continue;
            }

            let credential_state = credential
                .state
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed("state missing".to_string()))?
                .first()
                .ok_or(ExchangeProtocolError::Failed("state missing".to_string()))?;

            // only consider credentials that have finished the issuance flow
            if ![
                CredentialStateEnum::Accepted,
                CredentialStateEnum::Revoked,
                CredentialStateEnum::Suspended,
            ]
            .contains(&credential_state.state)
            {
                continue;
            }

            let claim_schemas = if let Some(claim_schemas) = schema.claim_schemas.clone() {
                claim_schemas
            } else {
                return Err(ExchangeProtocolError::Failed(
                    "claim schema missing".to_string(),
                ));
            };

            if group.claims.iter().all(|requested_claim| {
                !requested_claim.required
                    || claim_schemas.iter().any(|claim_schema| {
                        claim_schema.schema.key.starts_with(&requested_claim.key)
                    })
            }) {
                // For each requested claim
                if group.claims.iter().all(|requested_claim| {
                    claim_schemas.iter().any(|claim_schema| {
                        // Find the claim schema
                        claim_schema.schema.key == requested_claim.key
                            // And make sure a parent element is not an array
                            && claim_schemas
                                .iter()
                                .filter(|other_schema| {
                                    claim_schema
                                        .schema
                                        .key
                                        .starts_with(&format!("{}/", &other_schema.schema.key))
                                })
                                .any(|other_schema| other_schema.schema.array)
                    })
                }) {
                    return Err(ExchangeProtocolError::Failed(
                        "field in array requested".into(),
                    ));
                }

                let claims = credential
                    .claims
                    .as_ref()
                    .ok_or(ExchangeProtocolError::Failed("claims are None".to_string()))?;

                // For each requested claim
                if group.claims.iter().any(|requested_claim| {
                    // Check if all required claims are present
                    if !requested_claim.required {
                        return false;
                    }

                    let schema = claim_schemas.iter().find(|claim_schema| {
                        // Find the claim schema
                        claim_schema.schema.key == requested_claim.key
                    });

                    if let Some(schema) = schema {
                        if object_datatypes.contains(schema.schema.data_type.as_str()) {
                            return false;
                        }

                        // Find if claim is present
                        !claims.iter().any(|claim| {
                            if let Some(schema) = claim.schema.as_ref() {
                                schema.key == requested_claim.key
                            } else {
                                false
                            }
                        })
                    } else {
                        false
                    }
                }) {
                    group.inapplicable_credentials.push(credential.to_owned());
                } else {
                    group.applicable_credentials.push(credential.to_owned());
                }

                relevant_credentials.push(credential.to_owned());
            }
        }
    }

    Ok((relevant_credentials, credential_groups))
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

pub fn gather_object_datatypes_from_config(config: &DatatypeConfig) -> HashSet<&str> {
    config
        .iter()
        .filter_map(|(name, fields)| {
            if fields.r#type == DatatypeType::Object {
                Some(name)
            } else {
                None
            }
        })
        .collect()
}
