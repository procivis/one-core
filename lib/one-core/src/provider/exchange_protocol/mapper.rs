use std::collections::{HashMap, HashSet};

use shared_types::{CredentialId, DidId, OrganisationId, ProofId};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::dto::{CredentialGroup, CredentialGroupItem, PresentationDefinitionFieldDTO};
use super::{ExchangeProtocolError, StorageAccess};
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::{CoreConfig, DatatypeConfig, DatatypeType};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Clearable, Credential, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchemaClaim;
use crate::model::did::Did;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
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
        state: Some(crate::model::credential::CredentialStateEnum::Accepted),
        suspend_end_date: Clearable::DontTouch,
        key: None,
        holder_did_id: Some(holder_did_id),
        issuer_did_id: None,
        interaction: None,
        redirect_uri: None,
        claims: None,
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
        state,
        role: ProofRole::Holder,
        requested_date: Some(now),
        completed_date: None,
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

pub(crate) async fn get_relevant_credentials_to_credential_schemas(
    storage_access: &StorageAccess,
    mut credential_groups: Vec<CredentialGroup>,
    group_id_to_schema_id_mapping: HashMap<String, String>,
    allowed_schema_formats: &HashSet<&str>,
    object_datatypes: &HashSet<&str>,
    organisation_id: OrganisationId,
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
            .get_credentials_by_credential_schema_id(credential_schema_id, organisation_id)
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

            let credential_state = credential.state;

            // only consider credentials that have finished the issuance flow
            if ![
                CredentialStateEnum::Accepted,
                CredentialStateEnum::Revoked,
                CredentialStateEnum::Suspended,
            ]
            .contains(&credential_state)
            {
                continue;
            }

            let claim_schemas = if let Some(claim_schemas) = schema.claim_schemas.as_ref() {
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
                                        .starts_with(&format!("{}{NESTED_CLAIM_MARKER}", &other_schema.schema.key))
                                })
                                .any(|other_schema| other_schema.schema.array)
                    })
                }) {
                    return Err(ExchangeProtocolError::Failed(
                        "field in array requested".into(),
                    ));
                }

                let credential_claims_schemas = credential
                    .claims
                    .as_ref()
                    .ok_or(ExchangeProtocolError::Failed("claims are None".to_string()))?
                    .iter()
                    .map(|claim| {
                        claim.schema.as_ref().ok_or(ExchangeProtocolError::Failed(
                            "claim_schemas are None".to_string(),
                        ))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                // For each required requested claim, check whether such a claim is present
                if group
                    .claims
                    .iter()
                    .filter(|requested_claim| requested_claim.required)
                    .all(|required_claim| {
                        is_requested_claim_present_in_credential(
                            required_claim,
                            &credential_claims_schemas,
                            claim_schemas,
                            object_datatypes,
                        )
                    })
                {
                    group.applicable_credentials.push(credential.to_owned());
                } else {
                    group.inapplicable_credentials.push(credential.to_owned());
                }

                relevant_credentials.push(credential.to_owned());
            }
        }
    }

    Ok((relevant_credentials, credential_groups))
}

fn is_requested_claim_present_in_credential(
    requested_claim: &CredentialGroupItem,
    credential_claims_schemas: &[&ClaimSchema],
    credential_schema_claim_schemas: &[CredentialSchemaClaim],
    object_datatypes: &HashSet<&str>,
) -> bool {
    // Find the claim schema
    let requested_claim_schema = credential_schema_claim_schemas
        .iter()
        .find(|claim_schema| claim_schema.schema.key == requested_claim.key);

    if let Some(requested_claim_schema) = requested_claim_schema {
        // in case a whole object is requested, then we need to search for any claim under this object
        if object_datatypes.contains(requested_claim_schema.schema.data_type.as_str()) {
            credential_claims_schemas.iter().any(|schema| {
                schema
                    .key
                    .starts_with(&format!("{}{NESTED_CLAIM_MARKER}", requested_claim.key))
            })
        } else {
            // a simple claim requested, try to find exact match
            credential_claims_schemas
                .iter()
                .any(|schema| schema.key == requested_claim.key)
        }
    } else {
        // This means the proof request mentions a claim,
        // for which we don't have a claim schema.
        // In such case we also cannot have the desired claim.
        false
    }
}

pub(crate) fn create_presentation_definition_field(
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

pub(crate) fn gather_object_datatypes_from_config(config: &DatatypeConfig) -> HashSet<&str> {
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
