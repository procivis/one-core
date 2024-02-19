use crate::model::{
    credential::{CredentialId, CredentialState, CredentialStateEnum, UpdateCredentialRequest},
    did::Did,
    history::{History, HistoryAction, HistoryEntityType},
    interaction::Interaction,
    key::Key,
    proof::{self, Proof, ProofId, ProofStateEnum},
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{Credential, CredentialRelations, CredentialStateRelations};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::DidRelations;
use crate::model::organisation::OrganisationRelations;
use crate::provider::transport_protocol::dto::{
    CredentialGroup, CredentialGroupItem, PresentationDefinitionFieldDTO,
};
use crate::provider::transport_protocol::TransportProtocolError;
use crate::repository::credential_repository::CredentialRepository;
use crate::service::credential::dto::CredentialDetailResponseDTO;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

pub(super) fn get_issued_credential_update(
    credential_id: &CredentialId,
    token: &str,
    key: &Key,
) -> UpdateCredentialRequest {
    UpdateCredentialRequest {
        id: credential_id.to_owned(),
        credential: Some(token.bytes().collect()),
        state: Some(CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
        }),
        key: Some(key.id),
        ..Default::default()
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
        last_modified: now,
        host: Some(host),
        data,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn proof_from_handle_invitation(
    proof_id: &ProofId,
    protocol: &str,
    redirect_uri: Option<String>,
    verifier_did: Option<Did>,
    holder_did: Did,
    interaction: Interaction,
    now: OffsetDateTime,
    verifier_key: Option<Key>,
) -> Proof {
    Proof {
        id: proof_id.to_owned(),
        created_date: now,
        last_modified: now,
        issuance_date: now,
        transport: protocol.to_owned(),
        redirect_uri,
        state: Some(vec![proof::ProofState {
            created_date: now,
            last_modified: now,
            state: ProofStateEnum::Pending,
        }]),
        schema: None,
        claims: None,
        verifier_did,
        holder_did: Some(holder_did),
        interaction: Some(interaction),
        verifier_key,
    }
}

pub fn credential_model_to_credential_dto(
    credentials: Vec<Credential>,
) -> Result<Vec<CredentialDetailResponseDTO>, TransportProtocolError> {
    credentials
        .into_iter()
        .map(|credential| credential.try_into())
        .collect::<Result<Vec<CredentialDetailResponseDTO>, _>>()
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))
}

pub async fn get_relevant_credentials(
    credential_repository: &Arc<dyn CredentialRepository>,
    mut credential_groups: Vec<CredentialGroup>,
    requested_claims: Vec<String>,
) -> Result<(Vec<Credential>, Vec<CredentialGroup>), TransportProtocolError> {
    let relevant_credentials = credential_repository
        .get_credentials_by_claim_names(
            requested_claims.clone(),
            &CredentialRelations {
                state: Some(CredentialStateRelations::default()),
                issuer_did: Some(DidRelations::default()),
                claims: Some(ClaimRelations {
                    schema: Some(ClaimSchemaRelations::default()),
                }),
                schema: Some(CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    organisation: Some(OrganisationRelations::default()),
                }),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

    let mut mentioned_credential_ids: HashSet<CredentialId> = HashSet::new();
    for group in &mut credential_groups {
        for credential in &relevant_credentials {
            let credential_state = credential
                .state
                .as_ref()
                .ok_or(TransportProtocolError::Failed("state missing".to_string()))?
                .first()
                .ok_or(TransportProtocolError::Failed("state missing".to_string()))?;

            // only consider credentials that have finished the issuance flow
            if credential_state.state != CredentialStateEnum::Accepted
                && credential_state.state != CredentialStateEnum::Revoked
            {
                continue;
            }

            let claim_schemas = credential
                .claims
                .as_ref()
                .ok_or(TransportProtocolError::Failed("claims missing".to_string()))?
                .iter()
                .map(|claim| {
                    claim
                        .schema
                        .as_ref()
                        .ok_or(TransportProtocolError::Failed("schema missing".to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if group.claims.iter().all(|requested_claim| {
                claim_schemas
                    .iter()
                    .any(|claim_schema| requested_claim.key == claim_schema.key)
            }) {
                group.applicable_credentials.push(credential.to_owned());
                mentioned_credential_ids.insert(credential.id);
            }
        }
    }

    Ok((
        relevant_credentials
            .into_iter()
            .filter(|credential| mentioned_credential_ids.contains(&credential.id))
            .collect(),
        credential_groups,
    ))
}

pub fn create_presentation_definition_field(
    field: CredentialGroupItem,
    credentials: &[Credential],
) -> Result<PresentationDefinitionFieldDTO, TransportProtocolError> {
    let mut key_map: HashMap<String, String> = HashMap::new();
    let key = field.key;
    for credential in credentials {
        for claim in credential
            .claims
            .as_ref()
            .ok_or(TransportProtocolError::Failed(
                "credential claims is None".to_string(),
            ))?
        {
            if claim
                .schema
                .as_ref()
                .ok_or(TransportProtocolError::Failed(
                    "claim schema is None".to_string(),
                ))?
                .key
                == key
            {
                key_map.insert(credential.id.to_string(), key.clone());
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

pub(super) fn credential_accepted_history_event(credential: Credential) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Accepted,
        entity_id: credential.id.into(),
        entity_type: HistoryEntityType::Credential,
        organisation: credential.schema.and_then(|s| s.organisation),
    }
}
