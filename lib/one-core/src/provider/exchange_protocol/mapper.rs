use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use shared_types::{CredentialId, DidId};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::{FormatConfig, FormatType};
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    Credential, CredentialRelations, CredentialState, CredentialStateEnum,
    CredentialStateRelations, UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::{Did, DidRelations};
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{self, Proof, ProofId, ProofStateEnum};
use crate::provider::exchange_protocol::dto::{
    CredentialGroup, CredentialGroupItem, PresentationDefinitionFieldDTO,
};
use crate::provider::exchange_protocol::ExchangeProtocolError;
use crate::repository::credential_repository::CredentialRepository;
use crate::service::credential::dto::CredentialDetailResponseDTO;

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
            state: CredentialStateEnum::Accepted,
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
    interaction: Interaction,
    now: OffsetDateTime,
    verifier_key: Option<Key>,
) -> Proof {
    Proof {
        id: proof_id.to_owned(),
        created_date: now,
        last_modified: now,
        issuance_date: now,
        exchange: protocol.to_owned(),
        redirect_uri,
        state: Some(vec![proof::ProofState {
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

pub fn credential_model_to_credential_dto(
    credentials: Vec<Credential>,
) -> Result<Vec<CredentialDetailResponseDTO>, ExchangeProtocolError> {
    credentials
        .into_iter()
        .map(|credential| credential.try_into())
        .collect::<Result<Vec<CredentialDetailResponseDTO>, _>>()
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
}

pub async fn get_relevant_credentials_to_credential_schemas(
    credential_repository: &Arc<dyn CredentialRepository>,
    mut credential_groups: Vec<CredentialGroup>,
    group_id_to_schema_id_mapping: HashMap<String, String>,
    allowed_schema_formats: &HashSet<&str>,
    format_config: &FormatConfig,
) -> Result<(Vec<Credential>, Vec<CredentialGroup>), ExchangeProtocolError> {
    let mut relevant_credentials: Vec<Credential> = Vec::new();
    for group in &mut credential_groups {
        let credential_schema_id =
            group_id_to_schema_id_mapping
                .get(&group.id)
                .ok_or(ExchangeProtocolError::Failed(
                    "Incorrect group id to credential schema id mapping".to_owned(),
                ))?;

        let relevant_credentials_inner = credential_repository
            .get_credentials_by_credential_schema_id(
                credential_schema_id.to_owned(),
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
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        for credential in &relevant_credentials_inner {
            let schema = credential
                .schema
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed("schema missing".to_string()))?;

            if !allowed_schema_formats
                .iter()
                .any(|allowed_schema_format| allowed_schema_format.starts_with(&schema.format))
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

            if !mdoc_verify_if_only_second_level_claims_are_present(
                &group.claims,
                &schema.format,
                format_config,
            ) {
                continue;
            }

            let claim_schemas = credential
                .claims
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed("claims missing".to_string()))?
                .iter()
                .map(|claim| {
                    claim
                        .schema
                        .as_ref()
                        .ok_or(ExchangeProtocolError::Failed("schema missing".to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if group.claims.iter().all(|requested_claim| {
                claim_schemas
                    .iter()
                    .any(|claim_schema| claim_schema.key.starts_with(&requested_claim.key))
            }) {
                group.applicable_credentials.push(credential.to_owned());
                relevant_credentials.push(credential.to_owned());
            }
        }
    }

    Ok((relevant_credentials, credential_groups))
}

fn mdoc_verify_if_only_second_level_claims_are_present(
    claims: &[CredentialGroupItem],
    format: &str,
    config: &FormatConfig,
) -> bool {
    let is_mdoc = config.iter().any(|(_, fields)| {
        fields.r#type.to_string().starts_with(format) && fields.r#type == FormatType::Mdoc
    });
    if !is_mdoc {
        return true;
    }

    let level_different_than_two = claims
        .iter()
        .any(|claim| claim.key.matches(NESTED_CLAIM_MARKER).count() == 0);
    !level_different_than_two
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

pub(super) fn credential_accepted_history_event(credential: Credential) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Accepted,
        entity_id: Some(credential.id.into()),
        entity_type: HistoryEntityType::Credential,
        metadata: None,
        organisation: credential.schema.and_then(|s| s.organisation),
    }
}