use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::time::Duration;

use itertools::Itertools;
use one_dto_mapper::convert_inner;
use serde_json::Value;
use shared_types::{CredentialId, CredentialSchemaId, EcosystemId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateProofRequestDTO, ProofClaimDTO, ProofClaimValueDTO, ProofDetailResponseDTO,
    ProofFilterParamsDTO, ProofFilterValue, ProofInputDTO, ProofListItemResponseDTO,
    TransactionDataResponseDTO,
};
use super::error::ProofServiceError;
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::mapper::{NESTED_CLAIM_MARKER, NESTED_CLAIM_MARKER_STR};
use crate::model::certificate::Certificate;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::history::{History, TrustResolutionResult};
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::proof::{Proof, ProofClaim, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::ecosystem::model::{TrustDetail, TrustDetailInfo};
use crate::provider::verification_protocol::openid4vp::model::{
    CommonVerifierInteractionContent, TransactionDataRequest,
};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::service::certificate::mapper::certificate_to_response_dto;
use crate::service::common_mapper::recorded_ecosystem_outcomes;
use crate::service::credential::dto::{
    CredentialAttestationBlobs, CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO,
    TrustInformation,
};
use crate::service::credential::mapper::{
    credential_detail_response_from_model, get_credential_trust_information,
};
use crate::service::credential_schema::dto::CredentialSchemaListItemResponseDTO;
use crate::service::credential_schema::mapper::to_credential_schema_list_response;
use crate::service::proof_schema::dto::ProofClaimSchemaResponseDTO;

fn build_claim_from_credential_claims(
    claims: &[ClaimSchema],
    key: &str,
    path: String,
    required: bool,
) -> Result<ProofClaimDTO, ProofServiceError> {
    let claim_schema = &claims
        .iter()
        .find(|claim_schema| claim_schema.key == key)
        .ok_or(ProofServiceError::MappingError(
            "nested claim is not found by key".into(),
        ))?;
    Ok(ProofClaimDTO {
        schema: ProofClaimSchemaResponseDTO {
            id: claim_schema.id,
            requested: true,
            required,
            key: claim_schema.key.to_owned(),
            data_type: claim_schema.data_type.to_owned(),
            claims: vec![],
            array: claim_schema.array,
        },
        path,
        value: Some(ProofClaimValueDTO::Claims(vec![])),
    })
}

fn get_or_insert_proof_container_claim<'a>(
    proof_claims: &'a mut Vec<ProofClaimDTO>,
    path: &str,
    original_key: &str,
    credential_claim_schemas: &[ClaimSchema],
    required: bool,
) -> Result<&'a mut ProofClaimDTO, ProofServiceError> {
    match path.rsplit_once(NESTED_CLAIM_MARKER) {
        // It's a nested claim
        Some((prefix, _)) => {
            let parent_claim = get_or_insert_proof_container_claim(
                proof_claims,
                prefix,
                original_key,
                credential_claim_schemas,
                required,
            )?;

            let Some(ProofClaimValueDTO::Claims(claims)) = &mut parent_claim.value else {
                return Err(ProofServiceError::MappingError(
                    "Parent claim can not have a text value or be empty".into(),
                ));
            };

            if let Some(i) = claims.iter().position(|claim| claim.path == path) {
                Ok(claims
                    .get_mut(i)
                    .ok_or_else(|| ProofServiceError::MappingError("invalid index".into()))?)
            } else {
                let key = from_path_to_key(path, original_key);
                let mut claim = build_claim_from_credential_claims(
                    credential_claim_schemas,
                    &key,
                    path.into(),
                    required,
                )?;

                // Individual array elements should not have the array flag in nested representation.
                // This adjustment is consistent with the adjustment on the credential detail endpoint.
                if parent_claim.schema.array {
                    claim.schema.array = false;
                }

                claims.push(claim);
                let last = claims.len() - 1;
                Ok(claims
                    .get_mut(last)
                    .ok_or_else(|| ProofServiceError::MappingError("invalid index".into()))?)
            }
        }
        // It's a root
        None => {
            if let Some(i) = proof_claims
                .iter()
                .position(|claim| claim.schema.key == path)
            {
                Ok(proof_claims
                    .get_mut(i)
                    .ok_or_else(|| ProofServiceError::MappingError("invalid index".into()))?)
            } else {
                proof_claims.push(build_claim_from_credential_claims(
                    credential_claim_schemas,
                    path,
                    path.into(),
                    required,
                )?);
                let last = proof_claims.len() - 1;
                Ok(proof_claims
                    .get_mut(last)
                    .ok_or_else(|| ProofServiceError::MappingError("invalid index".into()))?)
            }
        }
    }
}

pub(super) async fn list_item_from_proof(
    value: Proof,
) -> Result<ProofListItemResponseDTO, ProofServiceError> {
    let schema = match value.schema {
        Some(schema) => Some(schema.as_ref().await?.to_owned()),
        None => None,
    };

    let retain_until_date = match (value.completed_date, &schema) {
        (Some(completed_date), Some(schema)) if schema.expire_duration != 0 => {
            Some(completed_date + Duration::from_secs(schema.expire_duration as _))
        }
        _ => None,
    };

    let verifier_identifier = match value.verifier_identifier {
        Some(verifier_identifier) => Some(verifier_identifier.as_ref().await?.to_owned()),
        None => None,
    };

    Ok(ProofListItemResponseDTO {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        requested_date: value.requested_date,
        retain_until_date,
        transport: value.transport,
        completed_date: value.completed_date,
        engagement: value.engagement,
        verifier: convert_inner(verifier_identifier),
        protocol: value.protocol,
        state: value.state,
        role: value.role,
        schema: convert_inner(schema),
        profile: value.profile,
        webhook_destination_url: value.webhook_url,
        redirect_uri: value.redirect_uri,
        ecosystem: value.ecosystem,
    })
}

pub(super) async fn get_verifier_proof_detail(
    proof: Proof,
    config: &CoreConfig,
    claims_removed_event: Option<History>,
    credential_repository: &dyn CredentialRepository,
    formatter_provider: &dyn CredentialFormatterProvider,
    ecosystem_provider: &dyn EcosystemDirectory,
    history_repository: &dyn HistoryRepository,
) -> Result<ProofDetailResponseDTO, ProofServiceError> {
    let schema = proof
        .schema
        .as_ref()
        .ok_or(ProofServiceError::MappingError(
            "schema is None".to_string(),
        ))?
        .as_ref()
        .await?;

    let claims = proof.claims.as_ref().await?;

    let mut credential_for_credential_schema: HashMap<
        CredentialSchemaId,
        CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>,
    > = HashMap::new();

    let mut credential_for_schema_model: HashMap<CredentialSchemaId, Credential> = HashMap::new();
    for proof_claim in &claims {
        let credential = proof_claim.credential.as_ref().await?.to_owned();
        let Credential::Verifier { common, .. } = &credential else {
            return Err(ProofServiceError::MappingError(
                "Expected a verifier credential".into(),
            ));
        };
        credential_for_schema_model.insert(common.schema.id(), credential);
    }

    for (credential_schema_id, credential) in credential_for_schema_model {
        // trust is per credential: its own ecosystem, not the one of the proof
        let trust_information = get_credential_trust_information(
            &credential,
            None,
            ecosystem_provider,
            history_repository,
        )
        .await
        .error_while("getting credential trust information")?;

        let claims = credential.claims().as_ref().await?.to_owned();
        let credential_detail = credential_detail_response_from_model(
            credential,
            claims,
            config,
            CredentialAttestationBlobs::default(),
            trust_information,
            None,
            credential_repository,
            formatter_provider,
            None,
        )
        .await
        .error_while("creating credential detail")?;

        credential_for_credential_schema.insert(credential_schema_id, credential_detail);
    }

    let proof_input_schemas = schema.input_schemas.as_ref().await?;
    if proof_input_schemas.is_empty() {
        return Err(ProofServiceError::MappingError(
            "input_schemas are missing".to_string(),
        ));
    }

    let mut proof_inputs = vec![];

    for input_schema in &proof_input_schemas {
        let mut input_claim_schemas = input_schema.claim_schemas.as_ref().await?.clone();
        let credential_schema = input_schema.credential_schema.as_ref().await?;
        let credential_claim_schemas = credential_schema.claim_schemas.as_ref().await?;

        // construct generated proof input claim schemas that are nested children of explicit input_claim_schemas
        // in order to have all inputs available later to map to particular shared claims
        let object_nested_claims = input_claim_schemas
            .iter()
            .map(|claim| {
                config
                    .datatype
                    .get_fields(&claim.schema.data_type)
                    .map(|field| (claim, field.r#type))
            })
            .collect::<Result<Vec<_>, _>>()
            .error_while("getting datatypes")?
            .into_iter()
            // only object claim schemas can have nested claim schemas
            .filter(|(_, r#type)| r#type == &DatatypeType::Object)
            .flat_map(|(parent_input_claim, _)| {
                credential_claim_schemas
                    .iter()
                    .filter(|c| {
                        c.key.starts_with(&format!(
                            "{}{NESTED_CLAIM_MARKER}",
                            parent_input_claim.schema.key
                        ))
                    })
                    .enumerate()
                    .map(|(i, c)| {
                        // nested claims are required if the explicitly requested object parent is required
                        // and all parents on the path to the requested object are mandatory in the credential schema
                        let required = parent_input_claim.required
                            && c.required
                            && credential_claim_schemas
                                .iter()
                                .filter(|claim_in_between| {
                                    claim_in_between.key.starts_with(&format!(
                                        "{}{NESTED_CLAIM_MARKER}",
                                        parent_input_claim.schema.key
                                    )) && c.key.starts_with(&format!(
                                        "{}{NESTED_CLAIM_MARKER}",
                                        claim_in_between.key
                                    ))
                                })
                                .all(|claim_in_between| claim_in_between.required);

                        ProofInputClaimSchema {
                            schema: c.clone(),
                            required,
                            order: i as u32,
                        }
                    })
            })
            .collect::<Vec<_>>();

        input_claim_schemas.extend(object_nested_claims);

        let mut proof_input_claims = nest_proof_claims(
            &claims,
            &credential_claim_schemas,
            Some(&input_claim_schemas),
        )
        .await?;

        input_claim_schemas
            .iter()
            .filter(|input_claim| {
                !input_claim_schemas.iter().any(|other_input_claim| {
                    input_claim.schema.key.starts_with(&format!(
                        "{}{NESTED_CLAIM_MARKER}",
                        other_input_claim.schema.key
                    )) && other_input_claim.schema.array
                })
            })
            .try_for_each(|input_claim| {
                match input_claim.schema.key.rsplit_once(NESTED_CLAIM_MARKER) {
                    Some((prefix, _)) => {
                        let parent_proof_claim = get_or_insert_proof_container_claim(
                            &mut proof_input_claims,
                            prefix,
                            &input_claim.schema.key,
                            &credential_claim_schemas,
                            input_claim.required,
                        )?;

                        if parent_proof_claim.value.is_none() {
                            parent_proof_claim.value = Some(ProofClaimValueDTO::Claims(vec![]));
                        }

                        let Some(ProofClaimValueDTO::Claims(parent_proof_claims)) =
                            &mut parent_proof_claim.value
                        else {
                            return Err(ProofServiceError::MappingError(
                                "Parent claim can not have a text value or be empty".to_string(),
                            ));
                        };

                        if parent_proof_claims
                            .iter()
                            .any(|claim| claim.schema.id == input_claim.schema.id)
                        {
                            return Ok(());
                        }

                        parent_proof_claims.push(ProofClaimDTO {
                            schema: input_claim.clone().into(),
                            path: input_claim.schema.key.clone(),
                            value: None,
                        });
                    }
                    None => {
                        if proof_input_claims
                            .iter()
                            .any(|claim| claim.schema.id == input_claim.schema.id)
                        {
                            return Ok(());
                        }

                        proof_input_claims.push(ProofClaimDTO {
                            schema: input_claim.clone().into(),
                            path: input_claim.schema.key.clone(),
                            value: None,
                        })
                    }
                };

                Ok(())
            })?;

        let credential_schema_dto: CredentialSchemaListItemResponseDTO =
            to_credential_schema_list_response(
                credential_schema.clone(),
                false,
                formatter_provider,
            )
            .await
            .map_err(|e: NestedError| ProofServiceError::MappingError(e.to_string()))?;

        let credential = credential_for_credential_schema
            .get(&credential_schema.id)
            .cloned();
        proof_inputs.push(ProofInputDTO {
            claims: proof_input_claims,
            // the input reports the trust of the credential it holds, issuer included
            trust_information: credential
                .as_ref()
                .and_then(|credential| credential.trust_information.to_owned()),
            credential,
            credential_schema: credential_schema_dto,
        })
    }
    drop(proof_input_schemas);
    drop(claims);

    let redirect_uri = proof.redirect_uri.to_owned();
    let subscriber_information = proof.subscriber_information.to_owned();

    let verifier_certificate = match &proof.verifier_certificate {
        None => None,
        Some(certificate) => Some(
            certificate_to_response_dto(certificate.as_ref().await?.to_owned())
                .await
                .error_while("converting certificate")?,
        ),
    };

    let transaction_data = if proof.role == ProofRole::Verifier {
        verifier_transaction_data(&proof).await?
    } else {
        vec![]
    };

    let organisation_id = schema.organisation.id();
    drop(schema);

    let list_item_response = list_item_from_proof(proof).await?;

    Ok(ProofDetailResponseDTO {
        id: list_item_response.id,
        created_date: list_item_response.created_date,
        last_modified: list_item_response.last_modified,
        requested_date: list_item_response.requested_date,
        retain_until_date: list_item_response.retain_until_date,
        completed_date: list_item_response.completed_date,
        verifier: list_item_response.verifier,
        verifier_certificate,
        engagement: list_item_response.engagement,
        transport: list_item_response.transport,
        protocol: list_item_response.protocol,
        state: list_item_response.state,
        role: list_item_response.role,
        organisation_id,
        schema: list_item_response.schema,
        redirect_uri,
        proof_inputs,
        claims_removed_at: claims_removed_event.map(|event| event.created_date),
        profile: list_item_response.profile,
        webhook_destination_url: list_item_response.webhook_destination_url,
        trust_information: None,
        subscriber_information,
        transaction_data,
        ecosystem: list_item_response.ecosystem,
    })
}

async fn nest_proof_claims(
    flat_claims: &[ProofClaim],
    credential_claim_schemas: &[ClaimSchema],
    input_claim_schemas: Option<&[ProofInputClaimSchema]>,
) -> Result<Vec<ProofClaimDTO>, ProofServiceError> {
    let mut proof_input_claims = vec![];

    for proof_claim in flat_claims {
        let claim_schema = proof_claim.claim.schema.as_ref().await?;

        let mut schema = if let Some(input_claim_schemas) = input_claim_schemas {
            let Some(input_claim_schema) = input_claim_schemas
                .iter()
                .find(|input_claim_schema| input_claim_schema.schema.id == claim_schema.id)
                .cloned()
            else {
                continue;
            };
            ProofClaimSchemaResponseDTO::from(input_claim_schema)
        } else {
            let credential_schema_claim = credential_claim_schemas
                .iter()
                .find(|schema| schema.id == claim_schema.id)
                .ok_or(ProofServiceError::MappingError(format!(
                    "missing credential claim schema with id {}",
                    claim_schema.id
                )))?;

            ProofClaimSchemaResponseDTO {
                id: credential_schema_claim.id,
                key: credential_schema_claim.key.to_owned(),
                data_type: credential_schema_claim.data_type.to_owned(),
                claims: vec![],
                array: credential_schema_claim.array,
                // we don't have that information on holder side, so guessing flags here
                requested: true,
                required: credential_schema_claim.required,
            }
        };

        match (
            proof_claim.claim.path.rsplit_once(NESTED_CLAIM_MARKER),
            &proof_claim.claim.value,
        ) {
            (Some((prefix, _)), Some(_)) => {
                let parent_proof_claim = get_or_insert_proof_container_claim(
                    &mut proof_input_claims,
                    prefix,
                    &claim_schema.key,
                    credential_claim_schemas,
                    schema.required,
                )?;

                let Some(ProofClaimValueDTO::Claims(parent_proof_claims)) =
                    &mut parent_proof_claim.value
                else {
                    return Err(ProofServiceError::MappingError(
                        "Parent claim can not have a text value or be empty".to_string(),
                    ));
                };

                // Individual array elements should not have the array flag in nested representation.
                // This adjustment is consistent with the adjustment on the credential detail endpoint.
                if parent_proof_claim.schema.array {
                    schema.array = false;
                }

                parent_proof_claims.push(map_to_proof_claim_value_dto(proof_claim, schema)?);
            }
            (None, Some(_)) => {
                proof_input_claims.push(map_to_proof_claim_value_dto(proof_claim, schema)?)
            }
            (_, None) => {
                // No value -> insert container claims recursively up to the root
                get_or_insert_proof_container_claim(
                    &mut proof_input_claims,
                    &proof_claim.claim.path,
                    &claim_schema.key,
                    credential_claim_schemas,
                    schema.required,
                )?;
            }
        };
    }
    Ok(proof_input_claims)
}

fn map_to_proof_claim_value_dto(
    proof_claim: &ProofClaim,
    schema: ProofClaimSchemaResponseDTO,
) -> Result<ProofClaimDTO, ProofServiceError> {
    Ok(ProofClaimDTO {
        schema,
        path: proof_claim.claim.path.clone(),
        value: Some(ProofClaimValueDTO::Value(
            proof_claim
                .claim
                .value
                .as_ref()
                .ok_or(ProofServiceError::MappingError(format!(
                    "Expected proof claim {} to have value",
                    proof_claim.claim.id
                )))?
                .clone(),
        )),
    })
}

pub(super) async fn get_holder_proof_detail(
    proof: Proof,
    config: &CoreConfig,
    claims_removed_event: Option<History>,
    trust_information: Option<TrustInformation>,
    credential_repository: &dyn CredentialRepository,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<ProofDetailResponseDTO, ProofServiceError> {
    let organisation_id = match (
        proof.verifier_identifier.as_ref(),
        proof.interaction.as_ref(),
    ) {
        (Some(verifier_identifier), _) => verifier_identifier.as_ref().await?.organisation.id(),
        (_, Some(interaction)) => interaction.as_ref().await?.organisation.id(),
        (None, None) => {
            return Err(ProofServiceError::MappingError(
                "Missing organisation".to_string(),
            ));
        }
    };

    let redirect_uri = proof.redirect_uri.to_owned();
    let subscriber_information = proof.subscriber_information.to_owned();

    let mut submitted_credentials: HashMap<
        CredentialId,
        (
            Vec<ProofClaim>,
            CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>,
            CredentialSchema,
        ),
    > = HashMap::new();

    let proof_claims = proof.claims.as_ref().await?;
    for proof_claim in &proof_claims {
        let credential = proof_claim.credential.as_ref().await?;
        let credential_schema = credential.common().schema.as_ref().await?.to_owned();

        match submitted_credentials.entry(credential.common().id) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().0.push(proof_claim.clone());
            }
            Entry::Vacant(entry) => {
                entry.insert((
                    vec![proof_claim.clone()],
                    credential_detail_response_from_model(
                        credential.clone(),
                        crate::mapper::credential::stored_credential_claims(&credential).await?,
                        config,
                        CredentialAttestationBlobs::default(),
                        None,
                        None,
                        credential_repository,
                        formatter_provider,
                        None,
                    )
                    .await
                    .error_while("creating credential detail")?,
                    credential_schema.clone(),
                ));
            }
        }
    }
    drop(proof_claims);

    let mut proof_inputs = vec![];
    for (claims, credential, credential_schema) in submitted_credentials.into_values() {
        let credential_claim_schemas = credential_schema.claim_schemas.as_ref().await?;
        let credential_schema_dto: CredentialSchemaListItemResponseDTO =
            to_credential_schema_list_response(
                credential_schema.clone(),
                false,
                formatter_provider,
            )
            .await
            .map_err(|e: NestedError| ProofServiceError::MappingError(e.to_string()))?;

        proof_inputs.push(ProofInputDTO {
            claims: nest_proof_claims(&claims, &credential_claim_schemas, None).await?,
            trust_information: credential.trust_information.to_owned(),
            credential: Some(credential),
            credential_schema: credential_schema_dto,
        });
    }

    let verifier_certificate = match &proof.verifier_certificate {
        None => None,
        Some(certificate) => Some(
            certificate_to_response_dto(certificate.as_ref().await?.to_owned())
                .await
                .error_while("converting certificate")?,
        ),
    };

    let list_item_response = list_item_from_proof(proof).await?;

    Ok(ProofDetailResponseDTO {
        id: list_item_response.id,
        created_date: list_item_response.created_date,
        last_modified: list_item_response.last_modified,
        requested_date: list_item_response.requested_date,
        retain_until_date: list_item_response.retain_until_date,
        completed_date: list_item_response.completed_date,
        verifier: list_item_response.verifier,
        engagement: list_item_response.engagement,
        verifier_certificate,
        transport: list_item_response.transport,
        protocol: list_item_response.protocol,
        state: list_item_response.state,
        role: list_item_response.role,
        organisation_id,
        schema: list_item_response.schema,
        redirect_uri,
        proof_inputs,
        claims_removed_at: claims_removed_event.map(|event| event.created_date),
        profile: list_item_response.profile,
        webhook_destination_url: list_item_response.webhook_destination_url,
        trust_information,
        subscriber_information,
        transaction_data: vec![],
        ecosystem: list_item_response.ecosystem,
    })
}

#[expect(clippy::too_many_arguments)]
pub(super) fn proof_from_create_request(
    request: CreateProofRequestDTO,
    now: OffsetDateTime,
    schema: ProofSchema,
    transport: String,
    verifier_identifier: Identifier,
    verifier_key: Key,
    verifier_certificate: Option<Certificate>,
    interaction: Option<Interaction>,
) -> Proof {
    Proof {
        ecosystem: request.ecosystem,
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        protocol: request.protocol,
        redirect_uri: request.redirect_uri,
        state: ProofStateEnum::Created,
        role: ProofRole::Verifier,
        requested_date: None,
        completed_date: None,
        profile: request.profile,
        schema: Some(schema.into()),
        transport,
        claims: Default::default(),
        verifier_identifier: Some(verifier_identifier.into()),
        verifier_key: Some(verifier_key.into()),
        verifier_certificate: convert_inner(verifier_certificate),
        interaction: convert_inner(interaction),
        proof_blob_id: None,
        engagement: request.engagement,
        webhook_url: request.webhook_destination_url,
        subscriber_information: request.subscriber_information,
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

async fn verifier_transaction_data(
    proof: &Proof,
) -> Result<Vec<TransactionDataResponseDTO>, ProofServiceError> {
    let Some(interaction) = proof.interaction.as_ref() else {
        return Ok(vec![]);
    };

    let interaction = interaction.as_ref().await?;
    let Some(interaction_data) = &interaction.data else {
        return Ok(vec![]);
    };
    let content = serde_json::from_slice::<CommonVerifierInteractionContent>(interaction_data)
        .map_err(|e| {
            ProofServiceError::MappingError(format!("Failed to parse interaction data: {e}"))
        })?;

    if content.transaction_data.is_empty() {
        return Ok(vec![]);
    }
    let schema = proof
        .schema
        .as_ref()
        .ok_or_else(|| ProofServiceError::MappingError("proof schema is missing".to_string()))?
        .as_ref()
        .await?;
    let inputs = schema.input_schemas.as_ref().await?;
    let mut schema_ids_by_query = HashMap::new();
    for input in &inputs {
        let credential_schema = input.credential_schema.as_ref().await?;
        // Older interactions reference the credential schema directly.
        schema_ids_by_query.insert(credential_schema.id.to_string(), credential_schema.id);
        for format in &credential_schema.formats.as_ref().await? {
            schema_ids_by_query.insert(format.id.to_string(), credential_schema.id);
        }
    }

    content
        .transaction_data
        .into_iter()
        .map(|request| transaction_data_response_from_request(request, &schema_ids_by_query))
        .collect()
}

fn transaction_data_response_from_request(
    request: TransactionDataRequest,
    schema_ids_by_query: &HashMap<String, CredentialSchemaId>,
) -> Result<TransactionDataResponseDTO, ProofServiceError> {
    let credential_schema_ids = request
        .credential_ids
        .iter()
        .map(|id| {
            schema_ids_by_query
                .get(&id.to_string())
                .copied()
                .ok_or_else(|| {
                    ProofServiceError::MappingError(format!(
                        "unknown transaction data query id `{id}`"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unique()
        .collect();

    Ok(TransactionDataResponseDTO {
        r#type: request.r#type,
        credential_schema_ids,
        data: request.data,
    })
}

pub(super) async fn interaction_data_from_proof(proof: &Proof) -> Result<Value, ProofServiceError> {
    let interaction = proof
        .interaction
        .as_ref()
        .ok_or_else(|| ProofServiceError::MappingError("proof interaction is missing".into()))?
        .as_ref()
        .await?;

    let interaction_data = interaction.data.as_ref().ok_or_else(|| {
        ProofServiceError::MappingError("proof interaction data is missing".into())
    })?;

    serde_json::from_slice(interaction_data)
        .map_err(|err| ProofServiceError::MappingError(err.to_string()))
}

impl From<ProofFilterParamsDTO> for ListFilterCondition<ProofFilterValue> {
    fn from(value: ProofFilterParamsDTO) -> Self {
        let organisation_id = ProofFilterValue::OrganisationId(value.organisation_id).condition();

        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let name = value.name.map(|name| {
            ProofFilterValue::Name(StringMatch {
                r#match: get_string_match_type(crate::model::proof::ExactProofFilterColumn::Name),
                value: name,
            })
        });

        let states = value.states.map(ProofFilterValue::States);
        let roles = value.roles.map(ProofFilterValue::Roles);
        let proof_ids = value.ids.map(ProofFilterValue::ProofIds);
        let proof_schema_ids = value.proof_schema_ids.map(ProofFilterValue::ProofSchemaIds);
        let verifier_ids = value.verifier_ids.map(ProofFilterValue::VerifierIds);
        let profiles = value.profiles.map(ProofFilterValue::Profiles);
        let ecosystems = value.ecosystems.map(ProofFilterValue::Ecosystems);

        let created_date_after = value.created_date_after.map(|date| {
            ProofFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            ProofFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            ProofFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            ProofFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let requested_date_after = value.requested_date_after.map(|date| {
            ProofFilterValue::RequestedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let requested_date_before = value.requested_date_before.map(|date| {
            ProofFilterValue::RequestedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let completed_date_after = value.completed_date_after.map(|date| {
            ProofFilterValue::CompletedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let completed_date_before = value.completed_date_before.map(|date| {
            ProofFilterValue::CompletedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        organisation_id
            & name
            & states
            & roles
            & proof_schema_ids
            & verifier_ids
            & proof_ids
            & profiles
            & ecosystems
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
            & requested_date_after
            & requested_date_before
            & completed_date_after
            & completed_date_before
    }
}

/// Trust information recorded by the holder about a verifier
/// Verifiers call [`get_verifier_proof_detail`] instead
pub(super) async fn get_proof_trust_information(
    proof: &Proof,
    ecosystem_provider: &dyn EcosystemDirectory,
    history_repository: &dyn HistoryRepository,
) -> Result<TrustInformation, ProofServiceError> {
    let ecosystem_errors = recorded_ecosystem_outcomes(proof.id.into(), history_repository).await?;

    let Some(ecosystem_id) = &proof.ecosystem else {
        return Ok(TrustInformation {
            received_at: proof.requested_date.unwrap_or(proof.last_modified),
            name: None,
            result: TrustResolutionResult::Untrusted,
            ecosystem_errors,
        });
    };
    let (received_at, name) = match verifier_trust_detail(proof, ecosystem_id, ecosystem_provider)
        .await
    {
        Ok(details) => {
            let TrustDetailInfo::Eudi(info) = details.info;
            (details.received_at, Some(info.name))
        }
        Err(err) => {
            tracing::warn!(%err, "failed to get the verifier trust detail of proof {}", proof.id);
            (proof.requested_date.unwrap_or(proof.last_modified), None)
        }
    };
    Ok(TrustInformation {
        received_at,
        name,
        result: TrustResolutionResult::Trusted,
        ecosystem_errors,
    })
}

async fn verifier_trust_detail(
    proof: &Proof,
    ecosystem_id: &EcosystemId,
    ecosystem_provider: &dyn EcosystemDirectory,
) -> Result<TrustDetail, ProofServiceError> {
    Ok(ecosystem_provider
        .get(ecosystem_id)?
        .verifier_trust_details(&proof.id)
        .await
        .error_while("getting trust detail")?)
}
