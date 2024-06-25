mod mapper;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use dto_mapper::convert_inner;
use shared_types::CredentialId;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use self::mapper::{
    get_base_url, get_proof_claim_schemas_from_proof, presentation_definition_from_proof,
    remote_did_from_value,
};
use super::mapper::get_relevant_credentials_to_credential_schemas;
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::CoreConfig;
use crate::model::claim::{Claim, ClaimId};
use crate::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations, LayoutType,
};
use crate::model::did::{Did, DidRelations, KeyRole};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::FormatPresentationCtx;
use crate::provider::exchange_protocol::dto::{
    ConnectVerifierResponse, CredentialGroup, CredentialGroupItem,
    PresentationDefinitionResponseDTO, PresentedCredential, ProofClaimSchema, SubmitIssuerResponse,
};
use crate::provider::exchange_protocol::mapper::{
    interaction_from_handle_invitation, proof_from_handle_invitation,
};
use crate::provider::exchange_protocol::{ExchangeProtocol, ExchangeProtocolError};
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::error::DataLayerError;
use crate::repository::interaction_repository::InteractionRepository;
use crate::service::credential::dto::{
    DetailCredentialClaimResponseDTO, DetailCredentialClaimValueResponseDTO,
};
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::ssi_holder::dto::InvitationResponseDTO;
use crate::service::ssi_issuer::dto::ConnectIssuerResponseDTO;

const REDIRECT_URI_QUERY_PARAM_KEY: &str = "redirect_uri";

pub(crate) struct ProcivisTemp {
    client: reqwest::Client,
    base_url: Option<String>,
    credential_repository: Arc<dyn CredentialRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    did_repository: Arc<dyn DidRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    config: Arc<CoreConfig>,
}

impl ProcivisTemp {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_url: Option<String>,
        credential_repository: Arc<dyn CredentialRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        did_repository: Arc<dyn DidRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
            credential_repository,
            interaction_repository,
            credential_schema_repository,
            did_repository,
            formatter_provider,
            key_provider,
            config,
        }
    }
}

enum InvitationType {
    CredentialIssuance,
    ProofRequest { proof_id: String, protocol: String },
}

fn categorize_url(url: &Url) -> Result<InvitationType, ExchangeProtocolError> {
    let query_value_for = |query_name| {
        url.query_pairs()
            .find_map(|(k, v)| (k == query_name).then_some(v))
    };

    let protocol = query_value_for("protocol")
        .ok_or(ExchangeProtocolError::Failed(
            "Missing protocol query param".to_string(),
        ))?
        .to_string();

    if query_value_for("credential").is_some() {
        return Ok(InvitationType::CredentialIssuance);
    } else if let Some(proof) = query_value_for("proof") {
        return Ok(InvitationType::ProofRequest {
            proof_id: proof.to_string(),
            protocol,
        });
    }

    Err(ExchangeProtocolError::Failed("Invalid Query".to_owned()))
}

#[async_trait]
impl ExchangeProtocol for ProcivisTemp {
    fn detect_invitation_type(
        &self,
        url: &Url,
    ) -> Option<crate::provider::exchange_protocol::dto::InvitationType> {
        let r#type = categorize_url(url).ok()?;
        Some(match r#type {
            InvitationType::CredentialIssuance { .. } => {
                crate::provider::exchange_protocol::dto::InvitationType::CredentialIssuance
            }
            InvitationType::ProofRequest { .. } => {
                crate::provider::exchange_protocol::dto::InvitationType::ProofRequest
            }
        })
    }

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        let invitation_type = categorize_url(&url)?;

        let base_url = get_base_url(&url)?;

        let redirect_uri = url
            .query_pairs()
            .filter(|(k, _)| k == REDIRECT_URI_QUERY_PARAM_KEY)
            .map(|(_, v)| v.to_string())
            .next();

        let response = self
            .client
            .post(url)
            .send()
            .await
            .map_err(ExchangeProtocolError::HttpRequestError)?;

        let response = response
            .error_for_status()
            .map_err(ExchangeProtocolError::HttpRequestError)?;

        Ok(match invitation_type {
            InvitationType::CredentialIssuance { .. } => {
                let issuer_response = response
                    .json()
                    .await
                    .map_err(ExchangeProtocolError::HttpResponse)?;

                handle_credential_invitation(self, base_url, organisation, issuer_response).await?
            }
            InvitationType::ProofRequest { proof_id, protocol } => {
                let proof_request = response
                    .json()
                    .await
                    .map_err(ExchangeProtocolError::HttpResponse)?;

                handle_proof_invitation(
                    self,
                    base_url,
                    proof_id,
                    proof_request,
                    &protocol,
                    organisation,
                    redirect_uri,
                )
                .await?
            }
        })
    }

    async fn reject_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError> {
        let mut url = super::get_base_url_from_interaction(proof.interaction.as_ref())?;
        url.set_path("/ssi/temporary-verifier/v1/reject");
        url.set_query(Some(&format!("proof={}", proof.id)));

        let response = self
            .client
            .post(url)
            .send()
            .await
            .map_err(ExchangeProtocolError::HttpRequestError)?;
        response
            .error_for_status()
            .map_err(ExchangeProtocolError::HttpRequestError)?;

        Ok(())
    }

    async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<(), ExchangeProtocolError> {
        let presentation_formatter = self
            .formatter_provider
            .get_formatter("JWT")
            .ok_or_else(|| ExchangeProtocolError::Failed("JWT formatter not found".to_string()))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(key, jwk_key_id)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let tokens: Vec<String> = credential_presentations
            .into_iter()
            .map(|presented_credential| presented_credential.presentation)
            .collect();

        let presentation = presentation_formatter
            .format_presentation(
                &tokens,
                &holder_did.did,
                &key.key_type,
                auth_fn,
                FormatPresentationCtx::empty(),
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let mut url = super::get_base_url_from_interaction(proof.interaction.as_ref())?;
        url.set_path("/ssi/temporary-verifier/v1/submit");
        url.set_query(Some(&format!(
            "proof={}&didValue={}",
            proof.id, holder_did.did
        )));

        let response = self
            .client
            .post(url)
            .body(presentation)
            .send()
            .await
            .map_err(ExchangeProtocolError::HttpRequestError)?;
        response
            .error_for_status()
            .map_err(ExchangeProtocolError::HttpRequestError)?;

        Ok(())
    }

    async fn accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        _key: &Key,
        _jwk_key_id: Option<String>,
    ) -> Result<SubmitIssuerResponse, ExchangeProtocolError> {
        let mut url = super::get_base_url_from_interaction(credential.interaction.as_ref())?;
        url.set_path("/ssi/temporary-issuer/v1/submit");
        url.set_query(Some(&format!(
            "credentialId={}&didValue={}",
            credential.id, holder_did.did
        )));

        let response = self
            .client
            .post(url)
            .send()
            .await
            .map_err(ExchangeProtocolError::HttpRequestError)?;
        let response = response
            .error_for_status()
            .map_err(ExchangeProtocolError::HttpRequestError)?;
        let response_value = response
            .text()
            .await
            .map_err(ExchangeProtocolError::HttpRequestError)?;

        serde_json::from_str(&response_value).map_err(ExchangeProtocolError::JsonError)
    }

    async fn reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        let mut url = super::get_base_url_from_interaction(credential.interaction.as_ref())?;
        url.set_path("/ssi/temporary-issuer/v1/reject");
        url.set_query(Some(&format!("credentialId={}", credential.id)));

        let response = self
            .client
            .post(url)
            .send()
            .await
            .map_err(ExchangeProtocolError::HttpRequestError)?;
        response
            .error_for_status()
            .map_err(ExchangeProtocolError::HttpRequestError)?;

        Ok(())
    }

    async fn share_credential(
        &self,
        credential: &Credential,
    ) -> Result<String, ExchangeProtocolError> {
        let base_url = self
            .base_url
            .as_ref()
            .ok_or(ExchangeProtocolError::MissingBaseUrl)?;
        let connect_url = format!("{}/ssi/temporary-issuer/v1/connect", base_url);
        let mut url =
            Url::parse(&connect_url).map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("protocol", &credential.exchange);
        pairs.append_pair("credential", &credential.id.to_string());

        if let Some(redirect_uri) = credential.redirect_uri.as_ref() {
            pairs.append_pair("redirect_uri", redirect_uri);
        }

        let url = pairs.finish();

        Ok(url.to_string())
    }

    async fn share_proof(&self, proof: &Proof) -> Result<String, ExchangeProtocolError> {
        let base_url = self
            .base_url
            .as_ref()
            .ok_or(ExchangeProtocolError::MissingBaseUrl)?;
        let connect_url = format!("{}/ssi/temporary-verifier/v1/connect", base_url);
        let mut url =
            Url::parse(&connect_url).map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("protocol", &proof.exchange);
        pairs.append_pair("proof", &proof.id.to_string());

        if let Some(redirect_uri) = proof.redirect_uri.as_ref() {
            pairs.append_pair("redirect_uri", redirect_uri);
        }

        let url = pairs.finish();

        Ok(url.to_string())
    }

    async fn get_presentation_definition(
        &self,
        proof: &Proof,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        let requested_claims = get_proof_claim_schemas_from_proof(proof)?;
        let mut credential_groups: Vec<CredentialGroup> = vec![];
        let mut group_id_to_schema_id: HashMap<String, String> = HashMap::new();

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "interaction is None".to_string(),
            ))?;
        let proof_claim_schemas: Vec<ProofClaimSchema> =
            serde_json::from_slice(interaction.data.as_ref().ok_or(
                ExchangeProtocolError::Failed("interaction.data is None".to_string()),
            )?)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
        let allowed_formats: HashSet<&str> = proof_claim_schemas
            .iter()
            .map(|proof_claim_schema| proof_claim_schema.credential_schema.format.as_str())
            .collect();

        for requested_claim in requested_claims {
            let group_id = requested_claim.credential_schema.id;
            let credential_group_item = CredentialGroupItem {
                id: requested_claim.id,
                key: requested_claim.key,
                required: requested_claim.required,
            };

            if let Some(group) = credential_groups
                .iter_mut()
                .find(|group| group.id == group_id)
            {
                group.claims.push(credential_group_item);
            } else {
                group_id_to_schema_id.insert(
                    group_id.clone(),
                    requested_claim.credential_schema.schema_id,
                );
                credential_groups.push(CredentialGroup {
                    id: group_id,
                    name: Some(requested_claim.credential_schema.name),
                    purpose: None,
                    claims: vec![credential_group_item],
                    applicable_credentials: vec![],
                    validity_credential_nbf: None,
                });
            }
        }

        let (credentials, credential_groups) = get_relevant_credentials_to_credential_schemas(
            &self.credential_repository,
            credential_groups,
            group_id_to_schema_id,
            &allowed_formats,
        )
        .await?;

        presentation_definition_from_proof(proof, credentials, credential_groups, &self.config)
    }
}

async fn handle_credential_invitation(
    deps: &ProcivisTemp,
    base_url: Url,
    organisation: Organisation,
    issuer_response: ConnectIssuerResponseDTO,
) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
    let now = OffsetDateTime::now_utc();
    let credential_schema = match deps
        .credential_schema_repository
        .get_by_schema_id_and_organisation(
            &issuer_response.schema.schema_id,
            organisation.id,
            &Default::default(),
        )
        .await
        .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?
    {
        Some(credential_schema) => {
            if credential_schema.schema_type != issuer_response.schema.schema_type.into() {
                return Err(ExchangeProtocolError::IncorrectCredentialSchemaType);
            }

            deps.credential_schema_repository
                .get_credential_schema(
                    &credential_schema.id,
                    &CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                        organisation: Some(Default::default()),
                    },
                )
                .await
                .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?
                .ok_or(ExchangeProtocolError::Failed(
                    "Credential schema error".to_string(),
                ))?
        }
        None => {
            let credential_schema = CredentialSchema {
                id: issuer_response.schema.id,
                deleted_at: None,
                created_date: now,
                last_modified: now,
                name: issuer_response.schema.name,
                format: issuer_response.schema.format,
                revocation_method: issuer_response.schema.revocation_method,
                wallet_storage_type: issuer_response.schema.wallet_storage_type,
                layout_type: issuer_response
                    .schema
                    .layout_type
                    .unwrap_or(LayoutType::Card),
                layout_properties: convert_inner(issuer_response.schema.layout_properties),
                schema_id: issuer_response.schema.schema_id,
                schema_type: issuer_response.schema.schema_type.into(),
                claim_schemas: Some(extract_claim_schemas_from_incoming(
                    &issuer_response.schema.claims,
                    now,
                    "",
                )?),
                organisation: Some(organisation.to_owned()),
            };

            let _ = deps
                .credential_schema_repository
                .create_credential_schema(credential_schema.clone())
                .await
                .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

            credential_schema
        }
    };

    // insert issuer did if not yet known
    let issuer_did_value = issuer_response.issuer_did.did;
    let issuer_did = remote_did_from_value(issuer_did_value.to_owned(), organisation);
    let did_insert_result = deps.did_repository.create_did(issuer_did.clone()).await;
    let issuer_did = match did_insert_result {
        Ok(_) => issuer_did,
        Err(DataLayerError::AlreadyExists) => {
            let issuer_did = deps
                .did_repository
                .get_did_by_value(&issuer_did_value, &DidRelations::default())
                .await
                .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

            issuer_did.ok_or(ExchangeProtocolError::Failed(format!(
                "Error while getting DID {issuer_did_value}"
            )))?
        }
        Err(e) => {
            return Err(ExchangeProtocolError::Failed(format!(
                "Data layer error {e}"
            )))
        }
    };

    let interaction = interaction_from_handle_invitation(base_url, None, now);
    let interaction_id = deps
        .interaction_repository
        .create_interaction(interaction.clone())
        .await
        .map_err(|error| {
            ExchangeProtocolError::Failed(format!("Error while creating interaction {error}"))
        })?;

    // create credential
    let credential_id = issuer_response.id;
    let incoming_claims = issuer_response.claims;

    let claim_schemas =
        credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "claim_schemas is None".to_string(),
            ))?;

    let claims = incoming_claims
        .iter()
        .map(|value| unnest_incoming_claim(credential_id, value, claim_schemas, now, ""))
        .collect::<Result<Vec<Vec<_>>, ExchangeProtocolError>>()?
        .into_iter()
        .flatten()
        .collect();

    let credential = Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri: issuer_response.redirect_uri,
        role: CredentialRole::Holder,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Pending,
            suspend_end_date: None,
        }]),
        claims: Some(claims),
        issuer_did: Some(issuer_did),
        holder_did: None,
        schema: Some(credential_schema),
        interaction: Some(interaction),
        revocation_list: None,
        key: None,
    };

    Ok(InvitationResponseDTO::Credential {
        credentials: vec![credential],
        interaction_id,
    })
}

fn extract_claim_schemas_from_incoming(
    incoming_claims: &[CredentialClaimSchemaDTO],
    now: OffsetDateTime,
    prefix: &str,
) -> Result<Vec<CredentialSchemaClaim>, ExchangeProtocolError> {
    let mut result = vec![];

    incoming_claims.iter().try_for_each(|incoming_claim| {
        let key = format!("{prefix}{}", incoming_claim.key);
        result.push(CredentialSchemaClaim {
            schema: ClaimSchema {
                id: incoming_claim.id,
                key: key.to_owned(),
                data_type: incoming_claim.datatype.to_owned(),
                created_date: now,
                last_modified: now,
                array: false,
            },
            required: incoming_claim.required,
        });

        let nested_claims = &incoming_claim.claims;
        if !nested_claims.is_empty() {
            result.extend(extract_claim_schemas_from_incoming(
                nested_claims,
                now,
                &format!("{key}{NESTED_CLAIM_MARKER}"),
            )?);
        }

        Ok(())
    })?;

    Ok(result)
}

fn unnest_incoming_claim(
    credential_id: CredentialId,
    incoming_claim: &DetailCredentialClaimResponseDTO,
    claim_schemas: &[CredentialSchemaClaim],
    now: OffsetDateTime,
    prefix: &str,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    match &incoming_claim.value {
        DetailCredentialClaimValueResponseDTO::String(value) => {
            let expected_key = format!("{prefix}{}", incoming_claim.schema.key);

            let current_claim_schema = claim_schemas
                .iter()
                .find(|claim_schema| claim_schema.schema.key == expected_key)
                .ok_or(ExchangeProtocolError::Failed(format!(
                    "missing claim schema with key {expected_key}",
                )))?;
            Ok(vec![Claim {
                id: ClaimId::new_v4(),
                credential_id,
                path: current_claim_schema.schema.key.to_owned(),
                schema: Some(current_claim_schema.schema.to_owned()),
                value: value.to_owned(),
                created_date: now,
                last_modified: now,
            }])
        }
        DetailCredentialClaimValueResponseDTO::Nested(value) => {
            let result = value
                .iter()
                .map(|value| {
                    unnest_incoming_claim(
                        credential_id,
                        value,
                        claim_schemas,
                        now,
                        &format!("{prefix}{}{NESTED_CLAIM_MARKER}", incoming_claim.schema.key),
                    )
                })
                .collect::<Result<Vec<Vec<_>>, ExchangeProtocolError>>()?
                .into_iter()
                .flatten()
                .collect();
            Ok(result)
        }
    }
}

async fn handle_proof_invitation(
    deps: &ProcivisTemp,
    base_url: Url,
    proof_id: String,
    proof_request: ConnectVerifierResponse,
    protocol: &str,
    organisation: Organisation,
    redirect_uri: Option<String>,
) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
    let verifier_did_result = deps
        .did_repository
        .get_did_by_value(&proof_request.verifier_did, &DidRelations::default())
        .await
        .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

    let now = OffsetDateTime::now_utc();
    let verifier_did = match verifier_did_result {
        Some(did) => did,
        None => {
            let id = Uuid::new_v4();
            let new_did = Did {
                id: id.into(),
                created_date: now,
                last_modified: now,
                name: format!("verifier {id}"),
                did: proof_request.verifier_did,
                did_type: crate::model::did::DidType::Remote,
                did_method: "KEY".to_owned(),
                keys: None,
                organisation: Some(organisation),
                deactivated: false,
            };
            deps.did_repository
                .create_did(new_did.clone())
                .await
                .map_err(|error| {
                    ExchangeProtocolError::Failed(format!("Data layer error {error}"))
                })?;

            new_did
        }
    };

    let verifier_key = verifier_did
        .keys
        .as_ref()
        .map(|vec| {
            vec.iter()
                .find(|f| f.role == KeyRole::AssertionMethod)
                .map(|key| key.key.to_owned())
        })
        .and_then(|key| key);

    let data = serde_json::to_string(&proof_request.claims)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?
        .as_bytes()
        .to_vec();

    let interaction = interaction_from_handle_invitation(base_url, Some(data), now);

    let interaction_id = deps
        .interaction_repository
        .create_interaction(interaction.clone())
        .await
        .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

    let proof_id: Uuid = proof_id
        .parse()
        .map_err(|_| ExchangeProtocolError::Failed("Cannot parse proof id".to_string()))?;

    let proof = proof_from_handle_invitation(
        &proof_id.into(),
        protocol,
        redirect_uri,
        Some(verifier_did),
        interaction,
        now,
        verifier_key,
    );

    Ok(InvitationResponseDTO::ProofRequest {
        interaction_id,
        proof: Box::new(proof),
    })
}

#[cfg(test)]
mod test;
