mod mapper;

use async_trait::async_trait;
use std::sync::Arc;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use self::mapper::{
    get_base_url, get_proof_claim_schemas_from_proof, presentation_definition_from_proof,
    remote_did_from_value,
};
use crate::{
    model::{
        claim::{Claim, ClaimId},
        claim_schema::ClaimSchemaRelations,
        credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum},
        credential_schema::{CredentialSchema, CredentialSchemaRelations},
        did::{Did, DidRelations, KeyRole},
        key::Key,
        organisation::Organisation,
        proof::Proof,
    },
    provider::{
        credential_formatter::provider::CredentialFormatterProvider,
        key_storage::provider::KeyProvider,
        transport_protocol::{
            dto::{
                ConnectVerifierResponse, CredentialGroup, CredentialGroupItem,
                PresentationDefinitionResponseDTO, PresentedCredential, SubmitIssuerResponse,
            },
            mapper::{
                get_relevant_credentials, interaction_from_handle_invitation,
                proof_from_handle_invitation,
            },
            TransportProtocol, TransportProtocolError,
        },
    },
    repository::{
        credential_repository::CredentialRepository,
        credential_schema_repository::CredentialSchemaRepository, did_repository::DidRepository,
        error::DataLayerError, interaction_repository::InteractionRepository,
    },
    service::{
        credential::dto::CredentialDetailResponseDTO, ssi_holder::dto::InvitationResponseDTO,
    },
};

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
        }
    }
}

enum InvitationType {
    CredentialIssuance,
    ProofRequest { proof_id: String, protocol: String },
}

fn categorize_url(url: &Url) -> Result<InvitationType, TransportProtocolError> {
    let query_value_for = |query_name| {
        url.query_pairs()
            .find_map(|(k, v)| (k == query_name).then_some(v))
    };

    let protocol = query_value_for("protocol")
        .ok_or(TransportProtocolError::Failed(
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

    Err(TransportProtocolError::Failed("Invalid Query".to_owned()))
}

#[async_trait]
impl TransportProtocol for ProcivisTemp {
    fn detect_invitation_type(
        &self,
        url: &Url,
    ) -> Option<crate::provider::transport_protocol::dto::InvitationType> {
        let r#type = categorize_url(url).ok()?;
        Some(match r#type {
            InvitationType::CredentialIssuance { .. } => {
                crate::provider::transport_protocol::dto::InvitationType::CredentialIssuance
            }
            InvitationType::ProofRequest { .. } => {
                crate::provider::transport_protocol::dto::InvitationType::ProofRequest
            }
        })
    }

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
    ) -> Result<InvitationResponseDTO, TransportProtocolError> {
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
            .map_err(TransportProtocolError::HttpRequestError)?;

        let response = response
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;

        Ok(match invitation_type {
            InvitationType::CredentialIssuance { .. } => {
                let issuer_response = response
                    .json()
                    .await
                    .map_err(TransportProtocolError::HttpResponse)?;

                handle_credential_invitation(self, base_url, organisation, issuer_response).await?
            }
            InvitationType::ProofRequest { proof_id, protocol } => {
                let proof_request = response
                    .json()
                    .await
                    .map_err(TransportProtocolError::HttpResponse)?;

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

    async fn reject_proof(&self, proof: &Proof) -> Result<(), TransportProtocolError> {
        let mut url = super::get_base_url_from_interaction(proof.interaction.as_ref())?;
        url.set_path("/ssi/temporary-verifier/v1/reject");
        url.set_query(Some(&format!("proof={}", proof.id)));

        let response = self
            .client
            .post(url)
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;
        response
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;

        Ok(())
    }

    async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
    ) -> Result<(), TransportProtocolError> {
        let presentation_formatter = self
            .formatter_provider
            .get_formatter("JWT")
            .ok_or_else(|| TransportProtocolError::Failed("JWT formatter not found".to_string()))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(key)
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        let tokens: Vec<String> = credential_presentations
            .into_iter()
            .map(|presented_credential| presented_credential.presentation)
            .collect();

        let presentation = presentation_formatter
            .format_presentation(&tokens, &holder_did.did, &key.key_type, auth_fn, None)
            .await
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

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
            .map_err(TransportProtocolError::HttpRequestError)?;
        response
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;

        Ok(())
    }

    async fn accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        _key: &Key,
    ) -> Result<SubmitIssuerResponse, TransportProtocolError> {
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
            .map_err(TransportProtocolError::HttpRequestError)?;
        let response = response
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;
        let response_value = response
            .text()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;

        serde_json::from_str(&response_value).map_err(TransportProtocolError::JsonError)
    }

    async fn reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), TransportProtocolError> {
        let mut url = super::get_base_url_from_interaction(credential.interaction.as_ref())?;
        url.set_path("/ssi/temporary-issuer/v1/reject");
        url.set_query(Some(&format!("credentialId={}", credential.id)));

        let response = self
            .client
            .post(url)
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;
        response
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;

        Ok(())
    }

    async fn share_credential(
        &self,
        credential: &Credential,
    ) -> Result<String, TransportProtocolError> {
        let base_url = self
            .base_url
            .as_ref()
            .ok_or(TransportProtocolError::MissingBaseUrl)?;
        let connect_url = format!("{}/ssi/temporary-issuer/v1/connect", base_url);
        let mut url =
            Url::parse(&connect_url).map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("protocol", &credential.transport);
        pairs.append_pair("credential", &credential.id.to_string());

        if let Some(redirect_uri) = credential.redirect_uri.as_ref() {
            pairs.append_pair("redirect_uri", redirect_uri);
        }

        let url = pairs.finish();

        Ok(url.to_string())
    }

    async fn share_proof(&self, proof: &Proof) -> Result<String, TransportProtocolError> {
        let base_url = self
            .base_url
            .as_ref()
            .ok_or(TransportProtocolError::MissingBaseUrl)?;
        let connect_url = format!("{}/ssi/temporary-verifier/v1/connect", base_url);
        let mut url =
            Url::parse(&connect_url).map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("protocol", &proof.transport);
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
    ) -> Result<PresentationDefinitionResponseDTO, TransportProtocolError> {
        let requested_claims = get_proof_claim_schemas_from_proof(proof)?;
        let requested_claim_keys: Vec<String> = requested_claims
            .iter()
            .map(|claim_schema| claim_schema.key.to_owned())
            .collect();
        let mut credential_groups: Vec<CredentialGroup> = vec![];
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
                credential_groups.push(CredentialGroup {
                    id: group_id,
                    claims: vec![credential_group_item],
                    applicable_credentials: vec![],
                    validity_credential_nbf: None,
                });
            }
        }
        let (credentials, credential_groups) = get_relevant_credentials(
            &self.credential_repository,
            credential_groups,
            requested_claim_keys,
        )
        .await?;
        presentation_definition_from_proof(proof, credentials, credential_groups)
    }
}

async fn handle_credential_invitation(
    deps: &ProcivisTemp,
    base_url: Url,
    organisation: Organisation,
    issuer_response: CredentialDetailResponseDTO,
) -> Result<InvitationResponseDTO, TransportProtocolError> {
    let input_credential_schema: CredentialSchema = issuer_response.schema.into();
    let credential_schema = match deps
        .credential_schema_repository
        .get_by_schema_id_and_organisation(&input_credential_schema.schema_id, organisation.id)
        .await
        .map_err(|err| TransportProtocolError::Failed(err.to_string()))?
    {
        Some(credential_schema) => {
            if credential_schema.schema_type != input_credential_schema.schema_type {
                return Err(TransportProtocolError::IncorrectCredentialSchemaType);
            }

            deps.credential_schema_repository
                .get_credential_schema(
                    &credential_schema.id,
                    &CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|err| TransportProtocolError::Failed(err.to_string()))?
                .ok_or(TransportProtocolError::Failed(
                    "Credential schema error".to_string(),
                ))?
        }
        None => {
            let mut credential_schema = input_credential_schema;
            credential_schema.organisation = Some(organisation.to_owned());
            credential_schema.claim_schemas = Some(
                issuer_response
                    .claims
                    .iter()
                    .map(|claim| claim.schema.to_owned().into())
                    .collect(),
            );

            let _ = deps
                .credential_schema_repository
                .create_credential_schema(credential_schema.clone())
                .await
                .map_err(|err| TransportProtocolError::Failed(err.to_string()))?;

            credential_schema
        }
    };

    // insert issuer did if not yet known
    let issuer_did_value = issuer_response
        .issuer_did
        .ok_or(TransportProtocolError::Failed(
            "Issuer did not found in response".to_string(),
        ))?
        .did;

    let issuer_did = remote_did_from_value(issuer_did_value.to_owned(), organisation);
    let did_insert_result = deps.did_repository.create_did(issuer_did.clone()).await;
    let issuer_did = match did_insert_result {
        Ok(_) => issuer_did,
        Err(DataLayerError::AlreadyExists) => {
            let issuer_did = deps
                .did_repository
                .get_did_by_value(&issuer_did_value, &DidRelations::default())
                .await
                .map_err(|err| TransportProtocolError::Failed(err.to_string()))?;

            issuer_did.ok_or(TransportProtocolError::Failed(format!(
                "Error while getting DID {issuer_did_value}"
            )))?
        }
        Err(e) => {
            return Err(TransportProtocolError::Failed(format!(
                "Data layer error {e}"
            )))
        }
    };

    let now = OffsetDateTime::now_utc();

    let interaction = interaction_from_handle_invitation(base_url, None, now);
    let interaction_id = deps
        .interaction_repository
        .create_interaction(interaction.clone())
        .await
        .map_err(|error| {
            TransportProtocolError::Failed(format!("Error while creating interaction {error}"))
        })?;

    // create credential
    let credential_id = issuer_response.id;
    let incoming_claims = issuer_response.claims;
    let claims = credential_schema
        .claim_schemas
        .as_ref()
        .ok_or(TransportProtocolError::Failed(
            "claim_schemas is None".to_string(),
        ))?
        .iter()
        .map(
            |claim_schema| -> Result<Option<Claim>, TransportProtocolError> {
                if let Some(value) = incoming_claims
                    .iter()
                    .find(|claim| claim.schema.key == claim_schema.schema.key)
                {
                    Ok(Some(Claim {
                        id: ClaimId::new_v4(),
                        credential_id,
                        schema: Some(claim_schema.schema.to_owned()),
                        value: value.value.to_owned(),
                        created_date: now,
                        last_modified: now,
                    }))
                } else if claim_schema.required {
                    Err(TransportProtocolError::Failed(format!(
                        "Validation Error. Claim key {} missing",
                        &claim_schema.schema.key
                    )))
                } else {
                    Ok(None) // missing optional claim
                }
            },
        )
        .collect::<Result<Vec<Option<Claim>>, TransportProtocolError>>()?
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
        transport: "PROCIVIS_TEMPORARY".to_string(),
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

async fn handle_proof_invitation(
    deps: &ProcivisTemp,
    base_url: Url,
    proof_id: String,
    proof_request: ConnectVerifierResponse,
    protocol: &str,
    organisation: Organisation,
    redirect_uri: Option<String>,
) -> Result<InvitationResponseDTO, TransportProtocolError> {
    let verifier_did_result = deps
        .did_repository
        .get_did_by_value(&proof_request.verifier_did, &DidRelations::default())
        .await
        .map_err(|err| TransportProtocolError::Failed(err.to_string()))?;

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
                    TransportProtocolError::Failed(format!("Data layer error {error}"))
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
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?
        .as_bytes()
        .to_vec();

    let interaction = interaction_from_handle_invitation(base_url, Some(data), now);

    let interaction_id = deps
        .interaction_repository
        .create_interaction(interaction.clone())
        .await
        .map_err(|error| TransportProtocolError::Failed(error.to_string()))?;

    let proof_id: Uuid = proof_id
        .parse()
        .map_err(|_| TransportProtocolError::Failed("Cannot parse proof id".to_string()))?;

    let proof = proof_from_handle_invitation(
        &proof_id,
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
