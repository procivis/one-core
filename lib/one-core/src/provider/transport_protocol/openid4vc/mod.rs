use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize};
use shared_types::CredentialId;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use self::{
    dto::{
        OpenID4VCICredential, OpenID4VCICredentialDefinition, OpenID4VCICredentialOfferClaim,
        OpenID4VCICredentialOfferClaimValue, OpenID4VCICredentialOfferCredentialDTO,
        OpenID4VCICredentialOfferDTO, OpenID4VCICredentialValueDetails, OpenID4VCIProof,
    },
    mapper::{
        create_claims_from_credential_definition, create_credential_offer,
        create_open_id_for_vp_presentation_definition, create_presentation_submission,
        get_credential_offer_url,
    },
    model::{HolderInteractionData, OpenID4VCIInteractionContent},
};
use super::{
    deserialize_interaction_data,
    dto::{InvitationType, PresentedCredential, SubmitIssuerResponse},
    mapper::interaction_from_handle_invitation,
    serialize_interaction_data, TransportProtocol, TransportProtocolError,
};
use crate::config::core_config;
use crate::model::key::KeyRelations;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::{
    crypto::CryptoProvider,
    model::{
        claim::{Claim, ClaimRelations},
        claim_schema::ClaimSchemaRelations,
        credential::{
            Credential, CredentialRelations, CredentialRole, CredentialState, CredentialStateEnum,
            CredentialStateRelations, UpdateCredentialRequest,
        },
        credential_schema::{
            CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations,
            CredentialSchemaType, LayoutProperties, LayoutType, UpdateCredentialSchemaRequest,
        },
        did::{Did, DidRelations, DidType},
        interaction::{Interaction, InteractionId, InteractionRelations},
        organisation::{Organisation, OrganisationRelations},
        proof::{Proof, ProofClaimRelations, ProofId, ProofRelations, UpdateProofRequest},
        proof_schema::{ProofSchemaClaimRelations, ProofSchemaRelations},
    },
    provider::{
        credential_formatter::provider::CredentialFormatterProvider,
        key_storage::provider::KeyProvider,
        revocation::provider::RevocationMethodProvider,
        transport_protocol::{
            mapper::proof_from_handle_invitation,
            openid4vc::{
                dto::OpenID4VPInteractionData, mapper::create_open_id_for_vp_sharing_url_encoded,
                model::OpenID4VPInteractionContent, validator::validate_interaction_data,
            },
        },
    },
    repository::{
        credential_repository::CredentialRepository,
        credential_schema_repository::CredentialSchemaRepository, did_repository::DidRepository,
        error::DataLayerError, interaction_repository::InteractionRepository,
        proof_repository::ProofRepository,
    },
    service::{
        oidc::dto::{
            OpenID4VCICredentialResponseDTO, OpenID4VCIDiscoveryResponseDTO,
            OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCITokenRequestDTO,
            OpenID4VCITokenResponseDTO, OpenID4VPDirectPostResponseDTO,
        },
        ssi_holder::dto::InvitationResponseDTO,
    },
    util::{
        oidc::{map_core_to_oidc_format, map_from_oidc_format_to_core},
        proof_formatter::OpenID4VCIProofJWTFormatter,
    },
};
use crate::{
    model::credential_schema::WalletStorageTypeEnum,
    model::proof_schema::ProofInputSchemaRelations,
    provider::transport_protocol::mapper::get_relevant_credentials_to_credential_schemas,
};
use crate::{
    model::key::Key,
    provider::transport_protocol::openid4vc::mapper::{
        get_claim_name_by_json_path, presentation_definition_from_interaction_data,
    },
};
use crate::{
    provider::transport_protocol::dto::{
        CredentialGroup, CredentialGroupItem, PresentationDefinitionResponseDTO,
    },
    util::oidc::detect_correct_format,
};

#[cfg(test)]
mod test;

pub mod dto;
pub(crate) mod mapper;
mod model;
mod validator;

const CREDENTIAL_OFFER_URL_SCHEME: &str = "openid-credential-offer";
const CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY: &str = "credential_offer";
const CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY: &str = "credential_offer_uri";
const PRESENTATION_DEFINITION_VALUE_QUERY_PARAM_KEY: &str = "presentation_definition";
const PRESENTATION_DEFINITION_REFERENCE_QUERY_PARAM_KEY: &str = "presentation_definition_uri";

pub(crate) struct OpenID4VC {
    client: reqwest::Client,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    did_repository: Arc<dyn DidRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_provider: Arc<dyn RevocationMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    base_url: Option<String>,
    crypto: Arc<dyn CryptoProvider>,
    params: OpenID4VCParams,
    config: Arc<core_config::CoreConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCParams {
    pub(crate) pre_authorized_code_expires_in: u64,
    pub(crate) token_expires_in: u64,
    pub(crate) credential_offer_by_value: Option<bool>,
    pub(crate) client_metadata_by_value: Option<bool>,
    pub(crate) presentation_definition_by_value: Option<bool>,
    pub(crate) allow_insecure_http_transport: Option<bool>,
}

impl OpenID4VC {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_url: Option<String>,
        credential_repository: Arc<dyn CredentialRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        did_repository: Arc<dyn DidRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        crypto: Arc<dyn CryptoProvider>,
        params: OpenID4VCParams,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            base_url,
            credential_repository,
            credential_schema_repository,
            did_repository,
            proof_repository,
            interaction_repository,
            formatter_provider,
            revocation_provider,
            key_provider,
            key_algorithm_provider,
            client: reqwest::Client::new(),
            crypto,
            params,
            config,
        }
    }
}

#[async_trait]
impl TransportProtocol for OpenID4VC {
    fn detect_invitation_type(&self, url: &Url) -> Option<InvitationType> {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        if query_has_key(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY)
            || query_has_key(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY)
        {
            return Some(InvitationType::CredentialIssuance);
        }

        if query_has_key(PRESENTATION_DEFINITION_VALUE_QUERY_PARAM_KEY)
            || query_has_key(PRESENTATION_DEFINITION_REFERENCE_QUERY_PARAM_KEY)
        {
            return Some(InvitationType::ProofRequest);
        }

        None
    }

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
    ) -> Result<InvitationResponseDTO, TransportProtocolError> {
        let invitation_type =
            self.detect_invitation_type(&url)
                .ok_or(TransportProtocolError::Failed(
                    "No OpenID4VC query params detected".to_string(),
                ))?;

        match invitation_type {
            InvitationType::CredentialIssuance => {
                handle_credential_invitation(self, url, organisation).await
            }
            InvitationType::ProofRequest => {
                handle_proof_invitation(
                    url,
                    self,
                    self.params
                        .allow_insecure_http_transport
                        .is_some_and(|value| value),
                )
                .await
            }
        }
    }

    async fn reject_proof(&self, _proof: &Proof) -> Result<(), TransportProtocolError> {
        Err(TransportProtocolError::OperationNotSupported)
    }

    async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
    ) -> Result<(), TransportProtocolError> {
        let interaction_data: OpenID4VPInteractionData =
            deserialize_interaction_data(proof.interaction.as_ref())?;

        let tokens: Vec<String> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.presentation.to_owned())
            .collect();

        // temporary support for JWK presentation issuance.
        let (format, oidc_format) = if tokens.iter().any(|t| t.starts_with('{')) {
            ("JSON_LD_CLASSIC", "ldp_vp")
        } else {
            ("JWT", "jwt_vp_json")
        };

        let presentation_formatter = self
            .formatter_provider
            .get_formatter(format)
            .ok_or_else(|| TransportProtocolError::Failed("Formatter not found".to_string()))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(key)
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        let presentation_submission = create_presentation_submission(
            &interaction_data,
            credential_presentations,
            oidc_format,
        )?;

        let vp_token = presentation_formatter
            .format_presentation(
                &tokens,
                &holder_did.did,
                &key.key_type,
                auth_fn,
                Some(interaction_data.nonce),
            )
            .await
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        let mut params = HashMap::new();
        params.insert("vp_token", vp_token);
        params.insert(
            "presentation_submission",
            serde_json::to_string(&presentation_submission)
                .map_err(|e| TransportProtocolError::Failed(e.to_string()))?,
        );
        if let Some(state) = interaction_data.state {
            params.insert("state", state);
        }

        let response = self
            .client
            .post(interaction_data.response_uri)
            .form(&params)
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;

        let response: Result<OpenID4VPDirectPostResponseDTO, _> = response.json().await;

        if let Ok(value) = response {
            self.proof_repository
                .update_proof(UpdateProofRequest {
                    id: proof.id,
                    redirect_uri: Some(value.redirect_uri),
                    ..Default::default()
                })
                .await
                .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;
        }

        Ok(())
    }

    async fn accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
    ) -> Result<SubmitIssuerResponse, TransportProtocolError> {
        let schema = credential
            .schema
            .as_ref()
            .ok_or(TransportProtocolError::Failed("schema is None".to_string()))?;

        let format = map_core_to_oidc_format(&schema.format)
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        let interaction_data: HolderInteractionData =
            deserialize_interaction_data(credential.interaction.as_ref())?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(key)
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        let proof_jwt = OpenID4VCIProofJWTFormatter::format_proof(
            interaction_data.issuer_url,
            holder_did,
            key.key_type.to_owned(),
            auth_fn,
        )
        .await
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        let (credential_definition, doctype) = match format.as_str() {
            "mso_mdoc" => (None, Some(schema.schema_id.to_owned())),
            _ => (
                Some(OpenID4VCICredentialDefinition {
                    r#type: vec!["VerifiableCredential".to_string()],
                    credential_subject: None,
                }),
                None,
            ),
        };
        let body = OpenID4VCICredential {
            format,
            credential_definition,
            doctype,
            proof: OpenID4VCIProof {
                proof_type: "jwt".to_string(),
                jwt: proof_jwt,
            },
        };

        let response = self
            .client
            .post(interaction_data.credential_endpoint)
            .bearer_auth(interaction_data.access_token)
            .json(&body)
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

        let result: OpenID4VCICredentialResponseDTO =
            serde_json::from_str(&response_value).map_err(TransportProtocolError::JsonError)?;

        let format = detect_correct_format(schema, &result.credential)
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        // revocation method must be updated based on the issued credential (unknown in credential offer)
        let response_credential = self
            .formatter_provider
            .get_formatter(&format)
            .ok_or_else(|| {
                TransportProtocolError::Failed(format!("{} formatter not found", schema.format))
            })?
            .extract_credentials_unverified(&result.credential)
            .await
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        // Revocation method should be the same for every credential in list
        if let Some(credential_status) = response_credential.status.first() {
            let (_, revocation_method) = self
                .revocation_provider
                .get_revocation_method_by_status_type(&credential_status.r#type)
                .ok_or(TransportProtocolError::Failed(format!(
                    "Revocation method not found for status type {}",
                    credential_status.r#type
                )))?;

            self.credential_schema_repository
                .update_credential_schema(UpdateCredentialSchemaRequest {
                    id: schema.id,
                    revocation_method: Some(revocation_method),
                })
                .await
                .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;
        }

        // issuer_did must be set based on issued credential (unknown in credential offer)
        let issuer_did_value =
            response_credential
                .issuer_did
                .ok_or(TransportProtocolError::Failed(
                    "issuer_did missing".to_string(),
                ))?;

        let now = OffsetDateTime::now_utc();
        let issuer_did_id = match self
            .did_repository
            .get_did_by_value(&issuer_did_value, &DidRelations::default())
            .await
            .map_err(|err| TransportProtocolError::Failed(err.to_string()))?
        {
            Some(did) => did.id,
            None => {
                let id = Uuid::new_v4();
                self.did_repository
                    .create_did(Did {
                        id: id.into(),
                        name: format!("issuer {id}"),
                        created_date: now,
                        last_modified: now,
                        organisation: schema.organisation.to_owned(),
                        did: issuer_did_value,
                        did_type: DidType::Remote,
                        did_method: "KEY".to_string(),
                        keys: None,
                        deactivated: false,
                    })
                    .await
                    .map_err(|e| TransportProtocolError::Failed(e.to_string()))?
            }
        };

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential.id,
                issuer_did_id: Some(issuer_did_id),
                redirect_uri: Some(result.redirect_uri.to_owned()),
                credential: None,
                holder_did_id: None,
                state: None,
                interaction: None,
                key: None,
            })
            .await
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        Ok(result.into())
    }

    async fn reject_credential(
        &self,
        _credential: &Credential,
    ) -> Result<(), TransportProtocolError> {
        Err(TransportProtocolError::OperationNotSupported)
    }

    async fn share_credential(
        &self,
        credential: &Credential,
    ) -> Result<String, TransportProtocolError> {
        let credential = self
            .credential_repository
            .get_credential(
                &credential.id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    issuer_did: Some(DidRelations::default()),
                    holder_did: Some(DidRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        let Some(credential) = credential else {
            return Err(TransportProtocolError::Failed(
                "Missing credential".to_string(),
            ));
        };

        let interaction_id = Uuid::new_v4();
        let interaction_content: OpenID4VCIInteractionContent = OpenID4VCIInteractionContent {
            pre_authorized_code_used: false,
            access_token: format!(
                "{}.{}",
                interaction_id,
                self.crypto.generate_alphanumeric(32)
            ),
            access_token_expires_at: None,
        };
        add_new_interaction(
            interaction_id,
            &self.base_url,
            &self.interaction_repository,
            serde_json::to_vec(&interaction_content).ok(),
        )
        .await?;
        update_credentials_interaction(
            &credential.id,
            &interaction_id,
            &self.credential_repository,
        )
        .await?;
        clear_previous_interaction(&self.interaction_repository, &credential.interaction).await?;

        let mut url = Url::parse(&format!("{CREDENTIAL_OFFER_URL_SCHEME}://"))
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;
        let mut query = url.query_pairs_mut();

        if self
            .params
            .credential_offer_by_value
            .is_some_and(|by_value| by_value)
        {
            let offer = create_credential_offer(
                self.base_url.to_owned(),
                &interaction_id,
                &credential,
                &self.config,
            )?;

            let offer_string = serde_json::to_string(&offer)
                .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

            query.append_pair(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY, &offer_string);
        } else {
            let offer_url = get_credential_offer_url(self.base_url.to_owned(), &credential)?;
            query.append_pair(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY, &offer_url);
        }

        Ok(query.finish().to_string())
    }

    async fn share_proof(&self, proof: &Proof) -> Result<String, TransportProtocolError> {
        let proof = self
            .proof_repository
            .get_proof(
                &proof.id,
                &ProofRelations {
                    interaction: Some(InteractionRelations::default()),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(ClaimSchemaRelations::default()),
                        },
                        ..Default::default()
                    }),
                    schema: Some(ProofSchemaRelations {
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations::default()),
                        }),
                        ..Default::default()
                    }),
                    verifier_key: Some(KeyRelations::default()),
                    verifier_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?
            .ok_or(TransportProtocolError::Failed(format!(
                "Share proof missing proof {}",
                proof.id
            )))?;

        let interaction_id = Uuid::new_v4();

        // Pass the expected presentation content to interaction for verification
        let presentation_definition =
            create_open_id_for_vp_presentation_definition(interaction_id, &proof)?;
        let interaction_content = OpenID4VPInteractionContent {
            nonce: self.crypto.generate_alphanumeric(32),
            presentation_definition,
        };

        add_new_interaction(
            interaction_id,
            &self.base_url,
            &self.interaction_repository,
            serde_json::to_vec(&interaction_content).ok(),
        )
        .await?;
        update_proof_interaction(&proof.id, &interaction_id, &self.proof_repository).await?;

        clear_previous_interaction(&self.interaction_repository, &proof.interaction).await?;

        let encoded_offer = create_open_id_for_vp_sharing_url_encoded(
            self.base_url.clone(),
            interaction_id,
            interaction_content.nonce,
            proof,
            self.params
                .client_metadata_by_value
                .is_some_and(|value| value),
            self.params
                .presentation_definition_by_value
                .is_some_and(|value| value),
            &self.key_algorithm_provider,
        )?;

        Ok(format!("openid4vp://?{encoded_offer}"))
    }

    async fn get_presentation_definition(
        &self,
        proof: &Proof,
    ) -> Result<PresentationDefinitionResponseDTO, TransportProtocolError> {
        let interaction_data: OpenID4VPInteractionData =
            deserialize_interaction_data(proof.interaction.as_ref())?;
        let presentation_definition =
            interaction_data
                .presentation_definition
                .ok_or(TransportProtocolError::Failed(
                    "presentation_definition is None".to_string(),
                ))?;
        let mut credential_groups: Vec<CredentialGroup> = vec![];
        let mut group_id_to_schema_id: HashMap<String, String> = HashMap::new();
        for input_descriptor in presentation_definition.input_descriptors {
            let validity_credential_nbf = input_descriptor.constraints.validity_credential_nbf;

            let mut fields = input_descriptor.constraints.fields;

            let schema_id_filter_index = fields
                .iter()
                .position(|field| {
                    field.filter.is_some()
                        && field.path.contains(&"$.credentialSchema.id".to_string())
                })
                .ok_or(TransportProtocolError::Failed(
                    "schema_id filter not found".to_string(),
                ))?;

            let schema_id_filter = fields.remove(schema_id_filter_index).filter.ok_or(
                TransportProtocolError::Failed("schema_id filter not found".to_string()),
            )?;

            group_id_to_schema_id.insert(input_descriptor.id.clone(), schema_id_filter.r#const);
            credential_groups.push(CredentialGroup {
                id: input_descriptor.id,
                claims: fields
                    .iter()
                    .filter(|requested| requested.id.is_some())
                    .map(|requested_claim| {
                        Ok(CredentialGroupItem {
                            id: requested_claim
                                .id
                                .ok_or(TransportProtocolError::Failed(
                                    "requested_claim id is None".to_string(),
                                ))?
                                .to_string(),
                            key: get_claim_name_by_json_path(&requested_claim.path)?,
                            required: !requested_claim.optional.is_some_and(|optional| optional),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                applicable_credentials: vec![],
                validity_credential_nbf,
            });
        }
        let (credentials, credential_groups) = get_relevant_credentials_to_credential_schemas(
            &self.credential_repository,
            credential_groups,
            group_id_to_schema_id,
        )
        .await?;
        presentation_definition_from_interaction_data(proof.id, credentials, credential_groups)
    }
}

async fn clear_previous_interaction(
    interaction_repository: &Arc<dyn InteractionRepository>,
    interaction: &Option<Interaction>,
) -> Result<(), TransportProtocolError> {
    if let Some(interaction) = interaction.as_ref() {
        interaction_repository
            .delete_interaction(&interaction.id)
            .await
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;
    }
    Ok(())
}

async fn update_credentials_interaction(
    credential_id: &CredentialId,
    interaction_id: &InteractionId,
    credential_repository: &Arc<dyn CredentialRepository>,
) -> Result<(), TransportProtocolError> {
    let update = UpdateCredentialRequest {
        id: credential_id.to_owned(),
        interaction: Some(interaction_id.to_owned()),
        credential: None,
        holder_did_id: None,
        issuer_did_id: None,
        state: None,
        key: None,
        redirect_uri: None,
    };

    credential_repository
        .update_credential(update)
        .await
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;
    Ok(())
}

async fn update_proof_interaction(
    proof_id: &ProofId,
    interaction_id: &InteractionId,
    proof_repository: &Arc<dyn ProofRepository>,
) -> Result<(), TransportProtocolError> {
    let update = UpdateProofRequest {
        id: proof_id.to_owned(),
        interaction: Some(interaction_id.to_owned()),
        ..Default::default()
    };

    proof_repository
        .update_proof(update)
        .await
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;
    Ok(())
}

async fn add_new_interaction(
    interaction_id: InteractionId,
    base_url: &Option<String>,
    interaction_repository: &Arc<dyn InteractionRepository>,
    data: Option<Vec<u8>>,
) -> Result<(), TransportProtocolError> {
    let now = OffsetDateTime::now_utc();
    let host = base_url
        .as_ref()
        .map(|url| {
            url.parse()
                .map_err(|_| TransportProtocolError::Failed(format!("Invalid base url {url}")))
        })
        .transpose()?;

    let new_interaction = Interaction {
        id: interaction_id,
        created_date: now,
        last_modified: now,
        host,
        data,
    };
    interaction_repository
        .create_interaction(new_interaction)
        .await
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

    Ok(())
}

async fn resolve_credential_offer(
    deps: &OpenID4VC,
    invitation_url: Url,
) -> Result<OpenID4VCICredentialOfferDTO, TransportProtocolError> {
    let query_pairs: HashMap<_, _> = invitation_url.query_pairs().collect();
    let credential_offer_param = query_pairs.get(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY);
    let credential_offer_reference_param =
        query_pairs.get(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY);

    if credential_offer_param.is_some() && credential_offer_reference_param.is_some() {
        return Err(TransportProtocolError::Failed(
            format!("Detected both {CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY} and {CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY}"),
        ));
    }

    if let Some(credential_offer) = credential_offer_param {
        serde_json::from_str(credential_offer).map_err(|error| {
            TransportProtocolError::Failed(format!("Failed decoding credential offer {error}"))
        })
    } else if let Some(credential_offer_reference) = credential_offer_reference_param {
        let credential_offer_url = Url::parse(credential_offer_reference).map_err(|error| {
            TransportProtocolError::Failed(format!("Failed decoding credential offer url {error}"))
        })?;

        // TODO: forbid plain-text http requests in production
        // let url_scheme = credential_offer_url.scheme();
        // if url_scheme != "https" {
        //     return Err(TransportProtocolError::Failed(format!(
        //         "Invalid {CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY} url scheme: {url_scheme}"
        //     )));
        // }

        Ok(deps
            .client
            .get(credential_offer_url)
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?
            .json()
            .await
            .map_err(|error| {
                TransportProtocolError::Failed(format!(
                    "Failed decoding credential offer json {error}"
                ))
            })?)
    } else {
        Err(TransportProtocolError::Failed(
            "Missing credential offer param".to_string(),
        ))
    }
}

async fn handle_credential_invitation(
    deps: &OpenID4VC,
    invitation_url: Url,
    organisation: Organisation,
) -> Result<InvitationResponseDTO, TransportProtocolError> {
    let credential_offer = resolve_credential_offer(deps, invitation_url).await?;

    let credential_issuer_endpoint: Url =
        credential_offer.credential_issuer.parse().map_err(|_| {
            TransportProtocolError::Failed(format!(
                "Invalid credential issuer url {}",
                credential_offer.credential_issuer
            ))
        })?;

    let (oicd_discovery, issuer_metadata) =
        get_discovery_and_issuer_metadata(&deps.client, credential_issuer_endpoint.to_owned())
            .await?;

    let token_response: OpenID4VCITokenResponseDTO = deps
        .client
        .post(&oicd_discovery.token_endpoint)
        .form(&OpenID4VCITokenRequestDTO {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            pre_authorized_code: credential_offer.grants.code.pre_authorized_code.clone(),
        })
        .send()
        .await
        .map_err(TransportProtocolError::HttpResponse)?
        .error_for_status()
        .map_err(TransportProtocolError::HttpResponse)?
        .json()
        .await
        .map_err(TransportProtocolError::HttpResponse)?;

    // OID4VC credential offer query param should always contain one credential for the moment
    let credential: &OpenID4VCICredentialOfferCredentialDTO =
        credential_offer.credentials.first().ok_or_else(|| {
            TransportProtocolError::Failed("Credential offer is missing credentials".to_string())
        })?;

    let credential_schema_name = get_credential_schema_name(&issuer_metadata, credential)?;

    let holder_data = HolderInteractionData {
        issuer_url: issuer_metadata.credential_issuer,
        credential_endpoint: issuer_metadata.credential_endpoint,
        access_token: token_response.access_token,
        access_token_expires_at: Some(
            OffsetDateTime::now_utc() + Duration::seconds(token_response.expires_in.0),
        ),
    };
    let data = serialize_interaction_data(&holder_data)?;

    let interaction = create_and_store_interaction(
        &deps.interaction_repository,
        credential_issuer_endpoint,
        data,
    )
    .await
    .map_err(|error: DataLayerError| TransportProtocolError::Failed(error.to_string()))?;
    let interaction_id = interaction.id;

    let credential_id = Uuid::new_v4().into();

    let (schema_uri, schema_type) = find_schema_data(&credential_offer);
    // doctype is the schema_id for MDOC
    let schema_id = credential.doctype.clone().unwrap_or(schema_uri.clone());

    let claim_keys = build_claim_keys(credential)?;

    let (claims, credential_schema) =
        match deps
            .credential_schema_repository
            .get_by_schema_id_and_organisation(&schema_id, organisation.id)
            .await
            .map_err(|err| TransportProtocolError::Failed(err.to_string()))?
        {
            Some(credential_schema) => {
                if credential_schema.schema_type != schema_type {
                    return Err(TransportProtocolError::IncorrectCredentialSchemaType);
                }

                let credential_schema = deps
                    .credential_schema_repository
                    .get_credential_schema(
                        &credential_schema.id,
                        &CredentialSchemaRelations {
                            claim_schemas: Some(ClaimSchemaRelations::default()),
                            organisation: Some(Default::default()),
                        },
                    )
                    .await
                    .map_err(|err| TransportProtocolError::Failed(err.to_string()))?
                    .ok_or(TransportProtocolError::Failed(
                        "Credential schema error".to_string(),
                    ))?;

                let claim_schemas = credential_schema.claim_schemas.as_ref().ok_or(
                    TransportProtocolError::Failed(
                        "Missing claim schemas for existing credential schema".to_string(),
                    ),
                )?;

                let now = OffsetDateTime::now_utc();
                let mut claims = vec![];
                for claim_schema in claim_schemas {
                    let credential_value_details = &claim_keys.get(&claim_schema.schema.key);
                    match credential_value_details {
                        Some(value_details) => {
                            let claim = Claim {
                                id: Uuid::new_v4(),
                                credential_id,
                                created_date: now,
                                last_modified: now,
                                value: value_details.value.to_owned(),
                                schema: Some(claim_schema.schema.to_owned()),
                            };

                            claims.push(claim);
                        }
                        None if claim_schema.required => {
                            return Err(TransportProtocolError::Failed(format!(
                                "Validation Error. Claim key {} missing",
                                &claim_schema.schema.key
                            )))
                        }
                        _ => {
                            // skip non-required claims that aren't matching
                        }
                    }
                }

                (claims, credential_schema)
            }
            None => {
                let credential_format = map_from_oidc_format_to_core(&credential.format)
                    .map_err(|error| TransportProtocolError::Failed(error.to_string()))?;

                let (claim_schemas, claims): (Vec<_>, Vec<_>) =
                    create_claims_from_credential_definition(credential_id, &claim_keys)?;

                let layout = if schema_type.supports_custom_layout() {
                    resolve_layout_data(&schema_uri).await.map_err(|err| {
                        TransportProtocolError::Failed(format!(
                            "Failed resolving layout information from schema_id {err}"
                        ))
                    })?
                } else {
                    CredentialSchemaLayout::default()
                };

                let credential_schema = create_and_store_credential_schema(
                    &deps.credential_schema_repository,
                    credential_schema_name,
                    credential_format,
                    claim_schemas,
                    organisation,
                    credential.wallet_storage_type.clone(),
                    schema_type,
                    schema_id,
                    layout,
                )
                .await
                .map_err(|error| TransportProtocolError::Failed(error.to_string()))?;

                (claims, credential_schema)
            }
        };

    let credential = create_credential(credential_id, credential_schema, claims, interaction, None)
        .await
        .map_err(|error| TransportProtocolError::Failed(error.to_string()))?;

    Ok(InvitationResponseDTO::Credential {
        interaction_id,
        credentials: vec![credential],
    })
}

fn build_claim_keys(
    credential: &OpenID4VCICredentialOfferCredentialDTO,
) -> Result<HashMap<String, OpenID4VCICredentialValueDetails>, TransportProtocolError> {
    if let Some(credential_definition) = &credential.credential_definition {
        let credential_subject = credential_definition
            .credential_subject
            .as_ref()
            .ok_or_else(|| {
                TransportProtocolError::Failed("Missing credential subject".to_string())
            })?;

        return Ok(credential_subject.keys.to_owned());
    }

    if let Some(credential_claims) = credential.claims.as_ref() {
        return Ok(build_claims_keys_for_mdoc(credential_claims));
    }

    Err(TransportProtocolError::Failed(
        "Inconsistent credential offer missing both credential definition and claims fields"
            .to_string(),
    ))
}

fn build_claims_keys_for_mdoc(
    claims: &HashMap<String, OpenID4VCICredentialOfferClaim>,
) -> HashMap<String, OpenID4VCICredentialValueDetails> {
    fn build<'a>(
        normalized_claims: &mut HashMap<String, OpenID4VCICredentialValueDetails>,
        claims: &'a HashMap<String, OpenID4VCICredentialOfferClaim>,
        path: &mut Vec<&'a str>,
    ) {
        for (key, offer_claim) in claims {
            path.push(key);

            match &offer_claim.value {
                OpenID4VCICredentialOfferClaimValue::Nested(claims) => {
                    build(normalized_claims, claims, path);
                }
                OpenID4VCICredentialOfferClaimValue::String(value) => {
                    let key = path.join("/");

                    let value = OpenID4VCICredentialValueDetails {
                        value: value.to_owned(),
                        value_type: offer_claim.value_type.to_owned(),
                    };

                    normalized_claims.insert(key, value);
                }
            }

            path.pop();
        }
    }

    let mut claim_keys = HashMap::with_capacity(claims.len());
    let mut path = vec![];

    build(&mut claim_keys, claims, &mut path);

    claim_keys
}

fn find_schema_data(
    credential_offer: &OpenID4VCICredentialOfferDTO,
) -> (String, CredentialSchemaType) {
    match create_schema_id_from_issuer(&credential_offer.credential_issuer) {
        None => (
            Uuid::new_v4().to_string(),
            CredentialSchemaType::FallbackSchema2024,
        ),
        Some(schema_id) => (schema_id, CredentialSchemaType::ProcivisOneSchema2024),
    }
}

fn get_credential_schema_name(
    issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
    credential: &OpenID4VCICredentialOfferCredentialDTO,
) -> Result<String, TransportProtocolError> {
    let display_name = issuer_metadata
        .credentials_supported
        .first()
        .and_then(|credential| credential.display.as_ref())
        .and_then(|displays| displays.first())
        .map(|display| display.name.to_owned());

    let credential_schema_name = match display_name {
        Some(display_name) => display_name,
        // fallback to doctype for mdoc
        None if credential.format == "mso_mdoc" => {
            let doctype = credential
                .doctype
                .as_ref()
                .ok_or(TransportProtocolError::Failed(
                    "docType not specified for MDOC".to_string(),
                ))?;

            doctype.to_owned()
        }
        // fallback to credential type for other formats
        None => {
            let credential_definition =
                credential.credential_definition.as_ref().ok_or_else(|| {
                    TransportProtocolError::Failed(format!(
                        "Missing credential definition for format: {}",
                        credential.format
                    ))
                })?;

            credential_definition
                .r#type
                .last()
                .ok_or_else(|| {
                    TransportProtocolError::Failed(
                        "Credential definition has no type specified".to_string(),
                    )
                })?
                .to_owned()
        }
    };

    Ok(credential_schema_name)
}

#[allow(clippy::too_many_arguments)]
async fn create_and_store_credential_schema(
    repository: &Arc<dyn CredentialSchemaRepository>,
    name: String,
    format: String,
    claim_schemas: Vec<CredentialSchemaClaim>,
    organisation: Organisation,
    wallet_storage_type: Option<WalletStorageTypeEnum>,
    schema_type: CredentialSchemaType,
    schema_id: String,
    layout: CredentialSchemaLayout,
) -> Result<CredentialSchema, DataLayerError> {
    let now = OffsetDateTime::now_utc();

    let id = Uuid::new_v4();

    let credential_schema = CredentialSchema {
        id,
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name,
        format,
        wallet_storage_type,
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(claim_schemas),
        organisation: Some(organisation),
        layout_type: layout.layout_type,
        layout_properties: layout.layout_properties,
        schema_type,
        schema_id,
    };

    let _ = repository
        .create_credential_schema(credential_schema.clone())
        .await?;

    Ok(credential_schema)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialSchemaLayout {
    layout_type: LayoutType,
    layout_properties: Option<LayoutProperties>,
}

impl Default for CredentialSchemaLayout {
    fn default() -> Self {
        Self {
            layout_type: LayoutType::Card,
            layout_properties: None,
        }
    }
}

async fn resolve_layout_data(schema_id: &str) -> Result<CredentialSchemaLayout, reqwest::Error> {
    reqwest::get(schema_id)
        .await?
        .error_for_status()?
        .json()
        .await
}

async fn create_and_store_interaction(
    repository: &Arc<dyn InteractionRepository>,
    base_url: Url,
    data: Vec<u8>,
) -> Result<Interaction, DataLayerError> {
    let now = OffsetDateTime::now_utc();

    let interaction = interaction_from_handle_invitation(base_url, Some(data), now);

    repository.create_interaction(interaction.clone()).await?;

    Ok(interaction)
}

async fn create_credential(
    credential_id: CredentialId,
    credential_schema: CredentialSchema,
    claims: Vec<Claim>,
    interaction: Interaction,
    redirect_uri: Option<String>,
) -> Result<Credential, DataLayerError> {
    let now = OffsetDateTime::now_utc();

    Ok(Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        transport: "OPENID4VC".to_string(),
        redirect_uri,
        role: CredentialRole::Holder,
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Pending,
            suspend_end_date: None,
        }]),
        claims: Some(claims),
        issuer_did: None,
        holder_did: None,
        schema: Some(credential_schema),
        interaction: Some(interaction),
        revocation_list: None,
        key: None,
    })
}

async fn get_discovery_and_issuer_metadata(
    client: &reqwest::Client,
    credential_issuer_endpoint: Url,
) -> Result<
    (
        OpenID4VCIDiscoveryResponseDTO,
        OpenID4VCIIssuerMetadataResponseDTO,
    ),
    TransportProtocolError,
> {
    async fn fetch<T: DeserializeOwned>(
        client: &reqwest::Client,
        endpoint: impl reqwest::IntoUrl,
    ) -> Result<T, TransportProtocolError> {
        let response = client
            .get(endpoint)
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;

        response
            .json()
            .await
            .map_err(TransportProtocolError::HttpResponse)
    }

    let oicd_discovery = fetch(
        client,
        format!("{credential_issuer_endpoint}/.well-known/openid-configuration"),
    );
    let issuer_metadata = fetch(
        client,
        format!("{credential_issuer_endpoint}/.well-known/openid-credential-issuer"),
    );
    tokio::try_join!(oicd_discovery, issuer_metadata)
}

async fn interaction_data_from_query(
    query: &str,
    client: &reqwest::Client,
    allow_insecure_http_transport: bool,
) -> Result<OpenID4VPInteractionData, TransportProtocolError> {
    let mut interaction_data: OpenID4VPInteractionData = serde_qs::from_str(query)
        .map_err(|e| TransportProtocolError::InvalidRequest(e.to_string()))?;

    if interaction_data.client_metadata.is_some() && interaction_data.client_metadata_uri.is_some()
    {
        return Err(TransportProtocolError::InvalidRequest(
            "client_metadata and client_metadata_uri cannot be set together".to_string(),
        ));
    }

    if interaction_data.presentation_definition.is_some()
        && interaction_data.presentation_definition_uri.is_some()
    {
        return Err(TransportProtocolError::InvalidRequest(
            "presentation_definition and presentation_definition_uri cannot be set together"
                .to_string(),
        ));
    }

    if let Some(client_metadata_uri) = &interaction_data.client_metadata_uri {
        if !allow_insecure_http_transport && client_metadata_uri.scheme() != "https" {
            return Err(TransportProtocolError::InvalidRequest(
                "client_metadata_uri must use HTTPS scheme".to_string(),
            ));
        }

        let client_metadata = client
            .get(client_metadata_uri.to_owned())
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?
            .json()
            .await
            .map_err(|error| {
                TransportProtocolError::Failed(format!("Failed decoding client metadata: {error}"))
            })?;

        interaction_data.client_metadata = Some(client_metadata);
    }

    if let Some(presentation_definition_uri) = &interaction_data.presentation_definition_uri {
        if !allow_insecure_http_transport && presentation_definition_uri.scheme() != "https" {
            return Err(TransportProtocolError::InvalidRequest(
                "presentation_definition_uri must use HTTPS scheme".to_string(),
            ));
        }

        let presentation_definition = client
            .get(presentation_definition_uri.to_owned())
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?
            .json()
            .await
            .map_err(|error| {
                TransportProtocolError::Failed(format!(
                    "Failed decoding presentation definition: {error}"
                ))
            })?;

        interaction_data.presentation_definition = Some(presentation_definition);
    }

    Ok(interaction_data)
}

async fn handle_proof_invitation(
    url: Url,
    deps: &OpenID4VC,
    allow_insecure_http_transport: bool,
) -> Result<InvitationResponseDTO, TransportProtocolError> {
    let query = url.query().ok_or(TransportProtocolError::InvalidRequest(
        "Query cannot be empty".to_string(),
    ))?;

    let interaction_data =
        interaction_data_from_query(query, &deps.client, allow_insecure_http_transport).await?;
    validate_interaction_data(&interaction_data)?;
    let data = serialize_interaction_data(&interaction_data)?;

    let now = OffsetDateTime::now_utc();
    let interaction = create_and_store_interaction(
        &deps.interaction_repository,
        interaction_data.response_uri,
        data,
    )
    .await
    .map_err(|error| TransportProtocolError::Failed(error.to_string()))?;
    let interaction_id = interaction.id.to_owned();

    let proof_id = Uuid::new_v4();
    let proof = proof_from_handle_invitation(
        &proof_id,
        "OPENID4VC",
        interaction_data.redirect_uri,
        None,
        interaction,
        now,
        None,
    );

    Ok(InvitationResponseDTO::ProofRequest {
        interaction_id,
        proof: Box::new(proof),
    })
}

fn create_schema_id_from_issuer(issuer: &str) -> Option<String> {
    if issuer.contains("/ssi/oidc-issuer/v1/") {
        return Some(issuer.replace("/ssi/oidc-issuer/v1/", "/ssi/schema/v1/"));
    }

    None
}
