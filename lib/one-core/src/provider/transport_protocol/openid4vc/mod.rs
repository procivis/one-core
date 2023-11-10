use std::sync::Arc;

use self::{
    dto::{
        OpenID4VCICredential, OpenID4VCICredentialDefinition, OpenID4VCICredentialOffer,
        OpenID4VCIProof,
    },
    mapper::{create_claims_from_credential_definition, create_credential_offer_encoded},
    model::{HolderInteractionData, OpenID4VCIInteractionContent},
};

use super::{
    deserialize_interaction_data,
    dto::{InvitationType, SubmitIssuerResponse},
    mapper::interaction_from_handle_invitation,
    serialize_interaction_data, TransportProtocol, TransportProtocolError,
};
use crate::{
    config::data_structure::{ExchangeOPENID4VCParams, ExchangeParams, ParamsEnum},
    crypto::CryptoProvider,
    model::{
        claim::{Claim, ClaimRelations},
        claim_schema::ClaimSchemaRelations,
        credential::{
            Credential, CredentialId, CredentialRelations, CredentialState, CredentialStateEnum,
            CredentialStateRelations, UpdateCredentialRequest,
        },
        credential_schema::{
            CredentialSchema, CredentialSchemaClaim, CredentialSchemaId, CredentialSchemaRelations,
        },
        did::{Did, DidRelations},
        interaction::{Interaction, InteractionId, InteractionRelations},
        organisation::{Organisation, OrganisationRelations},
        proof::Proof,
    },
    repository::{
        credential_repository::CredentialRepository,
        credential_schema_repository::CredentialSchemaRepository, error::DataLayerError,
        interaction_repository::InteractionRepository, proof_repository::ProofRepository,
    },
    service::{
        oidc::dto::{
            OpenID4VCIDiscoveryResponseDTO, OpenID4VCIIssuerMetadataResponseDTO,
            OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
        },
        ssi_holder::dto::InvitationResponseDTO,
    },
    util::oidc::{map_core_to_oidc_format, map_from_oidc_format_to_core},
};

use crate::model::proof::{ProofId, ProofRelations, UpdateProofRequest};
use crate::model::proof_schema::{ProofSchemaClaimRelations, ProofSchemaRelations};
use crate::provider::transport_protocol::openid4vc::mapper::create_open_id_for_vp_sharing_url_encoded;
use crate::provider::transport_protocol::openid4vc::model::OpenID4VPInteractionContent;
use crate::util::proof_formatter::OpenID4VCIProofJWTFormatter;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::json;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

#[cfg(test)]
mod test;

pub mod dto;
pub(super) mod mapper;
mod model;

const CREDENTIAL_OFFER_QUERY_PARAM_KEY: &str = "credential_offer";
const PRESENTATION_DEFINITION_QUERY_PARAM_KEY: &str = "presentation_definition";

// TODO Remove when it's used
#[allow(unused)]
pub struct OpenID4VC {
    client: reqwest::Client,
    credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
    proof_repository: Arc<dyn ProofRepository + Send + Sync>,
    interaction_repository: Arc<dyn InteractionRepository + Send + Sync>,
    base_url: Option<String>,
    crypto: Arc<dyn CryptoProvider + Send + Sync>,
    params: ExchangeOPENID4VCParams,
}

impl OpenID4VC {
    pub fn new(
        base_url: Option<String>,
        credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
        proof_repository: Arc<dyn ProofRepository + Send + Sync>,
        interaction_repository: Arc<dyn InteractionRepository + Send + Sync>,
        crypto: Arc<dyn CryptoProvider + Send + Sync>,
        config: Option<ParamsEnum<ExchangeParams>>,
    ) -> Self {
        let params = match config {
            Some(ParamsEnum::Parsed(ExchangeParams::OPENID4VC(val))) => val,
            _ => ExchangeOPENID4VCParams::default(),
        };

        Self {
            base_url,
            credential_repository,
            credential_schema_repository,
            proof_repository,
            interaction_repository,
            client: reqwest::Client::new(),
            crypto,
            params,
        }
    }
}

#[async_trait]
impl TransportProtocol for OpenID4VC {
    fn detect_invitation_type(&self, url: &Url) -> Option<InvitationType> {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        if query_has_key(CREDENTIAL_OFFER_QUERY_PARAM_KEY) {
            return Some(InvitationType::CredentialIssuance);
        }

        if query_has_key(PRESENTATION_DEFINITION_QUERY_PARAM_KEY) {
            return Some(InvitationType::ProofRequest);
        }

        None
    }

    async fn handle_invitation(
        &self,
        url: Url,
        own_did: Did,
    ) -> Result<InvitationResponseDTO, TransportProtocolError> {
        let invitation_type =
            self.detect_invitation_type(&url)
                .ok_or(TransportProtocolError::Failed(
                    "No OpenID4VC query params detected".to_string(),
                ))?;

        match invitation_type {
            InvitationType::CredentialIssuance => {
                //for credential issuance credential_offer should be always present
                let value = url
                    .query_pairs()
                    .find_map(|(k, v)| (k == CREDENTIAL_OFFER_QUERY_PARAM_KEY).then_some(v))
                    .ok_or(TransportProtocolError::Failed(
                        "Missing credential offer param".to_string(),
                    ))?;

                // handle issuance
                let credential_offer: OpenID4VCICredentialOffer = serde_json::from_str(&value)
                    .map_err(|error| {
                        TransportProtocolError::Failed(format!(
                            "Failed decoding credential offer {error}"
                        ))
                    })?;

                handle_credential_invitation(self, credential_offer, own_did).await
            }
            InvitationType::ProofRequest => unimplemented!(),
        }
    }

    async fn reject_proof(&self, _proof: &Proof) -> Result<(), TransportProtocolError> {
        unimplemented!()
    }

    async fn submit_proof(
        &self,
        _proof: &Proof,
        _presentation: &str,
    ) -> Result<(), TransportProtocolError> {
        unimplemented!()
    }

    async fn accept_credential(
        &self,
        credential: &Credential,
    ) -> Result<SubmitIssuerResponse, TransportProtocolError> {
        let schema = credential
            .schema
            .as_ref()
            .ok_or(TransportProtocolError::Failed("schema is None".to_string()))?;

        let format = map_core_to_oidc_format(&schema.format)
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        let interaction_data: HolderInteractionData =
            deserialize_interaction_data(credential.interaction.as_ref())?;

        let holder_did = credential
            .holder_did
            .as_ref()
            .ok_or(TransportProtocolError::Failed("schema is None".to_string()))?;

        // TODO: add proper signature
        let algorithm = "EdDSA".to_string();
        let auth_fn = Box::new(move |_data: &str| Ok(vec![1u8]));

        let proof_jwt = OpenID4VCIProofJWTFormatter::format_proof(
            interaction_data.issuer_url,
            holder_did,
            algorithm,
            auth_fn,
        )
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        let body = OpenID4VCICredential {
            format,
            credential_definition: OpenID4VCICredentialDefinition {
                r#type: vec!["VerifiableCredential".to_string()],
                credential_subject: None,
            },
            proof: OpenID4VCIProof {
                proof_type: "jwt".to_string(),
                jwt: proof_jwt,
            },
        };

        let response = self
            .client
            .post(interaction_data.credential_endpoint)
            .header("Content-Type", "application/json")
            .bearer_auth(interaction_data.access_token)
            .body(json!(body).to_string())
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
        let encoded_offer =
            create_credential_offer_encoded(self.base_url.clone(), &interaction_id, &credential)?;
        Ok(format!("openid-credential-offer://?{encoded_offer}"))
    }

    async fn share_proof(&self, proof: &Proof) -> Result<String, TransportProtocolError> {
        let proof = self
            .proof_repository
            .get_proof(
                &proof.id,
                &ProofRelations {
                    interaction: Some(InteractionRelations::default()),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(ProofSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations {
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations::default()),
                                ..Default::default()
                            }),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

        let interaction_id = Uuid::new_v4();
        let interaction_content = OpenID4VPInteractionContent {
            nonce: self.crypto.generate_alphanumeric(32),
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
        )?;

        Ok(format!("openid4vp://?{encoded_offer}"))
    }
}
async fn clear_previous_interaction(
    interaction_repository: &Arc<dyn InteractionRepository + Send + Sync>,
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
    credential_repository: &Arc<dyn CredentialRepository + Send + Sync>,
) -> Result<(), TransportProtocolError> {
    let update = UpdateCredentialRequest {
        id: credential_id.to_owned(),
        interaction: Some(interaction_id.to_owned()),
        ..Default::default()
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
    proof_repository: &Arc<dyn ProofRepository + Send + Sync>,
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
    interaction_repository: &Arc<dyn InteractionRepository + Send + Sync>,
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

async fn handle_credential_invitation(
    deps: &OpenID4VC,
    credential_offer: OpenID4VCICredentialOffer,
    holder_did: Did,
) -> Result<InvitationResponseDTO, TransportProtocolError> {
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
        .json()
        .await
        .map_err(TransportProtocolError::HttpResponse)?;

    // extract schema id from the path until we find a better way
    let credential_schema_id: CredentialSchemaId = credential_issuer_endpoint
        .path_segments()
        .and_then(|p| p.last())
        .ok_or(TransportProtocolError::Failed(
            "Invalid credential issuer url".to_string(),
        ))?
        .parse()
        .map_err(|error| {
            TransportProtocolError::Failed(format!("Invalid credential schema id {error}"))
        })?;

    // OID4VC credential offer query param should always contain one credential for the moment
    let credential = credential_offer.credentials.first().ok_or_else(|| {
        TransportProtocolError::Failed("Credential offer is missing credentials".to_string())
    })?;

    let credential_format = map_from_oidc_format_to_core(&credential.format)
        .map_err(|error| TransportProtocolError::Failed(error.to_string()))?;

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
    .map_err(|error| TransportProtocolError::Failed(error.to_string()))?;
    let interaction_id = interaction.id;

    let credential_schema = match deps
        .credential_schema_repository
        .get_credential_schema(
            &credential_schema_id,
            &CredentialSchemaRelations {
                claim_schemas: Some(ClaimSchemaRelations::default()),
                ..Default::default()
            },
        )
        .await
    {
        Ok(schema) => Ok(Some(schema)),
        Err(DataLayerError::RecordNotFound) => Ok(None),
        Err(error) => Err(TransportProtocolError::Failed(error.to_string())),
    }?;

    let claims = create_claims_from_credential_definition(
        &credential.credential_definition,
        &credential_schema,
    )?;
    let (claim_schemas, claims): (Vec<_>, Vec<_>) = claims.into_iter().unzip();

    let credential_schema = match credential_schema {
        Some(schema) => schema,
        None => create_and_store_credential_schema(
            &deps.credential_schema_repository,
            credential_schema_id,
            credential_format,
            claim_schemas,
            holder_did.organisation.clone(),
        )
        .await
        .map_err(|error| TransportProtocolError::Failed(error.to_string()))?,
    };

    let credential = create_and_store_credential(
        &deps.credential_repository,
        holder_did,
        credential_schema,
        claims,
        interaction,
    )
    .await
    .map_err(|error| TransportProtocolError::Failed(error.to_string()))?;

    Ok(InvitationResponseDTO::Credential {
        interaction_id,
        credential_ids: vec![credential],
    })
}

async fn create_and_store_credential_schema(
    repository: &Arc<dyn CredentialSchemaRepository + Send + Sync>,
    id: CredentialSchemaId,
    format: String,
    claim_schemas: Vec<CredentialSchemaClaim>,
    organisation: Option<Organisation>,
) -> Result<CredentialSchema, DataLayerError> {
    let now = OffsetDateTime::now_utc();

    let credential_schema = CredentialSchema {
        id,
        deleted_at: None,
        created_date: now,
        last_modified: now,
        //todo: we need to figure out what to put here
        name: Uuid::new_v4().to_string(),
        format,
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(claim_schemas),
        organisation,
    };

    let result = repository
        .create_credential_schema(credential_schema.clone())
        .await;

    let credential_schema = match result {
        Ok(_) => credential_schema,
        Err(DataLayerError::AlreadyExists) => {
            repository
                .get_credential_schema(&id, &CredentialSchemaRelations::default())
                .await?
        }
        Err(error) => return Err(error),
    };

    Ok(credential_schema)
}

async fn create_and_store_interaction(
    repository: &Arc<dyn InteractionRepository + Send + Sync>,
    base_url: Url,
    data: Vec<u8>,
) -> Result<Interaction, DataLayerError> {
    let now = OffsetDateTime::now_utc();

    let interaction = interaction_from_handle_invitation(base_url, Some(data), now);

    repository.create_interaction(interaction.clone()).await?;

    Ok(interaction)
}

async fn create_and_store_credential(
    repository: &Arc<dyn CredentialRepository + Send + Sync>,
    holder_did: Did,
    credential_schema: CredentialSchema,
    claims: Vec<Claim>,
    interaction: Interaction,
) -> Result<CredentialId, DataLayerError> {
    let now = OffsetDateTime::now_utc();

    repository
        .create_credential(Credential {
            id: Uuid::new_v4(),
            created_date: now,
            issuance_date: now,
            last_modified: now,
            credential: vec![],
            transport: "OPENID4VC".to_string(),
            state: Some(vec![CredentialState {
                created_date: now,
                state: CredentialStateEnum::Pending,
            }]),
            claims: Some(claims),
            issuer_did: None,
            holder_did: Some(holder_did),
            schema: Some(credential_schema),
            interaction: Some(interaction),
            revocation_list: None,
        })
        .await
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
    let (oicd_discovery, issuer_metadata) = tokio::join!(oicd_discovery, issuer_metadata);

    Ok((oicd_discovery?, issuer_metadata?))
}
