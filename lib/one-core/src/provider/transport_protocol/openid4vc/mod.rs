use std::sync::Arc;

use self::{
    dto::{OpenID4VCICredentialDefinition, OpenID4VCICredentialRequestDTO},
    mapper::create_credential_offer_encoded,
    model::InteractionContent,
};

use super::{
    dto::{InvitationResponse, InvitationType, SubmitIssuerResponse},
    TransportProtocol, TransportProtocolError,
};
use crate::{
    config::data_structure::{ExchangeOPENID4VCParams, ExchangeParams, ParamsEnum},
    crypto::Crypto,
    model::{
        claim::ClaimRelations,
        claim_schema::ClaimSchemaRelations,
        credential::{
            Credential, CredentialId, CredentialRelations, CredentialStateRelations,
            UpdateCredentialRequest,
        },
        credential_schema::CredentialSchemaRelations,
        did::{Did, DidRelations},
        interaction::{Interaction, InteractionId, InteractionRelations},
        organisation::OrganisationRelations,
        proof::Proof,
    },
    repository::{
        credential_repository::CredentialRepository, interaction_repository::InteractionRepository,
        proof_repository::ProofRepository,
    },
    util::oidc::map_core_to_oidc_format,
};
use async_trait::async_trait;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

#[cfg(test)]
mod test;

pub(super) mod mapper;
mod model;

pub mod dto;

// TODO Remove when it's used
#[allow(unused)]
pub struct OpenID4VC {
    client: reqwest::Client,
    credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    proof_repository: Arc<dyn ProofRepository + Send + Sync>,
    interaction_repository: Arc<dyn InteractionRepository + Send + Sync>,
    base_url: Option<String>,
    params: ExchangeOPENID4VCParams,
}

impl OpenID4VC {
    pub fn new(
        base_url: Option<String>,
        credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
        proof_repository: Arc<dyn ProofRepository + Send + Sync>,
        interaction_repository: Arc<dyn InteractionRepository + Send + Sync>,
        config: Option<ParamsEnum<ExchangeParams>>,
    ) -> Self {
        let params = match config {
            Some(ParamsEnum::Parsed(ExchangeParams::OPENID4VC(val))) => val,
            _ => ExchangeOPENID4VCParams::default(),
        };

        Self {
            base_url,
            credential_repository,
            proof_repository,
            interaction_repository,
            client: reqwest::Client::new(),
            params,
        }
    }
}

#[async_trait]
impl TransportProtocol for OpenID4VC {
    fn detect_invitation_type(&self, _url: &str) -> Option<InvitationType> {
        unimplemented!()
    }

    async fn handle_invitation(
        &self,
        _url: &str,
        _own_did: &Did,
    ) -> Result<InvitationResponse, TransportProtocolError> {
        unimplemented!()
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
        let schema_id = schema.id.to_string();

        let body = OpenID4VCICredentialRequestDTO {
            format,
            credential_definition: OpenID4VCICredentialDefinition {
                r#type: vec!["VerifiableCredential".to_string()],
                credential_subject: None,
            },
        };

        let mut url = super::get_base_url(&credential.interaction)?;
        url.set_path(&format!("/ssi/oidc-issuer/v1/{}/credential", schema_id));

        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
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

        // fetch and delete interactions
        if let Some(interaction) = credential.interaction.as_ref() {
            _ = self
                .interaction_repository
                .delete_interaction(&interaction.id)
                .await;
        }

        let interaction_id =
            add_new_interaction(self.base_url.to_owned(), &self.interaction_repository).await?;

        update_credentials_interaction(
            &credential.id,
            &interaction_id,
            &self.credential_repository,
        )
        .await?;

        let encoded_offer =
            create_credential_offer_encoded(self.base_url.clone(), &interaction_id, &credential)?;

        Ok(format!("openid-credential-offer://?{encoded_offer}"))
    }

    async fn share_proof(&self, _proof: &Proof) -> Result<String, TransportProtocolError> {
        unimplemented!()
    }
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

async fn add_new_interaction(
    base_url: Option<String>,
    interaction_repository: &Arc<dyn InteractionRepository + Send + Sync>,
) -> Result<InteractionId, TransportProtocolError> {
    let interaction_id = Uuid::new_v4();
    let interaction_content: InteractionContent = InteractionContent {
        pre_authorized_code_used: false,
        access_token: format!("{}.{}", interaction_id, Crypto::generate_alphanumeric(32)),
        access_token_expires_at: None,
    };

    let now = OffsetDateTime::now_utc();

    let new_interaction = Interaction {
        id: interaction_id,
        created_date: now,
        last_modified: now,
        host: base_url,
        data: serde_json::to_vec(&interaction_content).ok(),
    };

    interaction_repository
        .create_interaction(new_interaction)
        .await
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

    Ok(interaction_id)
}
