use crate::common_mapper::{
    extracted_credential_to_model, get_exchange_param_pre_authorization_expires_in,
    get_exchange_param_token_expires_in, get_or_create_did,
};
use crate::common_validator::{
    throw_if_latest_credential_state_not_eq, throw_if_latest_proof_state_not_eq,
};
use crate::model::claim::{Claim, ClaimRelations};
use crate::model::claim_schema::{ClaimSchema, ClaimSchemaId, ClaimSchemaRelations};
use crate::model::credential::{
    CredentialRelations, CredentialState, CredentialStateEnum, CredentialStateRelations,
    UpdateCredentialRequest,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaId, CredentialSchemaRelations,
};
use crate::model::did::KeyRole;
use crate::model::interaction::InteractionRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{
    Proof, ProofId, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations,
};
use crate::model::proof_schema::{
    ProofSchemaClaim, ProofSchemaClaimRelations, ProofSchemaRelations,
};

use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::transport_protocol::openid4vc::dto::{
    OpenID4VCICredentialOfferDTO, OpenID4VPClientMetadata,
};
use crate::provider::transport_protocol::openid4vc::mapper::{
    create_credential_offer, create_open_id_for_vp_client_metadata,
};
use crate::service::error::ServiceError::MappingError;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use crate::service::oidc::dto::{
    OpenID4VCICredentialRequestDTO, OpenID4VCICredentialResponseDTO, OpenID4VCIError,
};
use crate::service::oidc::mapper::{
    interaction_data_to_dto, parse_access_token, parse_interaction_content,
    vec_last_position_from_token_path,
};
use crate::service::oidc::model::OpenID4VPPresentationDefinition;
use crate::service::oidc::validator::{
    throw_if_credential_request_invalid, throw_if_interaction_created_date,
    throw_if_interaction_data_invalid, throw_if_interaction_pre_authorized_code_used,
    throw_if_token_request_invalid, validate_claims, validate_config_entity_presence,
    validate_credential, validate_presentation, validate_transport_type,
};
use crate::service::oidc::{
    dto::{
        OpenID4VCIDiscoveryResponseDTO, OpenID4VCIIssuerMetadataResponseDTO,
        OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
    },
    mapper::{create_issuer_metadata_response, create_service_discovery_response},
    OIDCService,
};
use crate::util::key_verification::KeyVerification;
use crate::util::proof_formatter::OpenID4VCIProofJWTFormatter;
use shared_types::CredentialId;
use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::str::FromStr;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::dto::{
    OpenID4VPDirectPostRequestDTO, OpenID4VPDirectPostResponseDTO, ValidatedProofClaimDTO,
};

impl OIDCService {
    pub async fn oidc_get_issuer_metadata(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let (base_url, schema) = self
            .get_credential_schema_base_url(credential_schema_id)
            .await?;

        create_issuer_metadata_response(base_url, schema)
    }

    pub async fn oidc_get_client_metadata(
        &self,
        id: ProofId,
    ) -> Result<OpenID4VPClientMetadata, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .proof_repository
            .get_proof(
                &id,
                &ProofRelations {
                    state: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Proof(id)))?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;
        validate_transport_type(&self.config, &proof.transport)?;

        Ok(create_open_id_for_vp_client_metadata())
    }

    pub async fn oidc_service_discovery(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIDiscoveryResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let (base_url, _) = self
            .get_credential_schema_base_url(credential_schema_id)
            .await?;

        create_service_discovery_response(base_url)
    }

    async fn get_credential_schema_base_url(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<(String, CredentialSchema), ServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id, &CredentialSchemaRelations::default())
            .await?;

        let Some(schema) = schema else {
            return Err(EntityNotFoundError::CredentialSchema(*credential_schema_id).into());
        };

        let core_base_url = self
            .core_base_url
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "Host URL not specified".to_string(),
            ))?;

        Ok((
            format!("{}/ssi/oidc-issuer/v1/{}", core_base_url, schema.id),
            schema,
        ))
    }

    pub async fn oidc_get_credential_offer(
        &self,
        credential_schema_id: CredentialSchemaId,
        credential_id: CredentialId,
    ) -> Result<OpenID4VCICredentialOfferDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let credential = self
            .credential_repository
            .get_credential(
                &credential_id,
                &CredentialRelations {
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    state: Some(CredentialStateRelations::default()),
                    schema: Some(CredentialSchemaRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential) = credential else {
            return Err(EntityNotFoundError::Credential(credential_id).into());
        };

        throw_if_latest_credential_state_not_eq(&credential, CredentialStateEnum::Pending)
            .map_err(|_| ServiceError::OpenID4VCError(OpenID4VCIError::InvalidRequest))?;

        if credential.transport != "OPENID4VC" {
            return Err(OpenID4VCIError::InvalidRequest.into());
        }

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "credential schema missing".to_string(),
            ))?;

        if credential_schema.id != credential_schema_id {
            return Err(OpenID4VCIError::InvalidRequest.into());
        }

        let interaction = credential
            .interaction
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "interaction missing".to_string(),
            ))?;

        Ok(create_credential_offer(
            self.core_base_url.to_owned(),
            &interaction.id,
            &credential,
        )?)
    }

    pub async fn oidc_create_credential(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        request: OpenID4VCICredentialRequestDTO,
    ) -> Result<OpenID4VCICredentialResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let schema = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    organisation: Some(OrganisationRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(schema) = schema else {
            return Err(EntityNotFoundError::CredentialSchema(*credential_schema_id).into());
        };

        throw_if_credential_request_invalid(&schema, &request)?;

        let interaction_id = parse_access_token(access_token)?;
        let interaction = self
            .interaction_repository
            .get_interaction(&interaction_id, &InteractionRelations::default())
            .await?;

        let Some(interaction) = interaction else {
            return Err(
                BusinessLogicError::MissingInteractionForAccessToken { interaction_id }.into(),
            );
        };

        throw_if_interaction_data_invalid(&interaction_data_to_dto(&interaction)?, access_token)?;

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                &interaction.id,
                &CredentialRelations {
                    interaction: Some(InteractionRelations::default()),
                    state: Some(CredentialStateRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential) = credentials.into_iter().next() else {
            return Err(
                BusinessLogicError::MissingCredentialsForInteraction { interaction_id }.into(),
            );
        };

        let holder_did = if request.proof.proof_type == "jwt" {
            let jwt = OpenID4VCIProofJWTFormatter::verify_proof(&request.proof.jwt).await?;
            let holder_did_value = jwt
                .header
                .key_id
                .ok_or(ServiceError::OpenID4VCError(
                    OpenID4VCIError::InvalidOrMissingProof,
                ))
                .map(|v| match v.parse() {
                    Ok(v) => v,
                    Err(err) => match err {},
                })?;

            get_or_create_did(
                &*self.did_repository,
                &schema.organisation,
                &holder_did_value,
            )
            .await
        } else {
            Err(ServiceError::OpenID4VCError(
                OpenID4VCIError::InvalidOrMissingProof,
            ))
        }?;

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential.id,
                holder_did_id: Some(holder_did.id),
                credential: None,
                issuer_did_id: None,
                state: None,
                interaction: None,
                key: None,
                redirect_uri: None,
            })
            .await?;

        let issued_credential = self
            .protocol_provider
            .issue_credential(&credential.id)
            .await?;

        Ok(OpenID4VCICredentialResponseDTO {
            credential: issued_credential.credential,
            format: request.format,
            redirect_uri: credential.redirect_uri,
        })
    }

    pub async fn oidc_create_token(
        &self,
        credential_schema_id: &CredentialSchemaId,
        request: OpenID4VCITokenRequestDTO,
    ) -> Result<OpenID4VCITokenResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        throw_if_token_request_invalid(&request)?;

        if self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id, &CredentialSchemaRelations::default())
            .await?
            .is_none()
        {
            return Err(EntityNotFoundError::CredentialSchema(*credential_schema_id).into());
        }

        let interaction_id = Uuid::from_str(&request.pre_authorized_code)?;

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                &interaction_id,
                &CredentialRelations {
                    interaction: Some(InteractionRelations::default()),
                    state: Some(CredentialStateRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let now = OffsetDateTime::now_utc();

        let mut interaction = credentials
            .first()
            .ok_or(BusinessLogicError::MissingCredentialsForInteraction { interaction_id })?
            .interaction
            .clone()
            .ok_or(ServiceError::MappingError(
                "interaction is None".to_string(),
            ))?;

        throw_if_interaction_created_date(
            get_exchange_param_pre_authorization_expires_in(&self.config)?,
            &interaction,
        )?;

        let mut interaction_data = interaction_data_to_dto(&interaction)?;

        throw_if_interaction_pre_authorized_code_used(&interaction_data)?;

        for credential in &credentials {
            throw_if_latest_credential_state_not_eq(credential, CredentialStateEnum::Pending)?;
            self.credential_repository
                .update_credential(UpdateCredentialRequest {
                    id: credential.id,
                    state: Some(CredentialState {
                        created_date: now,
                        state: CredentialStateEnum::Offered,
                    }),
                    credential: None,
                    holder_did_id: None,
                    issuer_did_id: None,
                    interaction: None,
                    key: None,
                    redirect_uri: None,
                })
                .await?;
        }

        interaction_data.pre_authorized_code_used = true;
        interaction_data.access_token_expires_at =
            Some(now.add(get_exchange_param_token_expires_in(&self.config)?));

        let data = serde_json::to_vec(&interaction_data)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        interaction.data = Some(data);

        self.interaction_repository
            .update_interaction(interaction)
            .await?;

        interaction_data.try_into()
    }

    pub async fn oidc_verifier_direct_post(
        &self,
        request: OpenID4VPDirectPostRequestDTO,
    ) -> Result<OpenID4VPDirectPostResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let interaction_id = request.state;

        let proof = self
            .proof_repository
            .get_proof_by_interaction_id(
                &interaction_id,
                &ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations {
                            credential_schema: Some(CredentialSchemaRelations::default()),
                        }),
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    interaction: Some(InteractionRelations::default()),
                    state: Some(ProofStateRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(proof) = proof else {
            return Err(BusinessLogicError::MissingProofForInteraction(interaction_id).into());
        };

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;

        match self.process_proof_submission(request, &proof).await {
            Ok(proved_claims) => {
                let redirect_uri = proof.redirect_uri.to_owned();
                self.accept_proof(proof, proved_claims).await?;
                Ok(OpenID4VPDirectPostResponseDTO { redirect_uri })
            }
            Err(err) => {
                self.mark_proof_as_failed(&proof.id).await?;
                Err(err)
            }
        }
    }

    pub async fn oidc_verifier_presentation_definition(
        &self,
        id: ProofId,
    ) -> Result<OpenID4VPPresentationDefinition, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .proof_repository
            .get_proof(
                &id,
                &ProofRelations {
                    interaction: Some(InteractionRelations::default()),
                    schema: Some(ProofSchemaRelations::default()),
                    state: Some(ProofStateRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Proof(id)))?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;
        validate_transport_type(&self.config, &proof.transport)?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ServiceError::OpenID4VCError(
                OpenID4VCIError::InvalidRequest,
            ))?;

        let mut interaction_data = parse_interaction_content(interaction.data.as_ref())?;

        let proof_schema = proof
            .schema
            .as_ref()
            .ok_or(MappingError("Proof schema not found".to_string()))?;
        if let Some(validity_constraint) = proof_schema.validity_constraint {
            let now = OffsetDateTime::now_utc();
            interaction_data
                .presentation_definition
                .input_descriptors
                .iter_mut()
                .for_each(|input_descriptor| {
                    input_descriptor.constraints.validity_credential_nbf =
                        Some(now.sub(Duration::seconds(validity_constraint)));
                });
        }

        Ok(interaction_data.presentation_definition)
    }

    async fn process_proof_submission(
        &self,
        submission: OpenID4VPDirectPostRequestDTO,
        proof: &Proof,
    ) -> Result<Vec<ValidatedProofClaimDTO>, ServiceError> {
        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ServiceError::OpenID4VCError(
                OpenID4VCIError::InvalidRequest,
            ))?;

        let interaction_data = parse_interaction_content(interaction.data.as_ref())?;

        let presentation_submission = &submission.presentation_submission;

        if presentation_submission.definition_id != submission.state.to_string() {
            return Err(OpenID4VCIError::InvalidRequest.into());
        }

        if presentation_submission.descriptor_map.len()
            != interaction_data
                .presentation_definition
                .input_descriptors
                .len()
        {
            // different count of requested and submitted credentials
            return Err(OpenID4VCIError::InvalidRequest.into());
        }

        let presentation_strings: Vec<String> = if submission.vp_token.starts_with('[') {
            serde_json::from_str(&submission.vp_token)
                .map_err(|_| OpenID4VCIError::InvalidRequest)?
        } else {
            vec![submission.vp_token]
        };

        // collect expected credentials
        let proof_schema_claims = proof
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "missing proof schema".to_string(),
            ))?
            .claim_schemas
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "missing proof schema claims".to_string(),
            ))?;

        let mut claim_to_credential_schema_mapping: HashMap<ClaimSchemaId, CredentialSchemaId> =
            HashMap::new();
        let mut expected_credential_claims: HashMap<CredentialSchemaId, Vec<&ProofSchemaClaim>> =
            HashMap::new();
        for proof_schema_claim in proof_schema_claims {
            let credential_schema =
                proof_schema_claim
                    .credential_schema
                    .as_ref()
                    .ok_or(ServiceError::MappingError(
                        "missing proof schema claim credential_schema".to_string(),
                    ))?;

            let entry = expected_credential_claims
                .entry(credential_schema.id)
                .or_default();
            entry.push(proof_schema_claim);
            claim_to_credential_schema_mapping
                .insert(proof_schema_claim.schema.id, credential_schema.id);
        }

        let mut total_proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();
        // Unpack presentations and credentials
        for presentation_submitted in &presentation_submission.descriptor_map {
            let input_descriptor = interaction_data
                .presentation_definition
                .input_descriptors
                .iter()
                .find(|descriptor| descriptor.id == presentation_submitted.id)
                .ok_or(OpenID4VCIError::InvalidRequest)?;

            let presentation_string_index =
                vec_last_position_from_token_path(&presentation_submitted.path)?;
            let presentation_string = presentation_strings
                .get(presentation_string_index)
                .ok_or(OpenID4VCIError::InvalidRequest)?;

            let presentation = validate_presentation(
                presentation_string,
                &interaction_data.nonce,
                &presentation_submitted.format,
                &self.formatter_provider,
                self.build_key_verification(KeyRole::Authentication),
            )
            .await?;

            let holder_did =
                presentation
                    .issuer_did
                    .as_ref()
                    .ok_or(ServiceError::ValidationError(
                        "Missing holder id".to_string(),
                    ))?;

            let path_nested = presentation_submitted
                .path_nested
                .as_ref()
                .ok_or(OpenID4VCIError::InvalidRequest)?;
            let credential_index = vec_last_position_from_token_path(&path_nested.path)?;
            let credential = presentation
                .credentials
                .get(credential_index)
                .ok_or(OpenID4VCIError::InvalidRequest)?;

            let credential = validate_credential(
                credential,
                holder_did,
                &path_nested.format,
                &self.formatter_provider,
                self.build_key_verification(KeyRole::AssertionMethod),
                &self.revocation_method_provider,
            )
            .await?;

            let proved_claims: Vec<ValidatedProofClaimDTO> = validate_claims(
                credential,
                input_descriptor,
                &claim_to_credential_schema_mapping,
                &expected_credential_claims,
            )?;

            total_proved_claims.extend(proved_claims);
        }

        Ok(total_proved_claims)
    }

    fn build_key_verification(&self, key_role: KeyRole) -> Box<KeyVerification> {
        Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role,
        })
    }

    async fn accept_proof(
        &self,
        proof: Proof,
        proved_claims: Vec<ValidatedProofClaimDTO>,
    ) -> Result<(), ServiceError> {
        let proof_schema = proof.schema.as_ref().ok_or(ServiceError::MappingError(
            "proof schema is None".to_string(),
        ))?;

        struct ProvedClaim {
            claim_schema: ClaimSchema,
            value: String,
            credential: DetailCredential,
            credential_schema: CredentialSchema,
        }
        let proved_claims = proved_claims
            .into_iter()
            .map(|proved_claim| {
                Ok(ProvedClaim {
                    value: proved_claim.value,
                    credential: proved_claim.credential,
                    credential_schema: proved_claim.claim_schema.credential_schema.ok_or(
                        ServiceError::MappingError("credential schema is None".to_string()),
                    )?,
                    claim_schema: proved_claim.claim_schema.schema,
                })
            })
            .collect::<Result<Vec<ProvedClaim>, ServiceError>>()?;

        let mut claims_per_credential: HashMap<CredentialSchemaId, Vec<ProvedClaim>> =
            HashMap::new();
        for proved_claim in proved_claims {
            claims_per_credential
                .entry(proved_claim.credential_schema.id)
                .or_default()
                .push(proved_claim);
        }

        let mut proof_claims: Vec<Claim> = vec![];
        for (_, credential_claims) in claims_per_credential {
            let claims: Vec<(String, ClaimSchema)> = credential_claims
                .iter()
                .map(|claim| (claim.value.to_owned(), claim.claim_schema.to_owned()))
                .collect();

            let first_claim = credential_claims
                .first()
                .ok_or(ServiceError::MappingError("claims are empty".to_string()))?;
            let credential = &first_claim.credential;
            let issuer_did = credential
                .issuer_did
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "issuer_did is missing".to_string(),
                ))?;
            let issuer_did = get_or_create_did(
                &*self.did_repository,
                &proof_schema.organisation,
                issuer_did,
            )
            .await?;

            let holder_did = credential
                .subject
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "credential subject is missing".to_string(),
                ))
                .map_err(|e| ServiceError::MappingError(e.to_string()))?;
            let holder_did = get_or_create_did(
                &*self.did_repository,
                &proof_schema.organisation,
                holder_did,
            )
            .await?;

            let credential = extracted_credential_to_model(
                first_claim.credential_schema.to_owned(),
                claims,
                issuer_did,
                holder_did,
            );

            proof_claims.append(
                &mut credential
                    .claims
                    .as_ref()
                    .ok_or(ServiceError::MappingError("claims missing".to_string()))?
                    .to_owned(),
            );

            self.credential_repository
                .create_credential(credential)
                .await?;
        }

        self.proof_repository
            .set_proof_claims(&proof.id, proof_claims)
            .await?;

        let now = OffsetDateTime::now_utc();
        self.proof_repository
            .set_proof_state(
                &proof.id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: ProofStateEnum::Accepted,
                },
            )
            .await
            .map_err(ServiceError::from)
    }

    async fn mark_proof_as_failed(&self, id: &ProofId) -> Result<(), ServiceError> {
        let now = OffsetDateTime::now_utc();
        self.proof_repository
            .set_proof_state(
                id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: ProofStateEnum::Error,
                },
            )
            .await
            .map_err(ServiceError::from)
    }
}
