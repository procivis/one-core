use crate::common_mapper::{
    get_exchange_param_pre_authorization_expires_in, get_exchange_param_token_expires_in,
    get_or_create_did,
};
use crate::common_validator::{
    throw_if_latest_credential_state_not_eq, throw_if_latest_proof_state_not_eq,
};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchemaId;
use crate::model::credential::{
    CredentialRelations, CredentialState, CredentialStateEnum, CredentialStateRelations,
    UpdateCredentialRequest,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaId, CredentialSchemaRelations,
};
use crate::model::interaction::InteractionRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{
    ProofId, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations,
};
use crate::model::proof_schema::{
    ProofSchemaClaim, ProofSchemaClaimRelations, ProofSchemaRelations,
};

use crate::service::error::ServiceError;
use crate::service::oidc::dto::{
    OpenID4VCICredentialRequestDTO, OpenID4VCICredentialResponseDTO, OpenID4VCIError,
};
use crate::service::oidc::mapper::{
    interaction_data_to_dto, parse_access_token, vec_last_position_from_token_path,
};
use crate::service::oidc::model::OpenID4VPInteractionContent;
use crate::service::oidc::validator::{
    throw_if_credential_request_invalid, throw_if_interaction_created_date,
    throw_if_interaction_data_invalid, throw_if_interaction_pre_authorized_code_used,
    throw_if_token_request_invalid, validate_claims, validate_credential, validate_presentation,
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
use std::collections::HashMap;
use std::ops::Add;
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{OpenID4VPDirectPostRequestDTO, OpenID4VPDirectPostResponseDTO};

impl OIDCService {
    pub async fn oidc_get_issuer_metadata(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
        let (base_url, schema) = self
            .get_credential_schema_base_url(credential_schema_id)
            .await?;

        create_issuer_metadata_response(base_url, schema)
    }

    pub async fn oidc_service_discovery(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIDiscoveryResponseDTO, ServiceError> {
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

    pub async fn oidc_create_credential(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        request: OpenID4VCICredentialRequestDTO,
    ) -> Result<OpenID4VCICredentialResponseDTO, ServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    organisation: Some(OrganisationRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?;

        throw_if_credential_request_invalid(&schema, &request)?;

        let interaction_id = parse_access_token(access_token)?;
        let interaction = self
            .interaction_repository
            .get_interaction(&interaction_id, &InteractionRelations::default())
            .await
            .map_err(ServiceError::from)?;

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
            .await
            .map_err(ServiceError::from)?;

        if credentials.is_empty() {
            return Err(ServiceError::NotFound);
        }

        let credential = credentials
            .first()
            .ok_or(ServiceError::NotFound)?
            .to_owned();

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
                &self.did_repository,
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
                ..Default::default()
            })
            .await?;

        let credential = self
            .protocol_provider
            .issue_credential(&credential.id)
            .await?;

        Ok(OpenID4VCICredentialResponseDTO {
            credential: credential.credential,
            format: request.format,
        })
    }

    pub async fn oidc_create_token(
        &self,
        credential_schema_id: &CredentialSchemaId,
        request: OpenID4VCITokenRequestDTO,
    ) -> Result<OpenID4VCITokenResponseDTO, ServiceError> {
        throw_if_token_request_invalid(&request)?;

        self.credential_schema_repository
            .get_credential_schema(credential_schema_id, &CredentialSchemaRelations::default())
            .await
            .map_err(ServiceError::from)?;

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
            .await
            .map_err(ServiceError::from)?;

        if credentials.is_empty() {
            return Err(ServiceError::NotFound);
        }
        let now = OffsetDateTime::now_utc();

        let mut interaction = credentials
            .first()
            .ok_or(ServiceError::MappingError("credentials none".to_string()))?
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
                    ..Default::default()
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
        let interaction_id = request.state;

        let proof_request = self
            .proof_repository
            .get_proof_by_interaction_id(
                &interaction_id,
                &ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations {
                            credential_schema: Some(CredentialSchemaRelations::default()),
                        }),
                        ..Default::default()
                    }),
                    interaction: Some(InteractionRelations::default()),
                    state: Some(ProofStateRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let interaction =
            proof_request
                .interaction
                .as_ref()
                .ok_or(ServiceError::OpenID4VCError(
                    OpenID4VCIError::InvalidRequest,
                ))?;

        let interaction_data: OpenID4VPInteractionContent =
            if let Some(interaction_data) = interaction.data.as_ref() {
                serde_json::from_slice(interaction_data)
                    .map_err(|e| ServiceError::MappingError(e.to_string()))
            } else {
                Err(ServiceError::MappingError(
                    "Interaction data is missing or incorrect".to_string(),
                ))
            }?;

        throw_if_latest_proof_state_not_eq(&proof_request, ProofStateEnum::Pending)?;

        let presentation_submission = &request.presentation_submission;

        if presentation_submission.definition_id != interaction_id.to_string() {
            return Err(OpenID4VCIError::InvalidRequest.into());
        }

        let presentation_strings: Vec<String> = if request.vp_token.starts_with('[') {
            serde_json::from_str(&request.vp_token).map_err(|_| OpenID4VCIError::InvalidRequest)?
        } else {
            vec![request.vp_token]
        };

        // collect expected credentials
        let mut claim_to_credential_schema_mapping: HashMap<ClaimSchemaId, CredentialSchemaId> =
            HashMap::new();
        let mut expected_credential_claims: HashMap<CredentialSchemaId, Vec<&ProofSchemaClaim>> =
            HashMap::new();
        if let Some(proof_schema) = &proof_request.schema {
            if let Some(claim_schemas) = &proof_schema.claim_schemas {
                for proof_claim_schema in claim_schemas {
                    if let Some(credential_schema) = &proof_claim_schema.credential_schema {
                        let entry = expected_credential_claims
                            .entry(credential_schema.id)
                            .or_default();
                        entry.push(proof_claim_schema);
                        claim_to_credential_schema_mapping
                            .insert(proof_claim_schema.schema.id, credential_schema.id);
                    }
                }
            }
        }

        let key_verification = KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
        };

        let mut total_proved_claims: Vec<(ProofSchemaClaim, String)> = Vec::new();
        //Unpack presentations and credentials
        for presentation_submitted in &presentation_submission.descriptor_map {
            let credential_definition = interaction_data
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
                Box::new(key_verification.clone()),
            )
            .await?;

            if let Some(path_nested) = &presentation_submitted.path_nested {
                let credential_index = vec_last_position_from_token_path(&path_nested.path)?;
                let credential_string = presentation
                    .credentials
                    .get(credential_index)
                    .ok_or(OpenID4VCIError::InvalidRequest)?;

                let credential = validate_credential(
                    credential_string,
                    presentation
                        .issuer_did
                        .as_ref()
                        .ok_or(ServiceError::ValidationError(
                            "Missing holder id".to_string(),
                        ))?,
                    &path_nested.format,
                    &self.formatter_provider,
                    Box::new(key_verification.clone()),
                    &self.revocation_method_provider,
                )
                .await?;

                let proved_claims: Vec<(ProofSchemaClaim, String)> = validate_claims(
                    credential,
                    credential_definition,
                    &claim_to_credential_schema_mapping,
                    &mut expected_credential_claims,
                )?;

                total_proved_claims.extend(proved_claims);
            }
        }

        self.accept_proof(&proof_request.id, total_proved_claims)
            .await?;

        Ok(OpenID4VPDirectPostResponseDTO { redirect_uri: None })
    }

    async fn accept_proof(
        &self,
        id: &ProofId,
        proved_claims: Vec<(ProofSchemaClaim, String)>,
    ) -> Result<(), ServiceError> {
        let now = OffsetDateTime::now_utc();
        let claims: Vec<Claim> = proved_claims
            .into_iter()
            .map(|(proof_schema, value)| Claim {
                id: Uuid::new_v4(),
                created_date: now,
                last_modified: now,
                value,
                schema: Some(proof_schema.schema),
            })
            .collect();

        self.claim_repository
            .create_claim_list(claims.clone())
            .await?;
        self.proof_repository.set_proof_claims(id, claims).await?;

        self.proof_repository
            .set_proof_state(
                id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: ProofStateEnum::Accepted,
                },
            )
            .await
            .map_err(ServiceError::from)
    }
}
