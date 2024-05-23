use crate::common_mapper::{
    extracted_credential_to_model, get_encryption_key_jwk_from_proof,
    get_exchange_param_pre_authorization_expires_in, get_exchange_param_token_expires_in,
    get_or_create_did,
};
use crate::common_validator::{
    throw_if_latest_credential_state_not_eq, throw_if_latest_proof_state_not_eq,
};
use crate::model::claim::{Claim, ClaimRelations};
use crate::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use crate::model::credential::{
    CredentialRelations, CredentialState, CredentialStateEnum, CredentialStateRelations,
    UpdateCredentialRequest,
};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::model::did::{DidRelations, KeyRole};
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::interaction::InteractionRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{
    Proof, ProofId, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations,
};
use crate::model::proof_schema::{
    ProofInputSchemaRelations, ProofSchemaClaimRelations, ProofSchemaRelations,
};

use crate::model::key::{Key, KeyRelations};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::credential_formatter::ExtractPresentationCtx;
use crate::provider::key_algorithm::eddsa::JwkEddsaExt;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::transport_protocol::openid4vc::dto::{
    OpenID4VCICredentialOfferDTO, OpenID4VPClientMetadata,
};
use crate::provider::transport_protocol::openid4vc::mapper::{
    create_credential_offer, create_open_id_for_vp_client_metadata,
};
use crate::provider::transport_protocol::openid4vc::model::JwePayload;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};
use crate::service::oidc::dto::{
    OpenID4VCICredentialRequestDTO, OpenID4VCICredentialResponseDTO, OpenID4VCIError,
    PresentationSubmissionMappingDTO,
};
use crate::service::oidc::mapper::{
    interaction_data_to_dto, parse_access_token, parse_interaction_content,
    vec_last_position_from_token_path,
};
use crate::service::oidc::model::OpenID4VPPresentationDefinition;
use crate::service::oidc::validator::{
    peek_presentation, throw_if_credential_request_invalid, throw_if_interaction_created_date,
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
use crate::util::oidc::map_from_oidc_format_to_core_real;
use crate::util::proof_formatter::OpenID4VCIProofJWTFormatter;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm;
use josekit::jwe::{JweDecrypter, JweHeader};
use shared_types::{CredentialId, CredentialSchemaId, KeyId};
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

        create_issuer_metadata_response(base_url, schema, &self.config)
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
                    verifier_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    verifier_key: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Proof(id)))?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;
        validate_transport_type(&self.config, &proof.transport)?;

        Ok(create_open_id_for_vp_client_metadata(
            get_encryption_key_jwk_from_proof(&proof, &self.key_algorithm_provider)?,
        ))
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
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    ..Default::default()
                },
            )
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
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                        ..Default::default()
                    }),
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
            &self.config,
        )?)
    }

    pub async fn oidc_create_credential(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        request: OpenID4VCICredentialRequestDTO,
    ) -> Result<OpenID4VCICredentialResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let Some(schema) = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    organisation: Some(OrganisationRelations::default()),
                    ..Default::default()
                },
            )
            .await?
        else {
            return Err(EntityNotFoundError::CredentialSchema(*credential_schema_id).into());
        };

        throw_if_credential_request_invalid(&schema, &request)?;

        let interaction_id = parse_access_token(access_token)?;
        let Some(interaction) = self
            .interaction_repository
            .get_interaction(&interaction_id, &InteractionRelations::default())
            .await?
        else {
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
            .issue_credential(&credential.id, holder_did)
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
                        suspend_end_date: None,
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

        let unpacked_request = self.unpack_direct_post_request(request).await?;

        let interaction_id = unpacked_request.state;

        let proof = self
            .proof_repository
            .get_proof_by_interaction_id(
                &interaction_id,
                &ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations::default()),
                                ..Default::default()
                            }),
                        }),
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

        match self
            .process_proof_submission(unpacked_request, &proof)
            .await
        {
            Ok(proved_claims) => {
                let redirect_uri = proof.redirect_uri.to_owned();
                self.accept_proof(proof, proved_claims).await?;
                Ok(OpenID4VPDirectPostResponseDTO { redirect_uri })
            }
            Err(err) => {
                self.mark_proof_as_failed(&proof.id).await?;

                let _ = self
                    .history_repository
                    .create_history(History {
                        id: Uuid::new_v4().into(),
                        created_date: OffsetDateTime::now_utc(),
                        action: HistoryAction::Errored,
                        entity_id: Some(proof.id.into()),
                        entity_type: HistoryEntityType::Proof,
                        metadata: None,
                        organisation: proof.schema.and_then(|schema| schema.organisation),
                    })
                    .await;

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
                    schema: Some(ProofSchemaRelations {
                        proof_inputs: Some(ProofInputSchemaRelations {
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
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

        let proof_schema = proof.schema.as_ref().ok_or(ServiceError::MappingError(
            "Proof schema not found".to_string(),
        ))?;

        let proof_schema_inputs = match proof_schema.input_schemas.as_ref() {
            Some(input_schemas) if !input_schemas.is_empty() => input_schemas.to_vec(),
            _ => {
                return Err(ServiceError::MappingError(
                    "input_schemas are missing".to_string(),
                ))
            }
        };

        if proof_schema_inputs.len()
            != interaction_data
                .presentation_definition
                .input_descriptors
                .len()
        {
            return Err(ServiceError::Other(
                "Proof schema inputs length doesn't match interaction data input descriptors length"
                    .to_owned(),
            ));
        }

        let now = OffsetDateTime::now_utc();
        interaction_data
            .presentation_definition
            .input_descriptors
            .iter_mut()
            .zip(proof_schema_inputs)
            .for_each(|(input_descriptor, proof_schema_input)| {
                if let Some(validity_constraint) = proof_schema_input.validity_constraint {
                    input_descriptor.constraints.validity_credential_nbf =
                        Some(now.sub(Duration::seconds(validity_constraint)));
                }
            });

        Ok(interaction_data.presentation_definition)
    }

    async fn extract_lvvcs(
        &self,
        presentation_strings: &[String],
        presentation_submission: &PresentationSubmissionMappingDTO,
    ) -> Result<Vec<DetailCredential>, ServiceError> {
        let mut result = vec![];

        for presentation_submitted in &presentation_submission.descriptor_map {
            let presentation_string_index =
                vec_last_position_from_token_path(&presentation_submitted.path)?;
            let presentation_string = presentation_strings
                .get(presentation_string_index)
                .ok_or(OpenID4VCIError::InvalidRequest)?;

            let presentation = peek_presentation(
                presentation_string,
                &presentation_submitted.format,
                &self.formatter_provider,
            )
            .await?;

            let path_nested = presentation_submitted
                .path_nested
                .as_ref()
                .ok_or(OpenID4VCIError::InvalidRequest)?;

            let credential_index = vec_last_position_from_token_path(&path_nested.path)?;
            let credential = presentation
                .credentials
                .get(credential_index)
                .ok_or(OpenID4VCIError::InvalidRequest)?;

            let oidc_format = &path_nested.format;
            let format = map_from_oidc_format_to_core_real(oidc_format, credential)?;
            let formatter = &self
                .formatter_provider
                .get_formatter(&format)
                .ok_or(OpenID4VCIError::VCFormatsNotSupported)?;

            let credential = formatter
                .extract_credentials_unverified(credential)
                .await
                .map_err(|e| {
                    if matches!(e, FormatterError::CouldNotExtractCredentials(_)) {
                        OpenID4VCIError::VCFormatsNotSupported.into()
                    } else {
                        ServiceError::Other(e.to_string())
                    }
                })?;

            if credential.is_lvvc() {
                result.push(credential);
            }
        }

        Ok(result)
    }

    async fn process_proof_submission(
        &self,
        submission: RequestData,
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

        let definition_id = presentation_submission.definition_id.clone();
        let vp_token = submission.vp_token;
        let state = submission.state;

        if definition_id != state.to_string() {
            return Err(OpenID4VCIError::InvalidRequest.into());
        }

        let presentation_strings: Vec<String> = if vp_token.starts_with('[') {
            serde_json::from_str(&vp_token).map_err(|_| OpenID4VCIError::InvalidRequest)?
        } else {
            vec![vp_token]
        };

        // collect expected credentials
        let proof_schema = proof.schema.as_ref().ok_or(ServiceError::MappingError(
            "missing proof schema".to_string(),
        ))?;

        let proof_schema_inputs = match proof_schema.input_schemas.as_ref() {
            Some(input_schemas) if !input_schemas.is_empty() => input_schemas.to_vec(),
            _ => {
                return Err(ServiceError::Other("Missing proof input schema".to_owned()));
            }
        };

        let extracted_lvvcs = self
            .extract_lvvcs(&presentation_strings, presentation_submission)
            .await?;

        if presentation_submission.descriptor_map.len()
            != (interaction_data
                .presentation_definition
                .input_descriptors
                .len()
                + extracted_lvvcs.len())
        {
            // different count of requested and submitted credentials
            return Err(OpenID4VCIError::InvalidRequest.into());
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

            let context = if &presentation_submitted.format == "mso_mdoc" {
                let mut ctx = ExtractPresentationCtx::from(interaction_data.clone());
                if let Some(mdoc_generated_nonce) = submission.mdoc_generated_nonce.clone() {
                    ctx = ctx.with_mdoc_generated_nonce(mdoc_generated_nonce);
                }

                ctx
            } else {
                ExtractPresentationCtx::empty()
            };

            let presentation = validate_presentation(
                presentation_string,
                &interaction_data.nonce,
                &presentation_submitted.format,
                &self.formatter_provider,
                self.build_key_verification(KeyRole::Authentication),
                context,
            )
            .await?;

            let path_nested = presentation_submitted
                .path_nested
                .as_ref()
                .ok_or(OpenID4VCIError::InvalidRequest)?;

            // ONE-1924: there must be a specific schemaId filter
            let schema_id_filter = input_descriptor
                .constraints
                .fields
                .iter()
                .find(|field| {
                    field.filter.is_some()
                        && field.path.contains(&"$.credentialSchema.id".to_string())
                })
                .ok_or(ServiceError::OpenID4VCError(
                    OpenID4VCIError::InvalidRequest,
                ))?
                .filter
                .as_ref()
                .ok_or(ServiceError::OpenID4VCError(
                    OpenID4VCIError::InvalidRequest,
                ))?;

            let proof_schema_input = proof_schema_inputs
                .iter()
                .find(|input| {
                    input
                        .credential_schema
                        .as_ref()
                        .is_some_and(|schema| schema.schema_id == schema_id_filter.r#const)
                })
                .ok_or(ServiceError::Other(
                    "Missing proof input schema for credential schema".to_owned(),
                ))?;

            let credential = validate_credential(
                presentation,
                path_nested,
                &extracted_lvvcs,
                proof_schema_input,
                &self.formatter_provider,
                self.build_key_verification(KeyRole::AssertionMethod),
                &self.revocation_method_provider,
            )
            .await?;

            if credential.is_lvvc() {
                continue;
            }

            let proved_claims: Vec<ValidatedProofClaimDTO> =
                validate_claims(credential, proof_schema_input)?;

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
        let claim_schemas = proof_schema
            .input_schemas
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "input schemas is None".to_string(),
            ))?
            .first()
            .ok_or(ServiceError::MappingError(
                "input schemas are empty".to_string(),
            ))?
            .credential_schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "credential_schema is None".to_string(),
            ))?
            .claim_schemas
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "claim schemas is None".to_string(),
            ))?;

        struct ProvedClaim {
            claim_schema: ClaimSchema,
            value: serde_json::Value,
            credential: DetailCredential,
            credential_schema: CredentialSchema,
        }
        let proved_claims = proved_claims
            .into_iter()
            .map(|proved_claim| {
                Ok(ProvedClaim {
                    value: proved_claim.value,
                    credential: proved_claim.credential,
                    credential_schema: proved_claim.credential_schema,
                    claim_schema: proved_claim.proof_input_claim.schema,
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
            let claims: Vec<(serde_json::Value, ClaimSchema)> = credential_claims
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
                claim_schemas,
                first_claim.credential_schema.to_owned(),
                claims,
                issuer_did,
                holder_did,
            )?;

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

    async fn unpack_direct_post_request(
        &self,
        request: OpenID4VPDirectPostRequestDTO,
    ) -> Result<RequestData, ServiceError> {
        match request {
            OpenID4VPDirectPostRequestDTO {
                presentation_submission: Some(presentation_submission),
                vp_token: Some(vp_token),
                state: Some(state),
                response: None,
            } => Ok(RequestData {
                presentation_submission,
                vp_token,
                state,
                mdoc_generated_nonce: None,
            }),
            OpenID4VPDirectPostRequestDTO {
                response: Some(jwe),
                ..
            } => {
                let jwe_header = extract_jwe_header(&jwe).map_err(|err| {
                    ServiceError::Other(format!("Failed parsing JWE header: {err}"))
                })?;

                let key_id = jwe_header.key_id().ok_or_else(|| {
                    ServiceError::ValidationError("JWE header is missing key_id".to_string())
                })?;
                let key_id = KeyId::from_str(key_id).map_err(|err| {
                    ServiceError::ValidationError(format!("JWE key_id value invalid format: {err}"))
                })?;

                let key = self
                    .key_repository
                    .get_key(&key_id, &KeyRelations::default())
                    .await?
                    .ok_or_else(|| {
                        ServiceError::ValidationError("Invalid JWE key_id".to_string())
                    })?;

                let decrypter = build_jwe_decrypter(&*self.key_provider, &key)?;

                let (payload, _) = josekit::jwe::deserialize_compact(&jwe, &decrypter).unwrap();

                let payload = JwePayload::try_from_json_base64_decode(&payload).map_err(|err| {
                    ServiceError::Other(format!("Failed deserializing JWE payload: {err}"))
                })?;

                let mdoc_generated_nonce = jwe_header
                    .agreement_partyuinfo()
                    .and_then(|nonce| String::from_utf8(nonce).ok());

                Ok(RequestData {
                    presentation_submission: payload.presentation_submission,
                    vp_token: payload.vp_token,
                    state: payload.state.parse()?,
                    mdoc_generated_nonce,
                })
            }
            _ => Err(ServiceError::OpenID4VCError(
                OpenID4VCIError::InvalidRequest,
            )),
        }
    }
}

#[derive(Debug)]
struct RequestData {
    pub presentation_submission: PresentationSubmissionMappingDTO,
    pub vp_token: String,
    pub state: Uuid,
    pub mdoc_generated_nonce: Option<String>,
}

fn extract_jwe_header(jwe: &str) -> Result<JweHeader, anyhow::Error> {
    let header_b64 = jwe
        .split(|c| c == '.')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid JWE"))?;

    let header = Base64UrlSafeNoPadding::decode_to_vec(header_b64, None)?;
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&header)?;

    Ok(JweHeader::from_map(map)?)
}

fn build_jwe_decrypter(
    key_provider: &dyn KeyProvider,
    key: &Key,
) -> Result<impl JweDecrypter, ServiceError> {
    let key_storage = key_provider
        .get_key_storage(&key.storage_type)
        .ok_or_else(|| MissingProviderError::KeyStorage(key.storage_type.clone()))?;

    let jwk = key_storage.secret_key_as_jwk(key)?;
    let mut jwk = josekit::jwk::Jwk::from_bytes(jwk.as_bytes())
        .map_err(|err| ServiceError::MappingError(format!("Failed constructing JWK {err}")))?;

    if let Some("Ed25519") = jwk.curve() {
        jwk = jwk.into_x25519().map_err(|err| {
            ServiceError::KeyAlgorithmError(format!("Cannot convert Ed25519 into X25519: {err}"))
        })?;
    };

    EcdhEsJweAlgorithm::EcdhEs
        .decrypter_from_jwk(&jwk)
        .map_err(|err| ServiceError::Other(format!("Failed constructing EcdhEs decrypter: {err}")))
}
