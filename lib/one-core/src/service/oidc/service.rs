use std::str::FromStr;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use dto_mapper::convert_inner;
use josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm;
use josekit::jwe::{JweDecrypter, JweHeader};
use one_crypto::imp::utilities;
use one_providers::common_models::key::OpenKey;
use one_providers::exchange_protocol::openid4vc::error::{OpenID4VCError, OpenID4VCIError};
use one_providers::exchange_protocol::openid4vc::model::{
    OpenID4VCICredentialOfferDTO, OpenID4VCICredentialRequestDTO, OpenID4VCIDiscoveryResponseDTO,
    OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
    OpenID4VPClientMetadata, OpenID4VPDirectPostRequestDTO, OpenID4VPDirectPostResponseDTO,
    OpenID4VPPresentationDefinition, RequestData,
};
use one_providers::exchange_protocol::openid4vc::proof_formatter::OpenID4VCIProofJWTFormatter;
use one_providers::exchange_protocol::openid4vc::service::{
    create_credential_offer, create_issuer_metadata_response,
    create_open_id_for_vp_client_metadata, create_service_discovery_response, credentials_format,
    get_credential_schema_base_url, parse_access_token, parse_refresh_token,
};
use one_providers::key_algorithm::error::KeyAlgorithmError;
use one_providers::key_algorithm::imp::eddsa::JwkEddsaExt;
use one_providers::key_storage::provider::KeyProvider;
use shared_types::{CredentialId, CredentialSchemaId, KeyId, ProofId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::OpenID4VCICredentialResponseDTO;
use super::mapper::{credential_from_proved, credentials_supported_mdoc};
use super::OIDCService;
use crate::common_mapper::{
    get_encryption_key_jwk_from_proof, get_exchange_param_pre_authorization_expires_in,
    get_exchange_param_refresh_token_expires_in, get_exchange_param_token_expires_in,
    get_or_create_did,
};
use crate::common_validator::{
    throw_if_latest_credential_state_not_eq, throw_if_latest_proof_state_not_eq,
};
use crate::config::core_config::{ExchangeType, TransportType};
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    CredentialRelations, CredentialState, CredentialStateEnum, CredentialStateRelations,
    UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::DidRelations;
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::interaction::InteractionRelations;
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{Proof, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations};
use crate::model::proof_schema::{
    ProofInputSchemaRelations, ProofSchemaClaimRelations, ProofSchemaRelations,
};
use crate::provider::exchange_protocol::openid4vc::mapper::{
    create_open_id_for_vp_formats, credentials_format_mdoc,
};
use crate::provider::exchange_protocol::openid4vc::model::{
    BLEOpenID4VPInteractionData, JwePayload,
};
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};
use crate::service::oidc::mapper::{interaction_data_to_dto, parse_interaction_content};
use crate::service::oidc::validator::{
    throw_if_credential_request_invalid, throw_if_interaction_data_invalid,
    validate_config_entity_presence,
};
use crate::service::ssi_validator::validate_exchange_type;
use crate::util::oidc::{
    map_core_to_oidc_format, map_from_oidc_format_to_core_real, map_from_oidc_vp_format_to_core,
};

impl OIDCService {
    pub async fn oidc_get_issuer_metadata(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let core_base_url = self
            .core_base_url
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "Host URL not specified".to_string(),
            ))?;

        let base_url =
            get_credential_schema_base_url(&credential_schema_id.to_owned().into(), core_base_url)?;

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

        let format = &self.config.format.get_fields(&schema.format)?;
        let oidc_format = map_core_to_oidc_format(&schema.format).map_err(ServiceError::from)?;

        let schema_type = schema.schema_type.to_string();

        match format.r#type.as_str() {
            "MDOC" => credentials_supported_mdoc(&base_url, schema),
            _ => create_issuer_metadata_response(
                &base_url,
                &oidc_format,
                &schema.schema_id,
                &schema_type,
                &schema.name,
                schema.wallet_storage_type,
            )
            .map_err(Into::into),
        }
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
        validate_exchange_type(ExchangeType::OpenId4Vc, &self.config, &proof.exchange)?;

        let formats = create_open_id_for_vp_formats();
        let jwk = get_encryption_key_jwk_from_proof(&proof, &*self.key_algorithm_provider)?;

        Ok(create_open_id_for_vp_client_metadata(
            jwk.key_id.into(),
            jwk.jwk.into(),
            formats,
        ))
    }

    pub async fn oidc_service_discovery(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIDiscoveryResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let core_base_url = self
            .core_base_url
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "Host URL not specified".to_string(),
            ))?;

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

        let schema_base_url = get_credential_schema_base_url(&schema.id.into(), core_base_url)?;

        Ok(create_service_discovery_response(&schema_base_url)?)
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
            .map_err(|_| ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidRequest))?;

        if credential.exchange != "OPENID4VC" {
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

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "Missing credential schema".to_owned(),
            ))?;

        let claims = credential
            .claims
            .as_ref()
            .ok_or(ServiceError::MappingError("Missing claims".to_owned()))?
            .iter()
            .map(|claim| claim.to_owned().into())
            .collect::<Vec<_>>();

        let format_type = &self
            .config
            .format
            .get_fields(&credential_schema.format)
            .map_err(|e| ServiceError::Other(e.to_string()))?
            .r#type;

        let wallet_storage_type = credential_schema.wallet_storage_type.clone();
        let oidc_format = map_core_to_oidc_format(&credential_schema.format)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        let credentials = match format_type.as_str() {
            "MDOC" => {
                credentials_format_mdoc(&credential_schema.clone().into(), &claims, &self.config)
            }
            _ => credentials_format(wallet_storage_type, &oidc_format, &claims),
        }?;

        let url = get_url(self.core_base_url.to_owned())?;

        Ok(create_credential_offer(
            &url,
            &interaction.id.to_string(),
            &credential_schema_id.into(),
            credentials,
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

        let interaction_id = parse_access_token(access_token)?.into();
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

        validate_exchange_type(ExchangeType::OpenId4Vc, &self.config, &credential.exchange)?;

        let holder_did = if request.proof.proof_type == "jwt" {
            let jwt = OpenID4VCIProofJWTFormatter::verify_proof(&request.proof.jwt).await?;
            let holder_did_value = jwt
                .header
                .key_id
                .ok_or(ServiceError::OpenID4VCIError(
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
            Err(ServiceError::OpenID4VCIError(
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

        let Some(credential_schema) = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id, &CredentialSchemaRelations::default())
            .await?
        else {
            return Err(EntityNotFoundError::CredentialSchema(*credential_schema_id).into());
        };

        let interaction_id = match &request {
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code,
            } => Uuid::from_str(pre_authorized_code).map_err(|_| {
                ServiceError::OpenID4VCError(OpenID4VCError::OpenID4VCI(
                    OpenID4VCIError::InvalidRequest,
                ))
            })?,
            OpenID4VCITokenRequestDTO::RefreshToken { refresh_token } => {
                parse_refresh_token(refresh_token)?.into()
            }
        };

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

        let credential = credentials
            .first()
            .ok_or(BusinessLogicError::MissingCredentialsForInteraction { interaction_id })?;

        validate_exchange_type(ExchangeType::OpenId4Vc, &self.config, &credential.exchange)?;

        let mut interaction = credential
            .interaction
            .clone()
            .ok_or(ServiceError::MappingError(
                "interaction is None".to_string(),
            ))?;

        // both refresh and access token have the same structure
        let generate_new_token = || {
            format!(
                "{}.{}",
                interaction_id,
                utilities::generate_alphanumeric(32)
            )
        };

        let pre_authorization_expires_in =
            get_exchange_param_pre_authorization_expires_in(&self.config, &credential.exchange)?;
        let access_token_expires_in =
            get_exchange_param_token_expires_in(&self.config, &credential.exchange)?;
        let refresh_token_expires_in =
            get_exchange_param_refresh_token_expires_in(&self.config, &credential.exchange)?;

        let mut interaction_data =
            one_providers::exchange_protocol::openid4vc::service::oidc_create_token(
                interaction_data_to_dto(&interaction)?,
                &convert_inner(credentials.to_owned()),
                &interaction.to_owned().into(),
                &request,
                pre_authorization_expires_in,
                access_token_expires_in,
                refresh_token_expires_in,
            )?;

        let now = OffsetDateTime::now_utc();
        if let OpenID4VCITokenRequestDTO::PreAuthorizedCode { .. } = &request {
            for credential in &credentials {
                self.credential_repository
                    .update_credential(UpdateCredentialRequest {
                        id: credential.id,
                        state: Some(CredentialState {
                            created_date: now,
                            state: CredentialStateEnum::Offered,
                            suspend_end_date: None,
                        }),
                        ..Default::default()
                    })
                    .await?;
            }

            // we add refresh token for mdoc
            if credential_schema.format == "MDOC" {
                interaction_data.refresh_token = Some(generate_new_token());

                interaction_data.refresh_token_expires_at = Some(now + refresh_token_expires_in);
            }
        }

        let data = serde_json::to_vec(&interaction_data)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        interaction.data = Some(data);

        self.interaction_repository
            .update_interaction(interaction)
            .await?;

        interaction_data.try_into().map_err(Into::into)
    }

    // TODO (Eugeniu) - this method is used as part of the OIDC BLE flow
    // as soon as ONE-2754 is finalized, we should remove this method, and move
    // all logic to the provider instead. This is a temporary solution.
    pub async fn oidc_verifier_ble_presentation(
        &self,
        proof_id: &ProofId,
    ) -> Result<(), ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let (proof, presentation_submission) = loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            let proof = self
                .proof_repository
                .get_proof(
                    proof_id,
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
                .await?
                .ok_or(ServiceError::EntityNotFound(EntityNotFoundError::Proof(
                    *proof_id,
                )))?;

            if proof.transport != TransportType::Ble.to_string() {
                return Err(OpenID4VCIError::InvalidRequest.into());
            };

            let proof_state = proof
                .state
                .as_ref()
                .ok_or(ServiceError::MappingError("state is None".to_string()))?
                .first()
                .ok_or(ServiceError::MappingError("state is empty".to_string()))?;

            let state = proof_state.state.clone();

            if state.eq(&ProofStateEnum::Created)
                || state.eq(&ProofStateEnum::Accepted)
                || state.eq(&ProofStateEnum::Rejected)
                || state.eq(&ProofStateEnum::Error)
            {
                return Ok(());
            }

            if let Some(data) = proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref())
            {
                if let Ok(interaction_data) =
                    serde_json::from_slice::<BLEOpenID4VPInteractionData>(data)
                {
                    if let Some(ble_response) = interaction_data.presentation_submission {
                        let state =
                            Uuid::from_str(&ble_response.presentation_submission.definition_id)
                                .map_err(|e| {
                                    ServiceError::MappingError(format!(
                                        "Failed to parse BLE interaction data: {:?}",
                                        e.to_string()
                                    ))
                                })?;

                        let request_data = RequestData {
                            presentation_submission: ble_response.presentation_submission,
                            vp_token: ble_response.vp_token,
                            state,
                            mdoc_generated_nonce: None,
                        };

                        break Ok((proof, request_data)) as Result<_, ServiceError>;
                    }
                }
            }
        }?;

        self.oidc_verifier_verify_submission(proof, presentation_submission)
            .await?;
        Ok(())
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
            .await?
            .ok_or(ServiceError::BusinessLogic(
                BusinessLogicError::MissingProofForInteraction(interaction_id),
            ))?;

        self.oidc_verifier_verify_submission(proof, unpacked_request)
            .await
    }

    pub async fn oidc_verifier_verify_submission(
        &self,
        proof: Proof,
        unpacked_request: RequestData,
    ) -> Result<OpenID4VPDirectPostResponseDTO, ServiceError> {
        let organisation = proof
            .schema
            .as_ref()
            .ok_or(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ))?
            .organisation
            .as_ref()
            .ok_or(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ))?;

        validate_exchange_type(ExchangeType::OpenId4Vc, &self.config, &proof.exchange)?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ))?;

        let interaction_data = interaction
            .data
            .as_ref()
            .ok_or(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ))?;

        match one_providers::exchange_protocol::openid4vc::service::oidc_verifier_direct_post(
            unpacked_request,
            proof.to_owned().into(),
            interaction_data,
            &self.did_method_provider,
            &self.formatter_provider,
            &self.key_algorithm_provider,
            &self.revocation_method_provider,
            map_from_oidc_vp_format_to_core,
            map_from_oidc_format_to_core_real,
        )
        .await
        {
            Ok((accept_proof_result, response)) => {
                for proved_credential in accept_proof_result.proved_credentials {
                    let credential = credential_from_proved(
                        proved_credential,
                        organisation,
                        &*self.did_repository,
                    )
                    .await?;

                    self.credential_repository
                        .create_credential(credential)
                        .await?;
                }

                self.proof_repository
                    .set_proof_claims(&proof.id, convert_inner(accept_proof_result.proved_claims))
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
                    .map_err(ServiceError::from)?;

                Ok(response)
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

                Err(err.into())
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

        validate_exchange_type(ExchangeType::OpenId4Vc, &self.config, &proof.exchange)?;
        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            ))?;

        let interaction_data = parse_interaction_content(interaction.data.as_ref())?;

        Ok(one_providers::exchange_protocol::openid4vc::service::oidc_verifier_presentation_definition(proof.into(), interaction_data)?)
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
                    .get_key(&key_id.to_owned().into(), &KeyRelations::default())
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
            _ => Err(ServiceError::OpenID4VCIError(
                OpenID4VCIError::InvalidRequest,
            )),
        }
    }
}

fn extract_jwe_header(jwe: &str) -> Result<JweHeader, anyhow::Error> {
    let header_b64 = jwe
        .split('.')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid JWE"))?;

    let header = Base64UrlSafeNoPadding::decode_to_vec(header_b64, None)?;
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&header)?;

    Ok(JweHeader::from_map(map)?)
}

fn build_jwe_decrypter(
    key_provider: &dyn KeyProvider,
    key: &OpenKey,
) -> Result<impl JweDecrypter, ServiceError> {
    let key_storage = key_provider
        .get_key_storage(&key.storage_type)
        .ok_or_else(|| MissingProviderError::KeyStorage(key.storage_type.clone()))?;

    let jwk = key_storage.secret_key_as_jwk(&key.to_owned())?;
    let mut jwk = josekit::jwk::Jwk::from_bytes(jwk.as_bytes())
        .map_err(|err| ServiceError::MappingError(format!("Failed constructing JWK {err}")))?;

    if let Some("Ed25519") = jwk.curve() {
        jwk = jwk.into_x25519().map_err(|err| {
            KeyAlgorithmError::Failed(format!("Cannot convert Ed25519 into X25519: {err}"))
        })?;
    };

    EcdhEsJweAlgorithm::EcdhEs
        .decrypter_from_jwk(&jwk)
        .map_err(|err| ServiceError::Other(format!("Failed constructing EcdhEs decrypter: {err}")))
}

fn get_url(base_url: Option<String>) -> Result<String, ServiceError> {
    base_url.ok_or(ServiceError::Other("Missing base_url".to_owned()))
}
