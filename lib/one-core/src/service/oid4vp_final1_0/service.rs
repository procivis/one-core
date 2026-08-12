use std::borrow::Cow;
use std::str::FromStr;

use one_crypto::jwe::{decrypt_jwe_payload, extract_jwe_header};
use shared_types::{BlobId, KeyId, ProofId};
use standardized_types::openid4vp::{
    ClientIdPrefix, ClientMetadata, DirectPostResponse, EncryptedResponse, VerifierInfoAttestation,
    VerifierInfoAttestationFormat,
};
use tracing::warn;

use super::OID4VPFinal1_0Service;
use super::error::OID4VPFinal1_0ServiceError;
use super::proof_request::{
    generate_authorization_request_params_final1_0, select_key_agreement_key_from_proof,
};
use crate::clock::now_utc;
use crate::config::core_config::{BlobStorageType, VerificationProtocolType};
use crate::error::ErrorCode::BR_0000;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::blob::{Blob, BlobType};
use crate::model::history::HistoryErrorMetadata;
use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::identifier_trust_information::IdentifierTrustInformation;
use crate::model::key::KeyRelations;
use crate::model::proof::{Proof, ProofRelations, ProofStateEnum, UpdateProofRequest};
use crate::proto::openid4vp_proof_validator::ValidatedProofResult;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::final1_0::mappers::{
    create_open_id_for_vp_client_metadata_final1_0, decode_client_id_with_scheme,
};
use crate::provider::verification_protocol::openid4vp::mapper::{
    format_authorization_request_client_id_scheme_did,
    format_authorization_request_client_id_scheme_redirect_uri,
    format_authorization_request_client_id_scheme_verifier_attestation,
    format_authorization_request_client_id_scheme_x509,
};
use crate::provider::verification_protocol::openid4vp::model::{
    CommonVerifierInteractionContent, JwePayload, OpenID4VPDirectPostRequestDTO,
    OpenID4VPVerifierInteractionContent, SubmissionRequestData, VpSubmissionData,
};
use crate::repository::error::DataLayerError;
use crate::service::ssi_validator::validate_verification_protocol_type;
use crate::util::openid4vp::persist_accepted_proof;
use crate::validator::{throw_if_proof_state_not_eq, validate_verification_protocol_config_exists};

impl OID4VPFinal1_0Service {
    pub async fn get_client_request(
        &self,
        id: ProofId,
    ) -> Result<String, OID4VPFinal1_0ServiceError> {
        validate_verification_protocol_config_exists(
            &self.config,
            &[
                VerificationProtocolType::OpenId4VpFinal1_0,
                VerificationProtocolType::OpenId4VpFinal1_0Swiyu,
            ],
        )
        .error_while("checking config")?;

        let proof = self
            .proof_repository
            .get_proof(
                &id,
                &ProofRelations {
                    interaction: Some(Default::default()),
                    verifier_identifier: Some(IdentifierRelations {}),
                    verifier_key: Some(Default::default()),
                    verifier_certificate: Some(Default::default()),
                    schema: Some(Default::default()),
                    ..Default::default()
                },
                None,
            )
            .await
            .error_while("getting proof")?;

        throw_if_proof_state_not_eq(&proof, ProofStateEnum::Pending)
            .error_while("checking proof state")?;
        validate_verification_protocol_type(
            &[
                VerificationProtocolType::OpenId4VpFinal1_0,
                VerificationProtocolType::OpenId4VpFinal1_0Swiyu,
            ],
            &self.config,
            &proof.protocol,
        )
        .error_while("validating protocol type")?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(OID4VPFinal1_0ServiceError::MissingInteractionData)?;

        let interaction_data = interaction
            .data
            .as_ref()
            .ok_or(OID4VPFinal1_0ServiceError::MissingInteractionData)?;

        let OpenID4VPVerifierInteractionContent {
            nonce,
            dcql_query: Some(dcql_query),
            client_id,
            response_uri: Some(response_uri),
            client_id_scheme: Some(client_id_scheme),
            common: CommonVerifierInteractionContent { transaction_data },
            ..
        } = serde_json::from_slice(interaction_data)
            .map_err(OID4VPFinal1_0ServiceError::from)
            .error_while("parsing interaction data")?
        else {
            return Err(OID4VPFinal1_0ServiceError::MissingInteractionData);
        };

        let key_handle = select_key_agreement_key_from_proof(
            &proof,
            &*self.key_algorithm_provider,
            &self.config,
        )
        .await
        .error_while("selecting agreement key")?;

        let verifier_info = match client_id_scheme {
            ClientIdPrefix::X509SanDns | ClientIdPrefix::X509Hash => {
                let verifier_identifier = proof.verifier_identifier.as_ref().ok_or(
                    OID4VPFinal1_0ServiceError::MappingError("missing verifier".to_string()),
                )?;
                self.resolve_verifier_info(verifier_identifier)
                    .await
                    .error_while("generating verifier_info object")?
            }
            _ => vec![],
        };

        let transaction_data = transaction_data
            .into_iter()
            .map(|request| request.encoded)
            .collect();

        let authorization_request = generate_authorization_request_params_final1_0(
            nonce.clone(),
            dcql_query.clone(),
            transaction_data,
            client_id.clone(),
            response_uri.clone(),
            &interaction.id,
            create_open_id_for_vp_client_metadata_final1_0(key_handle)
                .error_while("creating metadata")?,
            verifier_info,
        )
        .error_while("generating authorization request")?;

        Ok(match client_id_scheme {
            ClientIdPrefix::RedirectUri => {
                format_authorization_request_client_id_scheme_redirect_uri(authorization_request)
                    .await
                    .error_while("formatting authorization request")?
            }
            ClientIdPrefix::VerifierAttestation => {
                let (client_id_without_prefix, _) = decode_client_id_with_scheme(&client_id, false)
                    .error_while("decoding clientId")?;

                format_authorization_request_client_id_scheme_verifier_attestation(
                    &proof,
                    &self.key_algorithm_provider,
                    &*self.key_provider,
                    client_id_without_prefix,
                    response_uri.clone(),
                    authorization_request,
                )
                .await
                .error_while("formatting authorization request")?
            }
            ClientIdPrefix::DecentralizedIdentifier => {
                format_authorization_request_client_id_scheme_did(
                    &proof,
                    &self.key_algorithm_provider,
                    &*self.key_provider,
                    authorization_request,
                )
                .await
                .error_while("formatting authorization request")?
            }
            ClientIdPrefix::X509SanDns | ClientIdPrefix::X509Hash => {
                format_authorization_request_client_id_scheme_x509(
                    &proof,
                    &self.key_algorithm_provider,
                    &*self.key_provider,
                    authorization_request,
                )
                .await
                .error_while("formatting authorization request")?
            }
        })
    }

    pub async fn get_client_metadata(
        &self,
        id: ProofId,
    ) -> Result<ClientMetadata, OID4VPFinal1_0ServiceError> {
        validate_verification_protocol_config_exists(
            &self.config,
            &[VerificationProtocolType::OpenId4VpFinal1_0],
        )
        .error_while("checking config")?;

        let proof = self
            .proof_repository
            .get_proof(
                &id,
                &ProofRelations {
                    verifier_identifier: Some(IdentifierRelations {}),
                    verifier_key: Some(Default::default()),
                    ..Default::default()
                },
                None,
            )
            .await
            .error_while("getting proof")?;

        throw_if_proof_state_not_eq(&proof, ProofStateEnum::Pending)
            .error_while("checking proof state")?;
        validate_verification_protocol_type(
            &[VerificationProtocolType::OpenId4VpFinal1_0],
            &self.config,
            &proof.protocol,
        )
        .error_while("validating protocol type")?;

        let key_handle = select_key_agreement_key_from_proof(
            &proof,
            &*self.key_algorithm_provider,
            &self.config,
        )
        .await
        .error_while("selecting agreement key")?;

        Ok(create_open_id_for_vp_client_metadata_final1_0(key_handle)
            .error_while("creating metadata")?)
    }

    pub async fn direct_post(
        &self,
        request: OpenID4VPDirectPostRequestDTO,
    ) -> Result<DirectPostResponse, OID4VPFinal1_0ServiceError> {
        validate_verification_protocol_config_exists(
            &self.config,
            &[
                VerificationProtocolType::OpenId4VpFinal1_0,
                VerificationProtocolType::OpenId4VpFinal1_0Swiyu,
            ],
        )
        .error_while("checking config")?;

        let unpacked_request = self.unpack_direct_post_request(request).await?;
        let interaction_id = unpacked_request.state;

        let proof = self
            .proof_repository
            .get_proof_by_interaction_id(
                &interaction_id,
                &ProofRelations {
                    schema: Some(Default::default()),
                    interaction: Some(Default::default()),
                    verifier_key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| match error {
                DataLayerError::EntityNotFound { .. } => {
                    OID4VPFinal1_0ServiceError::MissingProofForInteraction(interaction_id)
                }
                error => error.error_while("getting proof").into(),
            })?;

        let proof_id = proof.id;
        let result = self.verify_submission(proof, unpacked_request).await?;
        tracing::info!("Successfully verified response for proof request {proof_id}",);
        Ok(result)
    }

    async fn verify_submission(
        &self,
        proof: Proof,
        unpacked_request: SubmissionRequestData,
    ) -> Result<DirectPostResponse, OID4VPFinal1_0ServiceError> {
        let organisation = proof
            .schema
            .as_ref()
            .ok_or(OID4VPFinal1_0ServiceError::MappingError(
                "missing proof schema".to_string(),
            ))?
            .organisation
            .as_ref()
            .await?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(OID4VPFinal1_0ServiceError::MissingInteractionData)?;

        let interaction_data = interaction
            .data
            .as_ref()
            .ok_or(OID4VPFinal1_0ServiceError::MissingInteractionData)?;

        let interaction_data: OpenID4VPVerifierInteractionContent =
            serde_json::from_slice(interaction_data)
                .map_err(OID4VPFinal1_0ServiceError::from)
                .error_while("parsing interaction data")?;

        if let Some(used_key_id) = unpacked_request.encryption_key {
            let encryption_key_id = interaction_data
                .encryption_key
                .as_ref()
                .and_then(|key| key.kid())
                .ok_or(OID4VPFinal1_0ServiceError::MappingError(
                    "missing encryption key".to_string(),
                ))?;

            if used_key_id.to_string() != encryption_key_id {
                tracing::info!("Proof encrypted with an incorrect key");
                return Err(OpenID4VCError::ValidationError(
                    "Proof encrypted with an incorrect key".to_string(),
                )
                .into());
            }
        }

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let blob_value = serde_json::to_string(&unpacked_request.submission_data)
            .map_err(OID4VPFinal1_0ServiceError::from)
            .error_while("serializing proof blob data")?;

        let blob = Blob::new(blob_value, BlobType::Proof);
        let proof_blob_id = blob.id;
        blob_storage
            .create(blob)
            .await
            .error_while("creating proof blob")?;

        let validation_result: Result<
            (ValidatedProofResult, DirectPostResponse),
            OID4VPFinal1_0ServiceError,
        > = async {
            let (mut proof_result, response) = self
                .proof_validator
                .validate_submission(
                    unpacked_request,
                    proof.to_owned(),
                    interaction_data,
                    VerificationProtocolType::OpenId4VpFinal1_0,
                )
                .await
                .map_err(Into::<OID4VPFinal1_0ServiceError>::into)?;

            self.verify_trust(&proof, &proof_result).await?;

            if let Some(ecosystem_id) = &interaction.ecosystem {
                let ecosystem = self.ecosystem_provider.get(ecosystem_id)?;

                for proved_credential in proof_result.proved_credentials.iter_mut() {
                    ecosystem
                        .validate_interaction(
                            &ProtocolArtifact::VerifierSubmission {
                                credential: Cow::Borrowed(&proved_credential.credential),
                                issuer_details: Cow::Borrowed(&proved_credential.issuer_details),
                            },
                            interaction,
                        )
                        .await
                        .error_while("validating ecosystem")?;

                    proved_credential.credential.ecosystem = Some(ecosystem_id.to_owned());
                }
            }

            Ok((proof_result, response))
        }
        .await;

        match validation_result {
            Ok((validated_proof_result, response)) => {
                persist_accepted_proof(
                    &proof,
                    validated_proof_result,
                    &organisation,
                    proof_blob_id,
                    &*self.proof_repository,
                    &*self.credential_repository,
                    &*self.transaction_manager,
                    &*self.identifier_creator,
                )
                .await
                .error_while("persisting proof")?;
                Ok(response)
            }
            Err(err) => {
                let message = format!("Proof validation failed: {err}");
                tracing::info!(message);
                let error_metadata = HistoryErrorMetadata {
                    error_code: BR_0000,
                    message,
                };
                self.mark_proof_as_failed(&proof.id, proof_blob_id, error_metadata)
                    .await;
                Err(err)
            }
        }
    }

    async fn mark_proof_as_failed(
        &self,
        id: &ProofId,
        proof_blob_id: BlobId,
        error_metadata: HistoryErrorMetadata,
    ) {
        let result = self
            .proof_repository
            .update_proof(
                id,
                UpdateProofRequest {
                    state: Some(ProofStateEnum::Error),
                    proof_blob_id: Some(Some(proof_blob_id)),
                    ..Default::default()
                },
                Some(error_metadata),
            )
            .await;
        if let Err(err) = result {
            warn!("Failed to set proof state to 'ERROR': {err}");
        }
    }

    async fn unpack_direct_post_request(
        &self,
        request: OpenID4VPDirectPostRequestDTO,
    ) -> Result<SubmissionRequestData, OID4VPFinal1_0ServiceError> {
        match request {
            OpenID4VPDirectPostRequestDTO {
                submission_data: VpSubmissionData::Dcql(_),
                state: Some(state),
            } => Ok(SubmissionRequestData {
                submission_data: request.submission_data,
                state,
                mdoc_generated_nonce: None,
                encryption_key: None,
            }),
            OpenID4VPDirectPostRequestDTO {
                submission_data:
                    VpSubmissionData::EncryptedResponse(EncryptedResponse { response: jwe }),
                ..
            } => {
                let jwe_header = extract_jwe_header(&jwe).map_err(|err| {
                    OID4VPFinal1_0ServiceError::ValidationError(format!(
                        "Failed parsing JWE header: {err}"
                    ))
                })?;
                let key_id = jwe_header.key_id.as_ref().ok_or(
                    OID4VPFinal1_0ServiceError::ValidationError("Missing JWE key_id".to_string()),
                )?;
                let key_id = KeyId::from_str(key_id).map_err(|err| {
                    OID4VPFinal1_0ServiceError::ValidationError(format!(
                        "JWE key_id value invalid format: {err}"
                    ))
                })?;

                // KeyId can't be verified here since we don't know related proof yet.
                let key =
                    self.key_repository
                        .get_key(&key_id)
                        .await
                        .map_err(|error| match error {
                            DataLayerError::EntityNotFound { .. } => {
                                OID4VPFinal1_0ServiceError::ValidationError(
                                    "Invalid JWE key_id".to_string(),
                                )
                            }
                            error => error.error_while("getting key").into(),
                        })?;

                let key_storage = self.key_provider.get_key_storage(&key.storage_type)?;

                let key = key_storage
                    .key_handle(&key)
                    .error_while("getting key handle")?;

                let key = key
                    .key_agreement()
                    .and_then(|k| k.private())
                    .ok_or_else(|| {
                        OID4VPFinal1_0ServiceError::ValidationError(
                            "Unsupported JWE key".to_string(),
                        )
                    })?;

                let payload = decrypt_jwe_payload(&jwe, key.as_ref())
                    .await
                    .map_err(|err| {
                        OID4VPFinal1_0ServiceError::ValidationError(format!(
                            "Failed decrypting JWE payload: {err}"
                        ))
                    })?;

                let payload = JwePayload::try_from_json(&payload).map_err(|err| {
                    OID4VPFinal1_0ServiceError::ValidationError(format!(
                        "Failed deserializing JWE payload: {err}"
                    ))
                })?;

                let mdoc_generated_nonce = match jwe_header.partyuinfo_data {
                    None => None,
                    Some(data) => Some(String::from_utf8(data).map_err(|err| {
                        OID4VPFinal1_0ServiceError::ValidationError(format!(
                            "Failed deserializing mdocGeneratedNonce: {err}"
                        ))
                    })?),
                };

                Ok(SubmissionRequestData {
                    submission_data: payload.submission_data,
                    state: payload
                        .state
                        .ok_or(OID4VPFinal1_0ServiceError::ValidationError(
                            "missing state parameter".to_string(),
                        ))?
                        .parse()
                        .map_err(|err| {
                            OID4VPFinal1_0ServiceError::ValidationError(format!(
                                "Invalid state parameter: {err}"
                            ))
                        })?,
                    mdoc_generated_nonce,
                    encryption_key: Some(key_id),
                })
            }
            _ => Err(OpenID4VCError::InvalidRequest.into()),
        }
    }

    /// Resolves all IdentifierTrustInformation entries for an identifier
    /// A VerifierInfoAttestation struct with the resolved registration certificate
    /// is returned for each valid entry
    async fn resolve_verifier_info(
        &self,
        identifier: &Identifier,
    ) -> Result<Vec<VerifierInfoAttestation>, OID4VPFinal1_0ServiceError> {
        let trust_information = identifier.trust_information.as_ref().await?;

        let now = now_utc();
        let valid_registration_certificates: Vec<&IdentifierTrustInformation> = trust_information
            .iter()
            .filter(|entry| {
                if entry.allowed_verification_types.is_empty() {
                    return false;
                }

                if let Some(valid_from) = entry.valid_from
                    && valid_from > now
                {
                    return false;
                }

                if let Some(valid_to) = entry.valid_to
                    && valid_to < now
                {
                    return false;
                }

                true
            })
            .collect();

        if valid_registration_certificates.is_empty() {
            return Ok(vec![]);
        }

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let mut verifier_info = vec![];

        for entry in valid_registration_certificates {
            let certificate = blob_storage
                .get(&entry.blob_id)
                .await
                .error_while("resolving trust_information blob")?
                .ok_or(OID4VPFinal1_0ServiceError::TrustInformationError(
                    "Missing registration certificate".to_string(),
                ))?;

            if certificate.r#type != BlobType::RegistrationCertificate {
                return Err(OID4VPFinal1_0ServiceError::TrustInformationError(format!(
                    "Invalid trust information data, expected registration certificate, got {:?}",
                    certificate.r#type
                )));
            }

            verifier_info.push(VerifierInfoAttestation {
                format: VerifierInfoAttestationFormat::RegistrationCert,
                data: String::from_utf8(certificate.value)?,
                credential_ids: vec![],
            })
        }

        Ok(verifier_info)
    }
}
