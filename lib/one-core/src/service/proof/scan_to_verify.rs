use shared_types::ProofId;

use super::ProofService;
use super::dto::ScanToVerifyRequestDTO;
use super::mapper::proof_for_scan_to_verify;
use crate::common_mapper::{
    IdentifierRole, extracted_credential_to_model, get_or_create_identifier,
};
use crate::config::validator::transport::get_first_available_transport;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchemaClaim;
use crate::model::history::HistoryErrorMetadata;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::model::proof_schema::ProofSchema;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationState, VerifierCredentialData,
};
use crate::provider::verification_protocol::VerificationProtocol;
use crate::service::error::ErrorCode::BR_0000;
use crate::service::error::{BusinessLogicError, MissingProviderError, ServiceError};

impl ProofService {
    pub(super) async fn handle_scan_to_verify(
        &self,
        proof_schema: ProofSchema,
        exchange: String,
        profile: Option<String>,
        submission: ScanToVerifyRequestDTO,
    ) -> Result<ProofId, ServiceError> {
        let exchange_protocol = self
            .protocol_provider
            .get_protocol(&exchange)
            .ok_or(MissingProviderError::ExchangeProtocol(exchange.to_owned()))?;

        let submission_data = serde_json::to_vec(&submission)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        let (transport, _) = get_first_available_transport(
            &self.config.transport,
            &exchange_protocol.get_capabilities().supported_transports,
        )?;

        let proof = proof_for_scan_to_verify(
            &exchange,
            proof_schema,
            transport,
            submission_data.clone(),
            profile,
        );

        self.interaction_repository
            .create_interaction(proof.interaction.clone().ok_or(ServiceError::MappingError(
                "interaction not created".to_string(),
            ))?)
            .await?;

        self.proof_repository.create_proof(proof.clone()).await?;

        let result = self
            .validate_scan_to_verify_proof(&*exchange_protocol, &proof, &submission_data)
            .await;

        match result {
            Ok(claims) => {
                self.proof_repository
                    .set_proof_claims(&proof.id, claims)
                    .await?;

                self.proof_repository
                    .update_proof(
                        &proof.id,
                        UpdateProofRequest {
                            state: Some(ProofStateEnum::Accepted),
                            ..Default::default()
                        },
                        None,
                    )
                    .await?;
            }
            Err(err) => {
                let error_metadata = HistoryErrorMetadata {
                    error_code: BR_0000,
                    message: err.to_string(),
                };
                self.proof_repository
                    .update_proof(
                        &proof.id,
                        UpdateProofRequest {
                            state: Some(ProofStateEnum::Error),
                            ..Default::default()
                        },
                        Some(error_metadata),
                    )
                    .await?;
            }
        }

        Ok(proof.id)
    }

    async fn validate_scan_to_verify_proof(
        &self,
        exchange_protocol: &dyn VerificationProtocol,
        proof: &Proof,
        submission: &[u8],
    ) -> Result<Vec<Claim>, ServiceError> {
        let proof_schema = proof.schema.as_ref().ok_or(ServiceError::MappingError(
            "proof_schema is None".to_string(),
        ))?;

        let input_schema = proof_schema
            .input_schemas
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "input_schemas is None".to_string(),
            ))?
            .first() // always 1 credential is requested during SCAN_TO_VERIFY
            .ok_or(ServiceError::MappingError(
                "input_schemas is empty".to_string(),
            ))?;

        let credentials = exchange_protocol
            .verifier_handle_proof(proof, submission)
            .await?;

        let credential = credentials.first().ok_or(ServiceError::MappingError(
            "no credentials extracted".to_string(),
        ))?;

        let additional_data = CredentialDataByRole::Verifier(Box::new(VerifierCredentialData {
            credential: credential.to_owned(),
            extracted_lvvcs: vec![],
            proof_input: input_schema.clone(),
        }));

        // check revocation
        for status in &credential.status {
            let (revocation_method, _) = self
                .revocation_method_provider
                .get_revocation_method_by_status_type(&status.r#type)
                .ok_or(ServiceError::MissingProvider(
                    MissingProviderError::RevocationMethod(status.r#type.to_owned()),
                ))?;

            let state = revocation_method
                .check_credential_revocation_status(
                    status,
                    &credential.issuer,
                    Some(additional_data.to_owned()),
                    false,
                )
                .await?;

            if state != CredentialRevocationState::Valid {
                return Err(BusinessLogicError::CredentialIsRevokedOrSuspended.into());
            }
        }

        // map claims
        let proof_claim_schemas =
            input_schema
                .claim_schemas
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "claim_schemas is None".to_string(),
                ))?;

        let credential_schema =
            input_schema
                .credential_schema
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "credential_schema is None".to_string(),
                ))?;

        let credential_schema_claims =
            credential_schema
                .claim_schemas
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "claim_schemas is None".to_string(),
                ))?;

        let mut claim_schemas: Vec<CredentialSchemaClaim> = vec![];
        let mut claims: Vec<(serde_json::Value, ClaimSchema)> = vec![];
        for proof_claim_schema in proof_claim_schemas {
            let value = credential.claims.claims.get(&proof_claim_schema.schema.key);
            let value = match value {
                Some(val) => val,
                None => {
                    if proof_claim_schema.required {
                        return Err(ServiceError::ValidationError(
                            "required claim missing".to_string(),
                        ));
                    }
                    continue;
                }
            };

            claims.push((value.to_owned(), proof_claim_schema.schema.to_owned()));

            let claim_schema = credential_schema_claims
                .iter()
                .find(|claim| claim.schema.id == proof_claim_schema.schema.id)
                .ok_or(ServiceError::MappingError(
                    "claim_schema missing".to_string(),
                ))?;
            claim_schemas.push(claim_schema.to_owned());
        }

        let (issuer_identifier, issuer_identifier_relation) = get_or_create_identifier(
            &*self.did_method_provider,
            &*self.did_repository,
            &*self.certificate_repository,
            &*self.certificate_validator,
            &*self.key_repository,
            &*self.key_algorithm_provider,
            &*self.identifier_repository,
            &proof_schema.organisation,
            &credential.issuer,
            IdentifierRole::Issuer,
        )
        .await?;

        let credential = extracted_credential_to_model(
            &claim_schemas,
            credential_schema.to_owned(),
            claims,
            issuer_identifier,
            issuer_identifier_relation,
            None,
            proof.protocol.to_owned(),
            credential.issuance_date,
        )?;

        let proof_claims = credential
            .claims
            .to_owned()
            .ok_or(ServiceError::MappingError("claims is None".to_string()))?;

        self.credential_repository
            .create_credential(credential)
            .await?;

        Ok(proof_claims)
    }
}
