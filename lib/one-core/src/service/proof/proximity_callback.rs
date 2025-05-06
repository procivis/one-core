use std::str::FromStr;

use anyhow::Context;
use futures::future::BoxFuture;
use futures::FutureExt;
use itertools::Itertools;
use one_dto_mapper::convert_inner;
use shared_types::ProofId;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use super::ProofService;
use crate::common_mapper::{encode_cbor_base64, get_or_create_did_and_identifier, DidRole};
use crate::config::core_config::TransportType;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::InteractionRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{Proof, ProofRelations, ProofStateEnum, UpdateProofRequest};
use crate::model::proof_schema::{
    ProofInputSchemaRelations, ProofSchemaClaimRelations, ProofSchemaRelations,
};
use crate::model::validity_credential::Mdoc;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::mapper::credential_from_proved;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPDirectPostResponseDTO, SubmissionRequestData,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::model::BLEOpenID4VPInteractionData;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::mqtt::model::MQTTOpenID4VPInteractionDataVerifier;
use crate::provider::verification_protocol::openid4vp::service::oid4vp_verifier_process_submission;
use crate::service::error::ErrorCode::BR_0000;
use crate::service::error::ServiceError;

impl ProofService {
    // TODO: This method is used as part of the OID4VP BLE/MQTT flow
    // This is a workaround solution for asynchronous background handling of proof submission.
    pub(super) fn get_on_submission_ble_mqtt_callback(
        &self,
        proof_id: ProofId,
    ) -> BoxFuture<'static, ()> {
        let service = self.clone();
        async move {
            service.ble_mqtt_presentation(proof_id).await;
        }
        .boxed()
    }

    async fn ble_mqtt_presentation(&self, proof_id: ProofId) {
        let Ok(Some(proof)) = self
            .proof_repository
            .get_proof(
                &proof_id,
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
                    ..Default::default()
                },
            )
            .await
        else {
            tracing::error!(%proof_id, "Missing proof");
            return;
        };

        let request_data_fn = || {
            let interaction_data = proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref())
                .context("Missing interaction data")?;

            if proof.transport == TransportType::Ble.as_ref() {
                let interaction_data =
                    serde_json::from_slice::<BLEOpenID4VPInteractionData>(interaction_data)
                        .context("BLE interaction data deserialization")?;

                let response = interaction_data
                    .presentation_submission
                    .context("BLE interaction missing presentation_submission")?;

                let state = Uuid::from_str(&response.presentation_submission.definition_id)?;

                let request_data = SubmissionRequestData {
                    presentation_submission: response.presentation_submission,
                    vp_token: response.vp_token,
                    state,
                    mdoc_generated_nonce: interaction_data.identity_request_nonce,
                    encryption_key: None,
                };

                anyhow::Ok(request_data)
            } else {
                let interaction_data =
                    serde_json::from_slice::<MQTTOpenID4VPInteractionDataVerifier>(
                        interaction_data,
                    )
                    .context("MQTT interaction data deserialization")?;

                let response = interaction_data.presentation_submission;
                let state = Uuid::from_str(&response.presentation_submission.definition_id)?;

                let request_data = SubmissionRequestData {
                    presentation_submission: response.presentation_submission,
                    vp_token: response.vp_token,
                    state,
                    mdoc_generated_nonce: Some(interaction_data.identity_request_nonce),
                    encryption_key: None,
                };

                anyhow::Ok(request_data)
            }
        };

        let request_data = match request_data_fn() {
            Ok(request_data) => request_data,
            Err(error) => {
                let message = format!("Failed parsing interaction data: {error}");
                self.mark_proof_as_failed(&proof.id, message).await;
                return;
            }
        };

        if let Err(error) = self.verify_submission(proof, request_data).await {
            tracing::error!(%error, "Proof submission failed");
        }
    }

    async fn verify_submission(
        &self,
        proof: Proof,
        unpacked_request: SubmissionRequestData,
    ) -> Result<OpenID4VPDirectPostResponseDTO, ServiceError> {
        let organisation = proof
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "missing proof schema".to_string(),
            ))?
            .organisation
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "missing organisation".to_string(),
            ))?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "missing interaction".to_string(),
            ))?;

        let interaction_data = interaction.data.as_ref().ok_or(ServiceError::MappingError(
            "missing interaction data".to_string(),
        ))?;

        if let Some(used_key_id) = unpacked_request.encryption_key {
            let verifier_key = proof
                .verifier_key
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "missing verifier_key".to_string(),
                ))?;

            if used_key_id != verifier_key.id {
                tracing::info!("Proof encrypted with an incorrect key");
                return Err(OpenID4VCError::ValidationError(
                    "Proof encrypted with an incorrect key".to_string(),
                )
                .into());
            }
        }

        match oid4vp_verifier_process_submission(
            unpacked_request,
            proof.to_owned(),
            interaction_data,
            &self.did_method_provider,
            &self.credential_formatter_provider,
            &self.key_algorithm_provider,
            &self.revocation_method_provider,
            &self.config,
        )
        .await
        {
            Ok((accept_proof_result, response)) => {
                // store holder did on proof if it is not ambiguous
                let holder_did_value = accept_proof_result
                    .proved_credentials
                    .iter()
                    .map(|cred| &cred.holder_did_value)
                    .all_equal_value()
                    .ok();
                let holder_id = if let Some(holder_did_value) = holder_did_value {
                    let (did, identifer) = get_or_create_did_and_identifier(
                        &*self.did_method_provider,
                        &*self.did_repository,
                        &*self.identifier_repository,
                        &Some(organisation.to_owned()),
                        holder_did_value,
                        DidRole::Holder,
                    )
                    .await?;
                    (Some(did.id), Some(identifer.id))
                } else {
                    (None, None)
                };

                for proved_credential in accept_proof_result.proved_credentials {
                    let credential_id = proved_credential.credential.id;
                    let mdoc_mso = proved_credential.mdoc_mso.to_owned();

                    let credential = credential_from_proved(
                        proved_credential,
                        organisation,
                        &*self.did_repository,
                        &*self.identifier_repository,
                        &*self.did_method_provider,
                    )
                    .await?;

                    self.credential_repository
                        .create_credential(credential)
                        .await?;

                    if let Some(mso) = mdoc_mso {
                        let mso_cbor = encode_cbor_base64(mso)
                            .map_err(|e| OpenID4VCError::Other(e.to_string()))?;

                        self.validity_credential_repository
                            .insert(
                                Mdoc {
                                    id: Uuid::new_v4(),
                                    created_date: OffsetDateTime::now_utc(),
                                    credential: mso_cbor.into_bytes(),
                                    linked_credential_id: credential_id,
                                }
                                .into(),
                            )
                            .await?;
                    }
                }

                self.proof_repository
                    .set_proof_claims(&proof.id, convert_inner(accept_proof_result.proved_claims))
                    .await?;

                self.proof_repository
                    .update_proof(
                        &proof.id,
                        UpdateProofRequest {
                            state: Some(ProofStateEnum::Accepted),
                            holder_did_id: holder_id.0,
                            holder_identifier_id: holder_id.1,
                            ..Default::default()
                        },
                        None,
                    )
                    .await?;

                Ok(response)
            }
            Err(err) => {
                let message = format!("Proof validation failed: {err}");
                self.mark_proof_as_failed(&proof.id, message).await;
                Err(err.into())
            }
        }
    }

    async fn mark_proof_as_failed(&self, id: &ProofId, message: String) {
        tracing::info!(message);
        let error_metadata = HistoryErrorMetadata {
            error_code: BR_0000,
            message,
        };

        let result = self
            .proof_repository
            .update_proof(
                id,
                UpdateProofRequest {
                    state: Some(ProofStateEnum::Error),
                    ..Default::default()
                },
                Some(error_metadata),
            )
            .await;
        if let Err(err) = result {
            warn!("Failed to set proof state to 'ERROR': {err}");
        }
    }
}
