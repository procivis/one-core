use shared_types::{EcosystemId, ProofId};
use standardized_types::openid4vp::dc_api::IsoMdocResponse;
use uuid::Uuid;

use super::ProofService;
use super::error::ProofServiceError;
use crate::config::core_config::{TransportType, VerificationEngagement};
use crate::error::ContextWithErrorCode;
use crate::mapper::decode_cbor_base64url;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::ProofSchema;
use crate::model::relation::OptionalRelatedExt;
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
    Handover, SessionTranscript,
};
use crate::provider::presentation_formatter::mso_mdoc::try_decrypt_dcapi_response;
use crate::provider::verification_protocol::deserialize_interaction_data;
use crate::provider::verification_protocol::iso_mdl::ble::verifier::{
    handle_ble_verifier, setup_verifier_session,
};
use crate::provider::verification_protocol::iso_mdl::common::set_proof_to_error;
use crate::provider::verification_protocol::iso_mdl::dcapi::MdocDcApiVerifierInteractionData;
use crate::provider::verification_protocol::iso_mdl::device_engagement::{
    DeviceEngagement, DeviceRetrievalMethod,
};
use crate::provider::verification_protocol::iso_mdl::verifier::{
    IsoMdlVerifier, process_device_response,
};

impl ProofService {
    #[expect(clippy::too_many_arguments)]
    pub(super) async fn handle_iso_mdl_ble_verifier(
        &self,
        schema: ProofSchema,
        exchange: String,
        iso_mdl_engagement: String,
        engagement_type: VerificationEngagement,
        profile: Option<String>,
        verifier: Option<IsoMdlVerifier>,
        ecosystem: Option<EcosystemId>,
    ) -> Result<ProofId, ProofServiceError> {
        let (device_engagement, handover, device_retrieval_method) = match engagement_type {
            VerificationEngagement::QrCode => {
                let device_engagement = DeviceEngagement::parse_qr_code(&iso_mdl_engagement)
                    .map_err(|err| ProofServiceError::Other(err.to_string()))?;
                let device_retrieval_method = device_engagement
                    .inner()
                    .device_retrieval_methods
                    .first()
                    .ok_or_else(|| ProofServiceError::Other("no device retrieval method".into()))?
                    .clone();
                (
                    device_engagement,
                    Handover::QrCode(Default::default()),
                    device_retrieval_method,
                )
            }
            VerificationEngagement::NFC => {
                let (device_engagement, handover, device_retrieval_method) =
                    DeviceEngagement::parse_nfc(&iso_mdl_engagement)
                        .map_err(|err| ProofServiceError::Other(err.to_string()))?;
                (
                    device_engagement,
                    Handover::Nfc(handover),
                    device_retrieval_method,
                )
            }
        };

        let transport = self
            .config
            .transport
            .get_enabled_transport_type(TransportType::Ble)
            .error_while("checking transport config")?;

        let ble = self
            .ble
            .as_ref()
            .ok_or_else(|| ProofServiceError::Other("BLE is missing in service".into()))?;

        let verifier_session = setup_verifier_session(
            device_engagement,
            &schema,
            handover,
            verifier.as_ref(),
            self.key_algorithm_provider.as_ref(),
            self.blob_storage_provider.as_ref(),
        )
        .await
        .error_while("setting up verifier session")?;

        let now = crate::clock::now_utc();
        let interaction = Interaction {
            dpop_key: None,
            client_attestation_key: None,
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            data: None,
            organisation: schema.organisation.to_owned(),
            interaction_type: InteractionType::Verification,
            expires_at: None,
            ecosystem: ecosystem.clone(),
            ecosystem_data: Default::default(),
        };
        self.interaction_repository
            .create_interaction(interaction.clone())
            .await
            .error_while("creating interaction")?;

        let proof = Proof {
            ecosystem,
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            protocol: exchange.to_owned(),
            redirect_uri: None,
            state: ProofStateEnum::Pending,
            role: ProofRole::Verifier,
            requested_date: Some(now),
            completed_date: None,
            profile,
            proof_blob_id: None,
            engagement: None,
            schema: Some(schema.into()),
            transport: transport.to_owned(),
            claims: Default::default(),
            verifier_identifier: verifier.as_ref().map(|v| v.identifier.to_owned().into()),
            verifier_key: verifier.as_ref().map(|v| v.key.to_owned().into()),
            verifier_certificate: verifier.map(|v| v.certificate.into()),
            interaction: Some(interaction.clone().into()),
            webhook_url: None,
            subscriber_information: None,
        };

        if let Some(ecosystem) = &proof.ecosystem {
            let ecosystem = self.ecosystem_provider.get(ecosystem)?;
            ecosystem
                .validate_proof(&proof)
                .await
                .error_while("validating ecosystem")?;
        }

        let proof_id = self
            .proof_repository
            .create_proof(proof.clone())
            .await
            .error_while("creating proof")?;

        let DeviceRetrievalMethod::BleV1(ble_options) = device_retrieval_method;

        handle_ble_verifier(
            ble,
            ble_options,
            verifier_session,
            proof,
            interaction,
            self.credential_formatter_provider.clone(),
            self.presentation_formatter_provider.clone(),
            self.did_method_provider.clone(),
            self.key_algorithm_provider.clone(),
            self.credential_repository.clone(),
            self.proof_repository.clone(),
            self.certificate_validator.clone(),
            self.identifier_creator.clone(),
            self.ecosystem_resolver.clone(),
            self.revocation_method_provider.clone(),
        )
        .await
        .error_while("starting client")?;

        Ok(proof_id)
    }

    pub(super) async fn handle_iso_dc_api_response(
        &self,
        proof: &Proof,
        response: IsoMdocResponse,
    ) -> Result<(), ProofServiceError> {
        let interaction = proof.interaction.as_required_ref().await?;
        let interaction_data: MdocDcApiVerifierInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())
                .error_while("parsing interaction data")?;
        let encryption_key = self
            .key_repository
            .get_key(&interaction_data.encryption_key)
            .await
            .error_while("loading encryption key")?;

        let encryption_key = self
            .key_provider
            .get_key_storage(&encryption_key.storage_type)?
            .key_handle(&encryption_key)
            .error_while("getting issuer key handle")?;

        let encryption_key =
            encryption_key
                .key_agreement()
                .ok_or(ProofServiceError::MappingError(
                    "Invalid encryption key".to_string(),
                ))?;

        let session_transcript_bytes: EmbeddedCbor<SessionTranscript> =
            ciborium::from_reader(interaction_data.session_transcript_bytes.as_slice())
                .map_err(|e| ProofServiceError::MappingError(e.to_string()))?;
        let session_transcript = session_transcript_bytes.into_inner();

        let response_processing_result = async {
            let encrypted_response =
                decode_cbor_base64url(&response.response).error_while("parsing response")?;
            let device_response = try_decrypt_dcapi_response(
                encrypted_response,
                encryption_key,
                session_transcript.clone(),
            )
            .await
            .error_while("decrypting response")?;

            process_device_response(
                device_response,
                session_transcript,
                proof,
                &interaction,
                self.credential_formatter_provider.as_ref(),
                self.presentation_formatter_provider.as_ref(),
                self.did_method_provider.clone(),
                self.key_algorithm_provider.clone(),
                self.credential_repository.as_ref(),
                self.proof_repository.as_ref(),
                self.certificate_validator.clone(),
                self.identifier_creator.clone(),
                self.ecosystem_resolver.as_ref(),
                self.revocation_method_provider.as_ref(),
            )
            .await
            .error_while("processing device response")?;

            Ok::<_, ProofServiceError>(())
        }
        .await;

        if let Err(error) = self
            .key_repository
            .hard_delete(&interaction_data.encryption_key)
            .await
        {
            tracing::warn!(%error, "Failed to delete encryption key");
        }

        if let Err(error) = response_processing_result {
            tracing::info!(%error, "DC-API response processing failure");
            set_proof_to_error(self.proof_repository.as_ref(), &proof.id, (&error).into()).await;
            return Err(ProofServiceError::InvalidSubmission(error.to_string()));
        }

        Ok(())
    }
}
