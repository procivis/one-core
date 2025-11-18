use shared_types::ProofId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::ProofService;
use crate::config::core_config::{TransportType, VerificationEngagement};
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::ProofSchema;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::Handover;
use crate::provider::verification_protocol::iso_mdl::ble_verifier::{
    setup_verifier_session, start_client,
};
use crate::provider::verification_protocol::iso_mdl::device_engagement::{
    DeviceEngagement, RetrievalOptions,
};
use crate::service::error::ServiceError;

impl ProofService {
    pub(super) async fn handle_iso_mdl_verifier(
        &self,
        schema: ProofSchema,
        exchange: String,
        iso_mdl_engagement: String,
        engagement_type: VerificationEngagement,
        profile: Option<String>,
    ) -> Result<ProofId, ServiceError> {
        let (device_engagement, handover, device_retrieval_method) = match engagement_type {
            VerificationEngagement::QrCode => {
                let device_engagement = DeviceEngagement::parse_qr_code(&iso_mdl_engagement)
                    .map_err(|err| ServiceError::Other(err.to_string()))?;
                let device_retrieval_method = device_engagement
                    .inner()
                    .device_retrieval_methods
                    .first()
                    .ok_or_else(|| ServiceError::Other("no device retrival method".into()))?
                    .clone();
                (device_engagement, None, device_retrieval_method)
            }
            VerificationEngagement::NFC => {
                let (device_engagement, handover, device_retrieval_method) =
                    DeviceEngagement::parse_nfc(&iso_mdl_engagement)
                        .map_err(|err| ServiceError::Other(err.to_string()))?;
                (
                    device_engagement,
                    Some(Handover::Nfc(handover)),
                    device_retrieval_method,
                )
            }
        };

        let transport = self
            .config
            .transport
            .get_enabled_transport_type(TransportType::Ble)
            .map_err(|_| ServiceError::Other("BLE transport not available".into()))?;

        let ble = self
            .ble
            .as_ref()
            .ok_or_else(|| ServiceError::Other("BLE is missing in service".into()))?;

        let verifier_session = setup_verifier_session(device_engagement, &schema, handover)?;

        let now = OffsetDateTime::now_utc();
        let proof = Proof {
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
            schema: Some(schema),
            transport: transport.to_owned(),
            claims: None,
            verifier_identifier: None,
            verifier_key: None,
            verifier_certificate: None,
            interaction: None,
        };

        let proof_id = self.proof_repository.create_proof(proof.clone()).await?;

        let RetrievalOptions::Ble(ble_options) = device_retrieval_method.retrieval_options;

        start_client(
            ble,
            ble_options,
            verifier_session,
            proof,
            self.credential_formatter_provider.clone(),
            self.presentation_formatter_provider.clone(),
            self.did_method_provider.clone(),
            self.key_algorithm_provider.clone(),
            self.credential_repository.clone(),
            self.did_repository.clone(),
            self.identifier_repository.clone(),
            self.proof_repository.clone(),
            self.certificate_validator.clone(),
            self.certificate_repository.clone(),
            self.key_repository.clone(),
        )
        .await?;

        Ok(proof_id)
    }
}
