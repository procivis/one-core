use shared_types::{EcosystemId, ProofId};
use uuid::Uuid;

use super::ProofService;
use super::error::ProofServiceError;
use crate::config::core_config::{TransportType, VerificationEngagement};
use crate::error::ContextWithErrorCode;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::ProofSchema;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::Handover;
use crate::provider::verification_protocol::iso_mdl::ble::verifier::{
    IsoMdlVerifier, handle_ble_verifier, setup_verifier_session,
};
use crate::provider::verification_protocol::iso_mdl::device_engagement::{
    DeviceEngagement, DeviceRetrievalMethod,
};

impl ProofService {
    #[expect(clippy::too_many_arguments)]
    pub(super) async fn handle_iso_mdl_verifier(
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
        )
        .await
        .error_while("setting up verifier session")?;

        let now = crate::clock::now_utc();
        let interaction = Interaction {
            dpop_key: None,
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
        )
        .await
        .error_while("starting client")?;

        Ok(proof_id)
    }
}
