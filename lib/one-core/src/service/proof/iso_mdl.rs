use shared_types::ProofId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::ProofService;
use crate::config::validator::transport::get_available_transport_type;
use crate::model::proof::{self, Proof, ProofStateEnum};
use crate::model::proof_schema::ProofSchema;
use crate::provider::exchange_protocol::iso_mdl::ble::start_client;
use crate::provider::exchange_protocol::iso_mdl::device_engagement::{
    DeviceEngagement, RetrievalOptions,
};
use crate::service::error::ServiceError;

impl ProofService {
    pub(super) async fn handle_iso_mdl(
        &self,
        schema: ProofSchema,
        exchange: String,
        iso_mdl_engagement: String,
    ) -> Result<ProofId, ServiceError> {
        let qr = DeviceEngagement::parse_qr_code(&iso_mdl_engagement)
            .map_err(|err| ServiceError::Other(err.to_string()))?;

        let ble = self
            .ble
            .as_ref()
            .ok_or_else(|| ServiceError::Other("BLE is missing in service".into()))?;

        let device_retrieval_method = qr
            .device_engagement
            .device_retrieval_methods
            .first()
            .ok_or_else(|| ServiceError::Other("no device retrival method".into()))?
            .clone();

        let transport = get_available_transport_type(&self.config.transport)?;

        let now = OffsetDateTime::now_utc();
        let proof = Proof {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            issuance_date: now,
            exchange: exchange.to_owned(),
            redirect_uri: None,
            state: Some(vec![proof::ProofState {
                created_date: now,
                last_modified: now,
                state: ProofStateEnum::Pending,
            }]),
            schema: Some(schema.clone()),
            transport: transport.to_owned(),
            claims: None,
            verifier_did: None,
            holder_did: None,
            verifier_key: None,
            interaction: None,
        };

        self.proof_repository.create_proof(proof.clone()).await?;

        let RetrievalOptions::Ble(ble_options) = device_retrieval_method.retrieval_options;

        start_client(
            ble,
            ble_options,
            qr.device_engagement,
            schema,
            proof.clone(),
            self.proof_repository.clone(),
            self.credential_repository.clone(),
            self.did_repository.clone(),
            self.credential_formatter_provider.clone(),
            self.key_algorithm_provider.clone(),
            self.did_method_provider.clone(),
            self.revocation_method_provider.clone(),
        )
        .await?;

        Ok(proof.id)
    }
}