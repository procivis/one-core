use anyhow::{anyhow, Context};
use std::sync::Arc;
use std::time::Duration;
use std::vec;

use futures::{StreamExt, TryFutureExt};
use rand::rngs::OsRng;
use rand::Rng;
use shared_types::ProofId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::interaction::Interaction;
use crate::model::proof::{ProofState, ProofStateEnum};
use crate::provider::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::provider::bluetooth_low_energy::low_level::dto::{CharacteristicWriteType, DeviceInfo};
use crate::provider::exchange_protocol::openid4vc::dto::{Chunk, OpenID4VPPresentationDefinition};
use crate::provider::exchange_protocol::openid4vc::model::BLEOpenID4VPInteractionData;
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::{
    PRESENTATION_REQUEST_UUID, TRANSFER_SUMMARY_REQUEST_UUID,
};
use crate::provider::exchange_protocol::ExchangeProtocolError;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;

use super::{
    BLEParse, BLEPeer, BLEStream, IdentityRequest, KeyAgreementKey, MessageSize, IDENTITY_UUID,
    REQUEST_SIZE_UUID, SERVICE_UUID, TRANSFER_SUMMARY_REPORT_UUID,
};

pub struct OpenID4VCBLEHolder {
    pub proof_repository: Arc<dyn ProofRepository>,
    pub interaction_repository: Arc<dyn InteractionRepository>,
    pub ble_central: Arc<dyn BleCentral>,
    connected_verifier: Option<BLEPeer>,
}

impl OpenID4VCBLEHolder {
    pub fn new(
        proof_repository: Arc<dyn ProofRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        ble_central: Arc<dyn BleCentral>,
        connected_verifier: Option<BLEPeer>,
    ) -> Self {
        Self {
            proof_repository,
            interaction_repository,
            ble_central,
            connected_verifier,
        }
    }

    // The native implementation is loaded lazily. It sometimes happens that
    // on the first call to this method, the native implementation is not loaded yet.
    // This causes the method to return false even though the adapter is enabled.
    // To work around this, we retry the call after a short delay.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn enabled(&self) -> Result<bool, ExchangeProtocolError> {
        let enabled = self.ble_central.is_adapter_enabled().await.unwrap_or(false);

        if enabled {
            return Ok(true);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
        return self
            .ble_central
            .is_adapter_enabled()
            .await
            .map_err(|err| ExchangeProtocolError::Transport(err.into()));
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn handle_invitation(
        &mut self,
        name: String,
        x25519_public_key_hex: String,
        proof_id: ProofId,
        interaction_id: Uuid,
    ) -> Result<(), ExchangeProtocolError> {
        let result: Result<(), ExchangeProtocolError> = async {
            let verifier_public_key: [u8; 32] = hex::decode(&x25519_public_key_hex)
                .context("Failed to decode verifier public key")
                .map_err(ExchangeProtocolError::Transport)?
                .as_slice()
                .try_into()
                .context("Invalid verifier public key length")
                .map_err(ExchangeProtocolError::Transport)?;

            let device_info = self
                .connect_to_verifier(&name, &verifier_public_key)
                .await
                .map_err(|err| {
                    ExchangeProtocolError::Transport(anyhow!(
                        "failed to connect to verifier: {err}"
                    ))
                })?;

            let (identity_request, ble_peer) =
                self.session_key_and_identity_request(device_info, verifier_public_key)?;

            self.connected_verifier = Some(ble_peer.clone());

            self.send(IDENTITY_UUID, identity_request.clone().encode().as_ref())
                .await?;

            let presentation_definition = self.read_presentation_definition().await?;

            let now = OffsetDateTime::now_utc();
            self.interaction_repository
                .update_interaction(Interaction {
                    id: interaction_id,
                    created_date: now,
                    last_modified: now,
                    host: None,
                    data: Some(
                        serde_json::to_vec(&BLEOpenID4VPInteractionData {
                            peer: ble_peer,
                            presentation_definition,
                        })
                        .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?,
                    ),
                })
                .await
                .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

            Ok(())
        }
        .await;

        if let Err(err) = result {
            let now = OffsetDateTime::now_utc();
            let _ = self
                .proof_repository
                .set_proof_state(
                    &proof_id,
                    ProofState {
                        created_date: now,
                        last_modified: now,
                        state: ProofStateEnum::Error,
                    },
                )
                .await;
            return Err(err);
        }

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    async fn connect_to_verifier(
        &self,
        name: &str,
        public_key: &[u8],
    ) -> Result<DeviceInfo, ExchangeProtocolError> {
        if self.ble_central.is_scanning().await.map_err(|err| {
            ExchangeProtocolError::Transport(anyhow!("is_discovering failed: {err}"))
        })? {
            self.ble_central.stop_scan().await.map_err(|err| {
                ExchangeProtocolError::Transport(anyhow!("stop_discovery failed: {err}"))
            })?;
        }

        self.ble_central
            .start_scan(Some(vec![SERVICE_UUID.to_string()]))
            .await
            .map_err(|err| {
                ExchangeProtocolError::Transport(anyhow!("start_discovery failed: {err}"))
            })?;

        let expected_adv_data = [format!("OVP{}_", name).as_bytes(), &public_key[..5]].concat();

        loop {
            let discovered = self
                .ble_central
                .get_discovered_devices()
                .await
                .map_err(|err| {
                    ExchangeProtocolError::Transport(anyhow!(
                        "get_discovered_devices failed: {err}"
                    ))
                })?;

            for device in discovered {
                // The peripheral advertises via the local device name (iOS)
                let local_device_name_matches = device
                    .local_device_name
                    .as_ref()
                    .map(|advertised_name| advertised_name.eq(name))
                    .unwrap_or(false);

                // The peripheral advertises via the advertised service data (Android)
                let advertised_name_matches = device
                    .advertised_service_data
                    .as_ref()
                    .and_then(|data| data.get(&SERVICE_UUID.to_string()))
                    .map(|data| data.eq(&expected_adv_data))
                    .unwrap_or(false);

                if local_device_name_matches || advertised_name_matches {
                    let mtu = self
                        .ble_central
                        .connect(device.device_address.clone())
                        .await
                        .map_err(|err| {
                            ExchangeProtocolError::Transport(anyhow!("connect failed: {err}"))
                        })?;

                    self.ble_central.stop_scan().await.map_err(|err| {
                        ExchangeProtocolError::Transport(anyhow!("stop_discovery failed: {err}"))
                    })?;

                    return Ok(DeviceInfo {
                        address: device.device_address,
                        mtu,
                    });
                }
            }
        }
    }

    fn session_key_and_identity_request(
        &self,
        verifier_device: DeviceInfo,
        verifier_public_key: [u8; 32],
    ) -> Result<(IdentityRequest, BLEPeer), ExchangeProtocolError> {
        let key_agreement_key = KeyAgreementKey::new_random();
        let public_key = key_agreement_key.public_key_bytes();
        let nonce: [u8; 12] = OsRng.gen();

        let (receiver_key, sender_key) = key_agreement_key
            .derive_session_secrets(verifier_public_key, nonce)
            .map_err(ExchangeProtocolError::Transport)?;

        Ok((
            IdentityRequest {
                nonce,
                key: public_key,
            },
            BLEPeer::new(verifier_device, sender_key, receiver_key, nonce),
        ))
    }

    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    async fn read_presentation_definition(
        &self,
    ) -> Result<OpenID4VPPresentationDefinition, ExchangeProtocolError> {
        let connected_verifier =
            self.connected_verifier
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed(
                    "Verifier is not connected".to_string(),
                ))?;

        let mut received_chunks: Vec<Chunk> = vec![];

        let request_size: MessageSize = self
            .read(REQUEST_SIZE_UUID)?
            .parse()
            .map_err(ExchangeProtocolError::Transport)
            .await?;

        let mut message_stream = self.read(PRESENTATION_REQUEST_UUID)?;

        loop {
            tokio::select! {
               Some(chunk) = message_stream.next() => {
                    let chunk = chunk.map_err(|err| {
                           ExchangeProtocolError::Transport(anyhow!("Reading presentation request chunk failed: {err}"))
                       })?;

                    let chunk = Chunk::from_bytes(chunk.as_slice()).map_err(ExchangeProtocolError::Transport)?;
                    if received_chunks.iter().any(|c| c.index == chunk.index) {
                        continue;
                    } else {
                        received_chunks.push(chunk);
                    }

                    if received_chunks.len() as u16 == request_size {
                        break;
                    };
                },
                _ = self.summary_report_notification() => {
                    let missing_chunks = (0..request_size)
                        .filter(|idx| !received_chunks.iter().any(|c| c.index == *idx))
                        .map(|idx| idx.to_be_bytes())
                        .collect::<Vec<[u8; 2]>>()
                        .concat();

                    self.send(
                        TRANSFER_SUMMARY_REQUEST_UUID,
                        missing_chunks.as_ref(),
                    ).await?
                }
            }
        }

        if received_chunks.len() as u16 != request_size {
            return Err(ExchangeProtocolError::Failed(
                "not all chunks received".to_string(),
            ));
        }

        received_chunks.sort_by(|a, b| a.index.cmp(&b.index));

        let presentation_request: Vec<u8> = received_chunks
            .into_iter()
            .flat_map(|c| c.payload)
            .collect();

        connected_verifier
            .decrypt(&presentation_request)
            .map_err(|e| {
                ExchangeProtocolError::Transport(anyhow!(
                    "Failed to decrypt presentation request: {e}"
                ))
            })
    }

    pub async fn summary_report_notification(&self) -> Result<(), ExchangeProtocolError> {
        let wallet = self
            .connected_verifier
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "Verifier is not connected".to_string(),
            ))?;

        self.ble_central
            .subscribe_to_characteristic_notifications(
                wallet.device_info.address.clone(),
                SERVICE_UUID.to_string(),
                TRANSFER_SUMMARY_REPORT_UUID.to_string(),
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        self.ble_central
            .get_notifications(
                wallet.device_info.address.clone(),
                SERVICE_UUID.to_string(),
                TRANSFER_SUMMARY_REPORT_UUID.to_string(),
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        self.ble_central
            .unsubscribe_from_characteristic_notifications(
                wallet.device_info.address.clone(),
                SERVICE_UUID.to_string(),
                TRANSFER_SUMMARY_REPORT_UUID.to_string(),
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        Ok(())
    }
}

impl OpenID4VCBLEHolder {
    pub fn read(&self, id: &str) -> Result<BLEStream, ExchangeProtocolError> {
        let wallet = self
            .connected_verifier
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "Verifier is not connected".to_string(),
            ))?;

        Ok(Box::pin(futures::stream::unfold(
            (
                wallet.device_info.address.clone(),
                id.to_string(),
                self.ble_central.clone(),
                vec![],
            ),
            move |(address, id, ble_central, previous_message)| async move {
                loop {
                    let data = ble_central
                        .read_data(address.clone(), SERVICE_UUID.to_string(), id.clone())
                        .await;

                    if let Ok(data) = data.as_ref() {
                        if previous_message.eq(data) {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    }

                    return Some((
                        data.clone(),
                        (address, id, ble_central, data.unwrap_or_default()),
                    ));
                }
            },
        )))
    }

    pub async fn send(&self, id: &str, data: &[u8]) -> Result<(), ExchangeProtocolError> {
        let verifier = self
            .connected_verifier
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "Verifier not connected".to_string(),
            ))?;

        self.ble_central
            .write_data(
                verifier.device_info.address.to_string(),
                SERVICE_UUID.to_string(),
                id.to_string(),
                data,
                CharacteristicWriteType::WithResponse,
            )
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
            .await
    }
}
