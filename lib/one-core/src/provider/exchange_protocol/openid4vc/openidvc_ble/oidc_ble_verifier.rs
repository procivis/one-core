use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt, TryFutureExt};
use one_crypto::imp::utilities;
use one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinition;
use shared_types::ProofId;
use time::OffsetDateTime;

use super::{
    BLEPeer, BLEStream, IdentityRequest, KeyAgreementKey, MessageSize, TransferSummaryReport,
    CONTENT_SIZE_UUID, DISCONNECT_UUID, IDENTITY_UUID, PRESENTATION_REQUEST_UUID,
    REQUEST_SIZE_UUID, SERVICE_UUID, SUBMIT_VC_UUID, TRANSFER_SUMMARY_REPORT_UUID,
    TRANSFER_SUMMARY_REQUEST_UUID,
};
use crate::model::interaction::InteractionId;
use crate::model::proof::{self, ProofState, ProofStateEnum};
use crate::provider::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicPermissions, CharacteristicProperties, ConnectionEvent,
    CreateCharacteristicOptions, DeviceInfo, ServiceDescription,
};
use crate::provider::exchange_protocol::openid4vc::dto::{Chunk, ChunkExt, Chunks};
use crate::provider::exchange_protocol::openid4vc::model::{
    BLEOpenID4VPInteractionData, BleOpenId4VpResponse,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::BLEParse;
use crate::provider::exchange_protocol::ExchangeProtocolError;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::util::interactions::{add_new_interaction, update_proof_interaction};

pub struct OpenID4VCBLEVerifier {
    pub(crate) ble_peripheral: Arc<dyn BlePeripheral>,
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    connected_wallet: Option<BLEPeer>,
}

impl OpenID4VCBLEVerifier {
    pub fn new(
        ble_peripheral: Arc<dyn BlePeripheral>,
        proof_repository: Arc<dyn ProofRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        connected_wallet: Option<BLEPeer>,
    ) -> Result<Self, ExchangeProtocolError> {
        Ok(Self {
            ble_peripheral,
            connected_wallet,
            interaction_repository,
            proof_repository,
        })
    }

    // The native implementation is loaded lazily. It sometimes happens that
    // on the first call to this method, the native implementation is not loaded yet.
    // This causes the method to return false even though the adapter is enabled.
    // To work around this, we retry the call after a short delay.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn enabled(&self) -> Result<bool, ExchangeProtocolError> {
        let enabled = self
            .ble_peripheral
            .is_adapter_enabled()
            .await
            .unwrap_or(false);

        if enabled {
            return Ok(true);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
        return self
            .ble_peripheral
            .is_adapter_enabled()
            .await
            .map_err(|err| ExchangeProtocolError::Transport(err.into()));
    }

    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn share_proof(
        mut self,
        proof_request: OpenID4VPPresentationDefinition,
        proof_id: ProofId,
        interaction_id: InteractionId,
    ) -> Result<String, ExchangeProtocolError> {
        let keypair = KeyAgreementKey::new_random();
        let qr_url = self.start_advertisement(keypair.public_key_bytes()).await?;

        tokio::spawn(async move {
            // TODO
            // select between this future driving the main flow and a timeout future
            // select between this future driving the main flow and a disconnect event future
            let result: Result<(), ExchangeProtocolError> = async {
                let (wallet, identity_request) = self.wait_for_wallet_identify_request().await?;

                let (sender_key, receiver_key) = keypair
                    .derive_session_secrets(identity_request.key, identity_request.nonce)
                    .map_err(ExchangeProtocolError::Transport)?;

                let peer = BLEPeer::new(wallet, sender_key, receiver_key, identity_request.nonce);

                self.connected_wallet = Some(peer.clone());

                self.write_presentation_request(proof_request.clone())
                    .await?;

                let now = OffsetDateTime::now_utc();
                self.proof_repository
                    .set_proof_state(
                        &proof_id,
                        ProofState {
                            created_date: now,
                            last_modified: now,
                            state: ProofStateEnum::Requested,
                        },
                    )
                    .await
                    .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

                let submission = self.read_presentation_submission().await?;

                let new_data = BLEOpenID4VPInteractionData {
                    peer,
                    nonce: Some(hex::encode(identity_request.nonce)),
                    presentation_definition: Some(proof_request.into()),
                    presentation_submission: Some(submission),
                };

                let new_interaction = uuid::Uuid::new_v4();
                add_new_interaction(
                    new_interaction,
                    &None,
                    &*self.interaction_repository,
                    serde_json::to_vec(&new_data).ok(),
                )
                .await
                .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

                update_proof_interaction(proof_id, new_interaction, &*self.proof_repository)
                    .await
                    .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

                self.interaction_repository
                    .delete_interaction(&interaction_id)
                    .await
                    .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

                Ok(())
            }
            .await;

            let _ = self.ble_peripheral.stop_server().await;
            if result.is_err() {
                let now = OffsetDateTime::now_utc();
                let _ = self
                    .proof_repository
                    .set_proof_state(
                        &proof_id,
                        ProofState {
                            state: proof::ProofStateEnum::Error,
                            created_date: now,
                            last_modified: now,
                        },
                    )
                    .await;
            };
        });

        Ok(qr_url)
    }

    #[tracing::instrument(level = "debug", skip(self))]
    async fn start_advertisement(
        &self,
        public_key: [u8; 32],
    ) -> Result<String, ExchangeProtocolError> {
        if self.ble_peripheral.is_advertising().await.map_err(|e| {
            ExchangeProtocolError::Transport(anyhow!("Failed to check BLE advertising status: {e}"))
        })? {
            self.ble_peripheral
                .stop_advertisement()
                .await
                .map_err(|e| {
                    ExchangeProtocolError::Transport(anyhow!("Failed to stop BLE advertising: {e}"))
                })?;
        };

        // https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#section-5.1.1
        // The verifier can advertise via BLE only or via BLE + QR.
        // Depending on the use case, the advertised name is different.
        // The name can be max 8 bytes for Android.
        let verifier_name = utilities::generate_alphanumeric(8);

        self.ble_peripheral
            .start_advertisement(Some(verifier_name.clone()), vec![get_advertise_data()])
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        Ok(format!(
            "OPENID4VP://connect?name={}&key={}",
            verifier_name,
            hex::encode(public_key)
        ))
    }

    #[tracing::instrument(skip(self))]
    async fn wait_for_wallet_identify_request(
        &self,
    ) -> Result<(DeviceInfo, IdentityRequest), ExchangeProtocolError> {
        let mut identify_futures = FuturesUnordered::new();

        let holder_wallet = loop {
            tokio::select! {
                Some(wallet_info) = identify_futures.next() => {
                    break wallet_info;
                },
                connection_events = self.ble_peripheral.get_connection_change_events() => {
                    for event in connection_events.map_err(|e| {
                        ExchangeProtocolError::Transport(anyhow!(
                            "Failed to get BLE connection events: {e}"
                        ))
                    })? {
                        if let ConnectionEvent::Connected { device_info } = event {
                            identify_futures.push(async {
                                    let stream = self.read(IDENTITY_UUID, Some(device_info.address.clone()))?;
                                    let identity_request = stream.parse().map_err(ExchangeProtocolError::Transport).await?;
                                    Ok((device_info, identity_request))
                            });
                        } else {
                            continue;
                        }
                    }
                },
            };
        };
        self.ble_peripheral
            .stop_advertisement()
            .await
            .map_err(|e| {
                ExchangeProtocolError::Transport(anyhow!("Failed to stop advertisement: {e}"))
            })?;

        holder_wallet
    }

    #[tracing::instrument(level = "debug", skip(self))]
    async fn write_presentation_request(
        &self,
        proof_request: OpenID4VPPresentationDefinition,
    ) -> Result<(), ExchangeProtocolError> {
        let peer = self
            .connected_wallet
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "Wallet is not connected".to_string(),
            ))?;

        let encrypted = peer.encrypt(proof_request).map_err(|e| {
            ExchangeProtocolError::Transport(anyhow!("Failed to encrypt proof request: {e}"))
        })?;

        let chunks = Chunks::from_bytes(encrypted.as_slice(), peer.device_info.mtu());
        let len = (chunks.len() as u16).to_be_bytes();

        self.send(REQUEST_SIZE_UUID, &len).await?;
        self.write_chunks_with_report(chunks).await
    }

    #[tracing::instrument(level = "debug", skip(self))]
    async fn request_write_report(&self) -> Result<Vec<u16>, ExchangeProtocolError> {
        let device_address = self
            .connected_wallet
            .as_ref()
            .map(|peer| peer.device_info.address.clone())
            .ok_or(ExchangeProtocolError::Failed(
                "Wallet is not connected".to_string(),
            ))?;

        self.ble_peripheral
            .notify_characteristic_data(
                device_address,
                SERVICE_UUID.into(),
                TRANSFER_SUMMARY_REPORT_UUID.into(),
                &[],
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let report_bytes: TransferSummaryReport = self
            .read(TRANSFER_SUMMARY_REQUEST_UUID, None)?
            .parse()
            .map_err(ExchangeProtocolError::Transport)
            .await?;

        Ok(report_bytes)
    }

    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn read_presentation_submission(
        &self,
    ) -> Result<BleOpenId4VpResponse, ExchangeProtocolError> {
        let connected_wallet =
            self.connected_wallet
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed(
                    "Wallet is not connected".to_string(),
                ))?;

        let request_size: MessageSize = self
            .read(CONTENT_SIZE_UUID, None)?
            .parse()
            .map_err(ExchangeProtocolError::Transport)
            .await?;

        let mut received_chunks: Vec<Chunk> = vec![];
        let mut message_stream = self.read(SUBMIT_VC_UUID, None)?;
        let mut summary_report_request = self.read(TRANSFER_SUMMARY_REQUEST_UUID, None)?;

        tracing::info!("About to start reading data");
        loop {
            tokio::select! {
                Some(chunk) = message_stream.next() => {
                    let chunk = Chunk::from_bytes(&chunk.map_err(|e| ExchangeProtocolError::Transport(e.into()))?).map_err(ExchangeProtocolError::Transport)?;

                    if received_chunks.iter().any(|c| c.index == chunk.index) {
                        continue;
                    } else {
                        received_chunks.push(chunk);
                    }
                },
                _ = summary_report_request.next() => {
                    let missing_chunks = (1..request_size)
                        .filter(|idx| !received_chunks.iter().any(|c| c.index == *idx))
                        .map(|idx| idx.to_be_bytes())
                        .collect::<Vec<[u8; 2]>>()
                        .concat();

                    self.ble_peripheral
                        .notify_characteristic_data(
                            connected_wallet.device_info.address.clone(),
                            SERVICE_UUID.to_owned(),
                            TRANSFER_SUMMARY_REPORT_UUID.to_owned(),
                            &missing_chunks,
                        )
                        .await
                        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

                    if missing_chunks.is_empty() {
                        break;
                    }
                },
            }
        }

        tracing::info!("Received all chunks");
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

        connected_wallet
            .decrypt(&presentation_request)
            .map_err(|e| {
                ExchangeProtocolError::Transport(anyhow!(
                    "Failed to decrypt presentation request: {e}"
                ))
            })
    }

    #[tracing::instrument(level = "debug", skip(self))]
    fn write_chunks_with_report(
        &self,
        chunks: Chunks,
    ) -> BoxFuture<'_, Result<(), ExchangeProtocolError>> {
        return async move {
            for chunk in chunks.iter() {
                self.send(PRESENTATION_REQUEST_UUID, chunk.to_bytes().as_slice())
                    .await?
            }

            // Wait for the wallet to receive all the chunks
            tokio::time::sleep(Duration::from_millis(500)).await;

            let missed_chunks = self.request_write_report().await?;
            let to_resend = chunks
                .into_iter()
                .filter(|chunk| missed_chunks.contains(&{ chunk.index }))
                .collect::<Vec<_>>();

            if to_resend.is_empty() {
                return Ok(());
            }

            self.write_chunks_with_report(to_resend).await?;

            Ok(())
        }
        .boxed();
    }
}

fn get_advertise_data() -> ServiceDescription {
    let read_characteristics = vec![REQUEST_SIZE_UUID, PRESENTATION_REQUEST_UUID];
    let write_characteristics = vec![
        IDENTITY_UUID,
        CONTENT_SIZE_UUID,
        SUBMIT_VC_UUID,
        TRANSFER_SUMMARY_REQUEST_UUID,
    ];

    let notify_characteristics = vec![TRANSFER_SUMMARY_REPORT_UUID, DISCONNECT_UUID];
    let characteristics = read_characteristics
        .into_iter()
        .map(|uuid| CreateCharacteristicOptions {
            uuid: uuid.to_string(),
            permissions: vec![CharacteristicPermissions::Read],
            properties: vec![CharacteristicProperties::Read],
            initial_value: None,
        })
        .chain(
            write_characteristics
                .into_iter()
                .map(|uuid| CreateCharacteristicOptions {
                    uuid: uuid.to_string(),
                    permissions: vec![CharacteristicPermissions::Write],
                    properties: vec![
                        CharacteristicProperties::Write,
                        CharacteristicProperties::WriteWithoutResponse,
                    ],
                    initial_value: None,
                }),
        )
        .chain(
            notify_characteristics
                .into_iter()
                .map(|uuid| CreateCharacteristicOptions {
                    uuid: uuid.to_string(),
                    permissions: vec![CharacteristicPermissions::Read],
                    properties: vec![
                        CharacteristicProperties::Read,
                        CharacteristicProperties::Notify,
                    ],
                    initial_value: None,
                }),
        )
        .collect();

    ServiceDescription {
        uuid: SERVICE_UUID.to_string(),
        advertise: true,
        advertised_service_data: None,
        characteristics,
    }
}

impl OpenID4VCBLEVerifier {
    // The optional wallet address can be used to read before a device is connected
    pub fn read(
        &self,
        id: &str,
        wallet_address: Option<String>,
    ) -> Result<BLEStream, ExchangeProtocolError> {
        let address = self
            .connected_wallet
            .as_ref()
            .map(|wallet| wallet.device_info.address.clone())
            .or(wallet_address)
            .ok_or(ExchangeProtocolError::Failed(
                "Wallet is not connected".to_string(),
            ))?;

        let stream_of_streams = futures::stream::unfold(
            (address, id.to_string(), self.ble_peripheral.clone()),
            move |(address, id, ble_peripheral)| async move {
                let result = ble_peripheral
                    .get_characteristic_writes(
                        address.clone(),
                        SERVICE_UUID.to_string(),
                        id.clone(),
                    )
                    .await;

                let vec_of_results = match result {
                    Ok(items) => items.into_iter().map(Ok).collect(),
                    Err(err) => vec![Err(err)],
                };

                Some((
                    futures::stream::iter(vec_of_results),
                    (address, id, ble_peripheral),
                ))
            },
        );

        Ok(stream_of_streams.flatten().boxed())
    }

    pub async fn send(&self, id: &str, data: &[u8]) -> Result<(), ExchangeProtocolError> {
        let wallet = self
            .connected_wallet
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "Wallet is not connected".to_string(),
            ))?;

        self.ble_peripheral
            .set_characteristic_data(SERVICE_UUID.to_string(), id.to_string(), data)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
            .await?;

        self.ble_peripheral
            .wait_for_characteristic_read(
                wallet.device_info.address.to_string(),
                SERVICE_UUID.to_string(),
                id.to_string(),
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
    }
}
