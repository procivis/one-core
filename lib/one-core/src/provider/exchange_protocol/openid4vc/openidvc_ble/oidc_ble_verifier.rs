use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use futures::stream::FuturesUnordered;
use futures::{Stream, StreamExt, TryFutureExt};
use one_crypto::imp::utilities;
use one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinition;
use shared_types::ProofId;
use time::OffsetDateTime;
use uuid::uuid;

use super::{
    BLEPeer, IdentityRequest, KeyAgreementKey, MessageSize, TransferSummaryReport,
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
use crate::provider::bluetooth_low_energy::BleError;
use crate::provider::exchange_protocol::openid4vc::dto::{Chunk, ChunkExt, Chunks};
use crate::provider::exchange_protocol::openid4vc::model::{
    BLEOpenID4VPInteractionData, BleOpenId4VpResponse,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::BLEParse;
use crate::provider::exchange_protocol::ExchangeProtocolError;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::util::ble_resource::{BleWaiter, OnConflict};
use crate::util::interactions::{add_new_interaction, update_proof_interaction};

pub struct OpenID4VCBLEVerifier {
    ble: BleWaiter,
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
}

impl OpenID4VCBLEVerifier {
    pub fn new(
        ble: BleWaiter,
        proof_repository: Arc<dyn ProofRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
    ) -> Result<Self, ExchangeProtocolError> {
        Ok(Self {
            ble,
            interaction_repository,
            proof_repository,
        })
    }

    // The native implementation is loaded lazily. It sometimes happens that
    // on the first call to this method, the native implementation is not loaded yet.
    // This causes the method to return false even though the adapter is enabled.
    // To work around this, we retry the call after a short delay.
    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn enabled(&self) -> Result<bool, ExchangeProtocolError> {
        let enabled = self
            .ble
            .is_enabled()
            .await
            .map(|s| s.peripheral)
            .unwrap_or(false);

        if enabled {
            return Ok(true);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
        self.ble
            .is_enabled()
            .await
            .map(|s| s.peripheral)
            .map_err(|err| ExchangeProtocolError::Transport(err.into()))
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn share_proof(
        self,
        proof_request: OpenID4VPPresentationDefinition,
        proof_id: ProofId,
        interaction_id: InteractionId,
    ) -> Result<String, ExchangeProtocolError> {
        let proof_repository = self.proof_repository.clone();

        let keypair = KeyAgreementKey::new_random();

        // https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#section-5.1.1
        // The verifier can advertise via BLE only or via BLE + QR.
        // Depending on the use case, the advertised name is different.
        // The name can be max 8 bytes for Android.
        let verifier_name = utilities::generate_alphanumeric(8);

        let qr_url = format!(
            "OPENID4VP://connect?name={}&key={}",
            verifier_name,
            hex::encode(keypair.public_key_bytes()),
        );

        let result = self
            .ble
            .schedule(
                uuid!(SERVICE_UUID),
                |task_id, _, peripheral| async move {
                    start_advertisement(keypair.public_key_bytes(), verifier_name, &*peripheral)
                        .await?;

                    let result: Result<(), ExchangeProtocolError> = async {
                        let (wallet, identity_request) =
                            wait_for_wallet_identify_request(peripheral.clone()).await?;

                        let (sender_key, receiver_key) = keypair
                            .derive_session_secrets(identity_request.key, identity_request.nonce)
                            .map_err(ExchangeProtocolError::Transport)?;

                        let peer =
                            BLEPeer::new(wallet, sender_key, receiver_key, identity_request.nonce);

                        write_presentation_request(
                            proof_request.clone(),
                            &peer,
                            peripheral.clone(),
                        )
                        .await?;

                        let now = OffsetDateTime::now_utc();
                        proof_repository
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

                        let submission =
                            read_presentation_submission(&peer, peripheral.clone()).await?;

                        let new_data = BLEOpenID4VPInteractionData {
                            task_id,
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

                        update_proof_interaction(
                            proof_id,
                            new_interaction,
                            &*self.proof_repository,
                        )
                        .await
                        .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

                        self.interaction_repository
                            .delete_interaction(&interaction_id)
                            .await
                            .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

                        Ok(())
                    }
                    .await;

                    let _ = peripheral.stop_server().await;
                    if result.is_err() {
                        let now = OffsetDateTime::now_utc();
                        let _ = proof_repository
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

                    Ok::<_, ExchangeProtocolError>(())
                },
                |_, peripheral| async move {
                    let _ = peripheral.stop_server().await;
                },
                OnConflict::ReplaceIfSameFlow,
                false,
            )
            .await;

        if !result.is_scheduled() {
            return Err(ExchangeProtocolError::Failed(
                "ble is busy with other flow".into(),
            ));
        }

        Ok(qr_url)
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

#[tracing::instrument(level = "debug", skip(ble_peripheral), err(Debug))]
async fn start_advertisement(
    public_key: [u8; 32],
    verifier_name: String,
    ble_peripheral: &dyn BlePeripheral,
) -> Result<(), ExchangeProtocolError> {
    if ble_peripheral
        .is_advertising()
        .await
        .context("Failed to check BLE advertising status")
        .map_err(ExchangeProtocolError::Transport)?
    {
        ble_peripheral
            .stop_advertisement()
            .await
            .context("Failed to stop BLE advertising")
            .map_err(ExchangeProtocolError::Transport)?;
    };

    ble_peripheral
        .start_advertisement(Some(verifier_name.clone()), vec![get_advertise_data()])
        .await
        .map_err(|e| ExchangeProtocolError::Transport(e.into()))?;

    Ok(())
}

#[tracing::instrument(level = "debug", skip(ble_peripheral), err(Debug))]
async fn wait_for_wallet_identify_request(
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> Result<(DeviceInfo, IdentityRequest), ExchangeProtocolError> {
    let mut identify_futures = FuturesUnordered::new();

    let holder_wallet = loop {
        tokio::select! {
            Some(wallet_info) = identify_futures.next() => {
                break wallet_info;
            },
            connection_events = ble_peripheral.get_connection_change_events() => {
                for event in connection_events.context("Failed to get BLE connection events").map_err(ExchangeProtocolError::Transport)? {
                    if let ConnectionEvent::Connected { device_info } = event {
                        identify_futures.push(async {
                                let stream = read(IDENTITY_UUID, &device_info, ble_peripheral.clone());
                                let identity_request = stream.parse().map_err(ExchangeProtocolError::Transport).await?;
                                Ok((device_info, identity_request))
                        });
                    }
                }
            },
        };
    };
    ble_peripheral
        .stop_advertisement()
        .await
        .context("Failed to stop advertisement")
        .map_err(ExchangeProtocolError::Transport)?;

    holder_wallet
}

pub fn read(
    id: &str,
    device_info: &DeviceInfo,
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> impl Stream<Item = Result<Vec<u8>, BleError>> + Send {
    let address = device_info.address.clone();

    futures::stream::unfold(
        (address, id.to_string(), ble_peripheral),
        move |(address, id, ble_peripheral)| async move {
            let data = ble_peripheral
                .get_characteristic_writes(address.clone(), SERVICE_UUID.to_string(), id.clone())
                .await
                .map(|data| data.concat());

            Some((data, (address, id, ble_peripheral)))
        },
    )
}

#[tracing::instrument(level = "debug", skip(ble_peripheral), err(Debug))]
async fn write_presentation_request(
    proof_request: OpenID4VPPresentationDefinition,
    peer: &BLEPeer,
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> Result<(), ExchangeProtocolError> {
    let encrypted = peer
        .encrypt(proof_request)
        .context("Failed to encrypt proof request")
        .map_err(ExchangeProtocolError::Transport)?;

    let chunks = Chunks::from_bytes(encrypted.as_slice(), peer.device_info.mtu());
    let len = (chunks.len() as u16).to_be_bytes();

    send(REQUEST_SIZE_UUID, &len, peer, &*ble_peripheral).await?;
    write_chunks_with_report(chunks, peer, ble_peripheral).await
}

pub async fn send(
    id: &str,
    data: &[u8],
    wallet: &BLEPeer,
    ble_peripheral: &dyn BlePeripheral,
) -> Result<(), ExchangeProtocolError> {
    ble_peripheral
        .set_characteristic_data(SERVICE_UUID.to_string(), id.to_string(), data)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
        .await?;

    ble_peripheral
        .wait_for_characteristic_read(
            wallet.device_info.address.to_string(),
            SERVICE_UUID.to_string(),
            id.to_string(),
        )
        .await
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
}

#[tracing::instrument(level = "debug", skip(ble_peripheral), err(Debug))]
async fn write_chunks_with_report(
    chunks: Chunks,
    wallet: &BLEPeer,
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> Result<(), ExchangeProtocolError> {
    for chunk in chunks.iter() {
        send(
            PRESENTATION_REQUEST_UUID,
            chunk.to_bytes().as_slice(),
            wallet,
            &*ble_peripheral,
        )
        .await?
    }

    // Wait for the wallet to receive all the chunks
    tokio::time::sleep(Duration::from_millis(500)).await;

    let missed_chunks = request_write_report(wallet, ble_peripheral.clone()).await?;
    let to_resend = chunks
        .into_iter()
        .filter(|chunk| missed_chunks.contains(&{ chunk.index }))
        .collect::<Vec<_>>();

    if to_resend.is_empty() {
        return Ok(());
    }

    Box::pin(write_chunks_with_report(to_resend, wallet, ble_peripheral)).await
}

#[tracing::instrument(level = "debug", skip(ble_peripheral), err(Debug))]
async fn request_write_report(
    wallet: &BLEPeer,
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> Result<Vec<u16>, ExchangeProtocolError> {
    ble_peripheral
        .notify_characteristic_data(
            wallet.device_info.address.to_string(),
            SERVICE_UUID.into(),
            TRANSFER_SUMMARY_REPORT_UUID.into(),
            &[],
        )
        .await
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let report_bytes: TransferSummaryReport = read(
        TRANSFER_SUMMARY_REQUEST_UUID,
        &wallet.device_info,
        ble_peripheral.clone(),
    )
    .parse()
    .map_err(ExchangeProtocolError::Transport)
    .await?;

    Ok(report_bytes)
}

#[tracing::instrument(level = "debug", skip(ble_peripheral), err(Debug))]
pub async fn read_presentation_submission(
    connected_wallet: &BLEPeer,
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> Result<BleOpenId4VpResponse, ExchangeProtocolError> {
    let request_size: MessageSize = read(
        CONTENT_SIZE_UUID,
        &connected_wallet.device_info,
        ble_peripheral.clone(),
    )
    .parse()
    .map_err(ExchangeProtocolError::Transport)
    .await?;

    let mut received_chunks: Vec<Chunk> = vec![];
    let message_stream = read(
        SUBMIT_VC_UUID,
        &connected_wallet.device_info,
        ble_peripheral.clone(),
    );
    tokio::pin!(message_stream);
    let summary_report_request = read(
        TRANSFER_SUMMARY_REQUEST_UUID,
        &connected_wallet.device_info,
        ble_peripheral.clone(),
    );
    tokio::pin!(summary_report_request);

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

                ble_peripheral
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
            ExchangeProtocolError::Transport(anyhow!("Failed to decrypt presentation request: {e}"))
        })
}
