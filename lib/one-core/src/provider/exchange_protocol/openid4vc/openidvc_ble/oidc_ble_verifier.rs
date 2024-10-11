use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use futures::stream::FuturesUnordered;
use futures::{Stream, StreamExt, TryFutureExt, TryStreamExt};
use one_crypto::utilities;
use shared_types::ProofId;
use time::OffsetDateTime;
use tokio::select;

use super::{
    BLEPeer, IdentityRequest, MessageSize, TransferSummaryReport, CONTENT_SIZE_UUID,
    DISCONNECT_UUID, IDENTITY_UUID, OIDC_BLE_FLOW, PRESENTATION_REQUEST_UUID, REQUEST_SIZE_UUID,
    SERVICE_UUID, SUBMIT_VC_UUID, TRANSFER_SUMMARY_REPORT_UUID, TRANSFER_SUMMARY_REQUEST_UUID,
};
use crate::model::interaction::InteractionId;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{self, ProofRelations, ProofState, ProofStateEnum};
use crate::model::proof_schema::{ProofInputSchemaRelations, ProofSchemaRelations};
use crate::provider::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicPermissions, CharacteristicProperties, ConnectionEvent,
    CreateCharacteristicOptions, DeviceInfo, ServiceDescription,
};
use crate::provider::bluetooth_low_energy::BleError;
use crate::provider::exchange_protocol::openid4vc::dto::{Chunk, ChunkExt, Chunks};
use crate::provider::exchange_protocol::openid4vc::key_agreement_key::KeyAgreementKey;
use crate::provider::exchange_protocol::openid4vc::mapper::parse_identity_request;
use crate::provider::exchange_protocol::openid4vc::model::{
    BLEOpenID4VPInteractionData, BleOpenId4VpRequest, BleOpenId4VpResponse,
    OpenID4VPPresentationDefinition,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::BLEParse;
use crate::provider::exchange_protocol::{deserialize_interaction_data, ExchangeProtocolError};
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::util::ble_resource::{BleWaiter, OnConflict};
use crate::util::interactions::{add_new_interaction, update_proof_interaction};

type ConnectionEventStream = Pin<Box<dyn Stream<Item = Vec<ConnectionEvent>> + Send>>;

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

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn enabled(&self) -> Result<bool, ExchangeProtocolError> {
        self.ble
            .is_enabled()
            .await
            .map(|s| s.peripheral)
            .map_err(|err| ExchangeProtocolError::Transport(err.into()))
    }

    #[tracing::instrument(level = "debug", skip(self, keypair), err(Debug))]
    pub async fn share_proof(
        self,
        presentation_definition: OpenID4VPPresentationDefinition,
        proof_id: ProofId,
        interaction_id: InteractionId,
        keypair: KeyAgreementKey,
    ) -> Result<String, ExchangeProtocolError> {
        let proof_repository = self.proof_repository.clone();

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
        let interaction_repository = self.interaction_repository.clone();

        let result = self
            .ble
            .schedule(
                *OIDC_BLE_FLOW,
                |task_id, _, peripheral| async move {
                    start_advertisement(
                        keypair.public_key_bytes(),
                        verifier_name.clone(),
                        &*peripheral,
                    )
                    .await?;

                    let mut connection_event_stream =
                        get_connection_event_stream(peripheral.clone()).await;
                    let result: Result<(), ExchangeProtocolError> = async {
                        let (wallet, identity_request) = wait_for_wallet_identify_request(
                            peripheral.clone(),
                            &mut connection_event_stream,
                        )
                        .await?;

                        let (sender_key, receiver_key) = keypair
                            .derive_session_secrets(identity_request.key, identity_request.nonce)
                            .map_err(ExchangeProtocolError::Transport)?;

                        let peer = BLEPeer::new(
                            wallet.clone(),
                            sender_key,
                            receiver_key,
                            identity_request.nonce,
                        );

                        let nonce = utilities::generate_nonce();
                        let request = BleOpenId4VpRequest {
                            verifier_client_id: verifier_name.clone(),
                            nonce: nonce.clone(),
                            presentation_definition: presentation_definition.clone(),
                        };
                        tracing::info!("presentation request: {request:#?}");

                        let presentation_submission = select! {
                            biased;

                            _ = wallet_disconnect_event(&mut connection_event_stream, &wallet.address) => {
                                Err(ExchangeProtocolError::Failed("wallet disconnected".into()))
                            },
                            result = async {
                                write_presentation_request(request, &peer, peripheral.clone()).await?;

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

                                    read_presentation_submission(&peer, peripheral.clone()).await
                            } => result
                        }?;

                        let new_data = BLEOpenID4VPInteractionData {
                            task_id,
                            peer,
                            client_id: Some(verifier_name),
                            nonce: Some(nonce),
                            identity_request_nonce: Some(hex::encode(identity_request.nonce)),
                            presentation_definition: Some(presentation_definition),
                            presentation_submission: Some(presentation_submission),
                        };

                        let proof = self.proof_repository.get_proof(&proof_id, &ProofRelations {
                            state: None,
                            schema:  Some(ProofSchemaRelations {
                                organisation: Some(OrganisationRelations::default()),
                                proof_inputs: Some(ProofInputSchemaRelations::default()),
                            }),
                            claims: None,
                            verifier_did: None,
                            holder_did: None,
                            verifier_key: None,
                            interaction: None,
                        })
                            .await
                            .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?
                            .ok_or(ExchangeProtocolError::Failed("No proof found".to_string()))?;

                        let organisation = proof
                            .schema
                            .as_ref()
                            .and_then(|schema| schema.organisation.as_ref())
                            .ok_or_else(|| ExchangeProtocolError::Failed("Missing organisation".to_string()))?;

                        let new_interaction = uuid::Uuid::new_v4();
                        add_new_interaction(
                            new_interaction,
                            &None,
                            &*self.interaction_repository,
                            serde_json::to_vec(&new_data).ok(),
                            Some(organisation.to_owned()),
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

                        let _ = wallet_disconnect_event(&mut connection_event_stream, &wallet.address).await;
                        let _ = peripheral.stop_server().await;
                        Ok(()) as Result<(), ExchangeProtocolError>
                    }
                    .await;

                    if let Err(err) = result {
                        tracing::info!("BLE task failure: {err}, stopping BLE server");
                        let _ = peripheral.stop_server().await;
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
                move |_, peripheral| async move {
                    tracing::info!("cancelling proof sharing");
                    let Ok(interaction) = interaction_repository
                        .get_interaction(&interaction_id, &Default::default())
                        .await
                        .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))
                    else {
                        return;
                    };

                    if let Ok(interaction_data) =
                        deserialize_interaction_data::<BLEOpenID4VPInteractionData>(
                            interaction.as_ref().and_then(|i| i.data.as_ref()),
                        )
                    {
                        let _ = peripheral
                            .notify_characteristic_data(
                                interaction_data.peer.device_info.address,
                                SERVICE_UUID.to_string(),
                                DISCONNECT_UUID.to_string(),
                                &[],
                            )
                            .await;
                    };
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

async fn wallet_disconnect_event(
    connection_event_stream: &mut ConnectionEventStream,
    wallet_address: &str,
) {
    loop {
        let events = connection_event_stream.next().await;
        if let Some(events) = events {
            if events.iter().any(|event| {
                matches!(event, ConnectionEvent::Disconnected { device_address } if wallet_address.eq(device_address))
            }) {
                return;
            }
        }
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
        .start_advertisement(Some(verifier_name), vec![get_advertise_data()])
        .await
        .map_err(|e| ExchangeProtocolError::Transport(e.into()))?;

    Ok(())
}

async fn get_connection_event_stream(
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> ConnectionEventStream {
    futures::stream::unfold(ble_peripheral, |peripheral| async move {
        match peripheral.get_connection_change_events().await {
            Ok(events) => Some((events, peripheral)),
            Err(err) => {
                tracing::error!("Failed to get connection events: {:?}", err);
                None
            }
        }
    })
    .boxed()
}

#[tracing::instrument(
    level = "debug",
    skip(ble_peripheral, connection_event_stream),
    err(Debug)
)]
async fn wait_for_wallet_identify_request(
    ble_peripheral: Arc<dyn BlePeripheral>,
    connection_event_stream: &mut ConnectionEventStream,
) -> Result<(DeviceInfo, IdentityRequest), ExchangeProtocolError> {
    let mut connected_devices: HashMap<String, DeviceInfo> = HashMap::new();
    let mut identify_futures = FuturesUnordered::new();

    let identified_wallet = loop {
        tokio::select! {
            Some(wallet_info) = identify_futures.next() => {
                let wallet_info: Result<(String, Vec<u8>), ExchangeProtocolError> = wallet_info;
                if let Ok((address, data)) = wallet_info {
                    let identity_request = parse_identity_request(data).map_err(ExchangeProtocolError::Transport)?;
                    break Ok((address, identity_request));
                }
            },
            connection_events = connection_event_stream.next() => {
                for event in connection_events.context("Failed to get BLE connection events").map_err(ExchangeProtocolError::Transport)? {
                    match event {
                        ConnectionEvent::Connected { device_info } => {
                            if connected_devices.insert(device_info.address.to_owned(), device_info.to_owned()).is_none() {
                                identify_futures.push(async {
                                    let stream = read(IDENTITY_UUID, &device_info, ble_peripheral.clone());
                                    tokio::pin!(stream);
                                    let data = stream.try_next().await
                                        .map_err(|e| ExchangeProtocolError::Transport(anyhow::anyhow!(e)))?
                                        .ok_or(ExchangeProtocolError::Transport(anyhow::anyhow!("BLE identity request: No data read")))?;
                                    Ok((device_info.address, data))
                                });
                            }
                        },
                        ConnectionEvent::Disconnected { device_address } => {
                            connected_devices.remove(&device_address);
                        }
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

    let (address, identity_request) = identified_wallet?;
    let device_info = connected_devices
        .remove(&address)
        .ok_or(ExchangeProtocolError::Failed(
            "Could not find connected device info".to_string(),
        ))?;

    Ok((device_info, identity_request))
}

pub fn read(
    id: &str,
    device_info: &DeviceInfo,
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> impl Stream<Item = Result<Vec<u8>, BleError>> + Send {
    let address = device_info.address.clone();

    let stream_of_streams = futures::stream::unfold(
        (address, id.to_string(), ble_peripheral.clone()),
        move |(address, id, ble_peripheral)| async move {
            let result = ble_peripheral
                .get_characteristic_writes(address.clone(), SERVICE_UUID.to_string(), id.clone())
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

    stream_of_streams.flatten()
}

#[tracing::instrument(level = "debug", skip(ble_peripheral), err(Debug))]
async fn write_presentation_request(
    request: BleOpenId4VpRequest,
    peer: &BLEPeer,
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> Result<(), ExchangeProtocolError> {
    let encrypted = peer
        .encrypt(request)
        .context("Failed to encrypt presentation request")
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

    tracing::info!("About to start reading data, request_size: {request_size}");

    let mut transfer_summary_dispatched = false;
    loop {
        tokio::select! {
            biased;

            Some(chunk) = message_stream.next() => {
                let chunk = Chunk::from_bytes(&chunk.map_err(|e| ExchangeProtocolError::Transport(e.into()))?).map_err(ExchangeProtocolError::Transport)?;

                if received_chunks.iter().any(|c| c.index == chunk.index) {
                    continue;
                } else {
                    received_chunks.push(chunk);
                    if transfer_summary_dispatched && received_chunks.len() as u16 == request_size {
                        break;
                    }
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

                transfer_summary_dispatched = true;

                if missing_chunks.is_empty() {
                    break;
                }
            },
        }
    }

    if received_chunks.len() as u16 != request_size {
        return Err(ExchangeProtocolError::Failed(format!(
            "not all chunks received, collected: {}/{request_size}",
            received_chunks.len()
        )));
    }
    tracing::info!("Received all chunks");

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
