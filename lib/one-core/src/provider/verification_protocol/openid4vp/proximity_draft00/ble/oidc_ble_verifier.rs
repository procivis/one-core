use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use futures::future::{BoxFuture, Shared};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, Stream, StreamExt, TryFutureExt, TryStreamExt};
use one_crypto::utilities;
use tokio::select;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

use super::dto::BleOpenId4VpResponse;
use super::{
    BLEParse, BLEPeer, CONTENT_SIZE_UUID, DISCONNECT_UUID, IDENTITY_UUID, IdentityRequest,
    OIDC_BLE_FLOW, PRESENTATION_REQUEST_UUID, REQUEST_SIZE_UUID, SERVICE_UUID, SUBMIT_VC_UUID,
    TRANSFER_SUMMARY_REPORT_UUID, TRANSFER_SUMMARY_REQUEST_UUID, TransferSummaryReport,
};
use crate::config::core_config::TransportType;
use crate::model::did::Did;
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::InteractionId;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::bluetooth_low_energy::BleError;
use crate::provider::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicPermissions, CharacteristicProperties, ConnectionEvent,
    CreateCharacteristicOptions, DeviceInfo, ServiceDescription,
};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::OpenID4VPPresentationDefinition;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::KeyAgreementKey;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::async_verifier_flow::{
    AsyncTransportHooks, AsyncVerifierFlowParams, FlowState, async_verifier_flow, never,
    set_proof_state_infallible,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::mappers::parse_identity_request;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::model::BLEOpenID4VPInteractionData;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::dto::{
    Chunk, ChunkExt, Chunks, MessageSize,
};
use crate::provider::verification_protocol::{
    VerificationProtocolError, deserialize_interaction_data,
};
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ErrorCode::BR_0000;
use crate::util::ble_resource::{BleWaiter, OnConflict};

type ConnectionEventStream = Pin<Box<dyn Stream<Item = Vec<ConnectionEvent>> + Send>>;

pub(crate) struct OpenID4VCBLEVerifier {
    ble: BleWaiter,
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
}

impl OpenID4VCBLEVerifier {
    pub(crate) fn new(
        ble: BleWaiter,
        proof_repository: Arc<dyn ProofRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
    ) -> Result<Self, VerificationProtocolError> {
        Ok(Self {
            ble,
            interaction_repository,
            proof_repository,
        })
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub(crate) async fn enabled(&self) -> Result<bool, VerificationProtocolError> {
        self.ble
            .is_enabled()
            .await
            .map(|s| s.peripheral)
            .map_err(|err| VerificationProtocolError::Transport(err.into()))
    }

    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn share_proof(
        self,
        presentation_definition: OpenID4VPPresentationDefinition,
        proof: Proof,
        auth_fn: AuthenticationFn,
        did: Did,
        interaction_id: InteractionId,
        keypair: KeyAgreementKey,
        cancellation_token: CancellationToken,
        on_submission_callback: Option<Shared<BoxFuture<'static, ()>>>,
        url_scheme: &str,
    ) -> Result<String, VerificationProtocolError> {
        let proof_repository = self.proof_repository.clone();

        // https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#section-5.1.1
        // The verifier can advertise via BLE only or via BLE + QR.
        // Depending on the use case, the advertised name is different.
        // The name can be max 8 bytes for Android.
        let verifier_name = utilities::generate_alphanumeric(8);

        let public_key = keypair.public_key_bytes();
        let advertising_name = verifier_name.clone();
        let (advertising_task_id, advertising_result) = self
            .ble
            .schedule(
                *OIDC_BLE_FLOW,
                |_, _, peripheral| async move {
                    start_advertisement(advertising_name, &*peripheral).await
                },
                |_, peripheral| async move {
                    stop_server(&*peripheral).await;
                },
                OnConflict::ReplaceIfSameFlow,
                true,
            )
            .await
            .value_or(VerificationProtocolError::Failed("BLE is busy".to_string()))
            .await?;
        advertising_result
            .ok_or(VerificationProtocolError::Failed("flow was aborted".into()))??;

        let qr_url = format!(
            "{url_scheme}://connect?name={}&key={}",
            verifier_name,
            hex::encode(public_key),
        );

        let interaction_repository = self.interaction_repository.clone();
        let result = self
            .ble
            .schedule_continuation(
                advertising_task_id,
                |task_id, _, peripheral| async move {
                    let hooks = AsyncTransportHooks {
                        wallet_connect: wallet_connect(task_id, peripheral.clone(), keypair),
                        wallet_disconnect,
                        wallet_reject: never, // wallet cannot explicitly reject in BLE verifier flow
                        send_presentation_request,
                        receive_presentation,
                        interaction_data_from_response,
                    };

                    let flow_params = AsyncVerifierFlowParams {
                        proof: &proof,
                        presentation_definition,
                        did: &did.did,
                        interaction_id,
                        proof_repository: &*proof_repository,
                        interaction_repository: &*interaction_repository,
                        transport_type: TransportType::Ble,
                        cancellation_token,
                    };

                    let result = async_verifier_flow(flow_params, hooks, auth_fn).await;
                    stop_server(&*peripheral).await;
                    match &result {
                        Ok(FlowState::Finished) => {
                            if let Some(callback) = on_submission_callback {
                                callback.await;
                            }
                        }
                        Err(err) => {
                            let message = format!("BLE verifier flow failure: {err}");
                            info!(message);
                            let metadata = Some(HistoryErrorMetadata {
                                error_code: BR_0000,
                                message,
                            });
                            set_proof_state_infallible(
                                &proof,
                                ProofStateEnum::Error,
                                metadata,
                                &*proof_repository,
                            )
                            .await;
                        }
                        Ok(_) => {} // cancel or reject -> nothing to do
                    }
                    result
                },
                move |_, peripheral| async move {
                    info!("cancelling proof sharing");
                    let Ok(interaction) = self
                        .interaction_repository
                        .get_interaction(&interaction_id, &Default::default())
                        .await
                        .map_err(|err| VerificationProtocolError::Failed(err.to_string()))
                    else {
                        return;
                    };

                    if let Ok(interaction_data) =
                        deserialize_interaction_data::<BLEOpenID4VPInteractionData>(
                            interaction.as_ref().and_then(|i| i.data.as_ref()),
                        )
                    {
                        let result = peripheral
                            .notify_characteristic_data(
                                interaction_data.peer.device_info.address,
                                SERVICE_UUID.to_string(),
                                DISCONNECT_UUID.to_string(),
                                &[],
                            )
                            .await;
                        if let Err(err) = result {
                            warn!("failed to notify client about disconnect: {err}")
                        }
                    };
                    stop_server(&*peripheral).await;
                },
                false,
            )
            .await;

        if !result.is_scheduled() {
            return Err(VerificationProtocolError::Failed(
                "BLE is busy with other flow".into(),
            ));
        }

        Ok(qr_url)
    }
}

async fn stop_server(peripheral: &dyn BlePeripheral) {
    let result = peripheral.stop_server().await;
    if let Err(ref err) = result {
        warn!("failed to stop BLE peripheral server: {err}");
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
    verifier_name: String,
    ble_peripheral: &dyn BlePeripheral,
) -> Result<(), VerificationProtocolError> {
    if ble_peripheral
        .is_advertising()
        .await
        .context("Failed to check BLE advertising status")
        .map_err(VerificationProtocolError::Transport)?
    {
        ble_peripheral
            .stop_advertisement()
            .await
            .context("Failed to stop BLE advertising")
            .map_err(VerificationProtocolError::Transport)?;
    };

    ble_peripheral
        .start_advertisement(Some(verifier_name), vec![get_advertise_data()])
        .await
        .map_err(|e| VerificationProtocolError::Transport(e.into()))?;

    Ok(())
}

async fn get_connection_event_stream(
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> ConnectionEventStream {
    futures::stream::unfold(ble_peripheral, |peripheral| async move {
        match peripheral.get_connection_change_events().await {
            Ok(events) => Some((events, peripheral)),
            Err(err) => {
                tracing::error!("Failed to get connection events: {err:?}");
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
) -> Result<(DeviceInfo, IdentityRequest), VerificationProtocolError> {
    let mut connected_devices: HashMap<String, DeviceInfo> = HashMap::new();
    let mut identify_futures = FuturesUnordered::new();

    let (address, identity_request) = loop {
        select! {
            Some(wallet_info) = identify_futures.next() => {
                let wallet_info: Result<(String, Vec<u8>), VerificationProtocolError> = wallet_info;
                if let Ok((address, data)) = wallet_info {
                    let identity_request = parse_identity_request(data).map_err(VerificationProtocolError::Transport)?;
                    break (address, identity_request);
                }
            },
            connection_events = connection_event_stream.next() => {
                for event in connection_events.context("Failed to get BLE connection events").map_err(VerificationProtocolError::Transport)? {
                    match event {
                        ConnectionEvent::Connected { device_info } => {
                            if connected_devices.insert(device_info.address.to_owned(), device_info.to_owned()).is_none() {
                                identify_futures.push(async {
                                    let stream = read(IDENTITY_UUID, &device_info, ble_peripheral.clone());
                                    tokio::pin!(stream);
                                    let data = stream.try_next().await
                                        .map_err(|e| VerificationProtocolError::Transport(anyhow::anyhow!(e)))?
                                        .ok_or(VerificationProtocolError::Transport(anyhow::anyhow!("BLE identity request: No data read")))?;
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
        }
    };

    ble_peripheral
        .stop_advertisement()
        .await
        .context("Failed to stop advertisement")
        .map_err(VerificationProtocolError::Transport)?;

    let device_info =
        connected_devices
            .remove(&address)
            .ok_or(VerificationProtocolError::Failed(
                "Could not find connected device info".to_string(),
            ))?;

    Ok((device_info, identity_request))
}

pub(crate) fn read(
    id: &str,
    device_info: &DeviceInfo,
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> impl Stream<Item = Result<Vec<u8>, BleError>> + Send + use<> {
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
    request: &String,
    peer: &BLEPeer,
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> Result<(), VerificationProtocolError> {
    let encrypted = peer
        .encrypt(request)
        .context("Failed to encrypt presentation request")
        .map_err(VerificationProtocolError::Transport)?;

    let chunks = Chunks::from_bytes(encrypted.as_slice(), peer.device_info.mtu());
    let len = (chunks.len() as u16).to_be_bytes();

    send(REQUEST_SIZE_UUID, &len, peer, &*ble_peripheral).await?;
    write_chunks_with_report(chunks, peer, ble_peripheral).await
}

pub(crate) async fn send(
    id: &str,
    data: &[u8],
    wallet: &BLEPeer,
    ble_peripheral: &dyn BlePeripheral,
) -> Result<(), VerificationProtocolError> {
    ble_peripheral
        .set_characteristic_data(SERVICE_UUID.to_string(), id.to_string(), data)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
        .await?;

    ble_peripheral
        .wait_for_characteristic_read(
            wallet.device_info.address.to_string(),
            SERVICE_UUID.to_string(),
            id.to_string(),
        )
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
}

#[tracing::instrument(level = "debug", skip(ble_peripheral), err(Debug))]
async fn write_chunks_with_report(
    chunks: Chunks,
    wallet: &BLEPeer,
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> Result<(), VerificationProtocolError> {
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
) -> Result<Vec<u16>, VerificationProtocolError> {
    ble_peripheral
        .notify_characteristic_data(
            wallet.device_info.address.to_string(),
            SERVICE_UUID.into(),
            TRANSFER_SUMMARY_REPORT_UUID.into(),
            &[],
        )
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let report_bytes: TransferSummaryReport = read(
        TRANSFER_SUMMARY_REQUEST_UUID,
        &wallet.device_info,
        ble_peripheral.clone(),
    )
    .parse()
    .map_err(VerificationProtocolError::Transport)
    .await?;

    Ok(report_bytes)
}

#[tracing::instrument(level = "debug", skip(ble_peripheral), err(Debug))]
pub(crate) async fn read_presentation_submission(
    connected_wallet: &BLEPeer,
    ble_peripheral: Arc<dyn BlePeripheral>,
) -> Result<BleOpenId4VpResponse, VerificationProtocolError> {
    let request_size: MessageSize = read(
        CONTENT_SIZE_UUID,
        &connected_wallet.device_info,
        ble_peripheral.clone(),
    )
    .parse()
    .map_err(VerificationProtocolError::Transport)
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

    info!("About to start reading data, request_size: {request_size}");

    let mut transfer_summary_dispatched = false;
    loop {
        select! {
            biased;

            Some(chunk) = message_stream.next() => {
                let chunk = Chunk::from_bytes(&chunk.map_err(|e| VerificationProtocolError::Transport(e.into()))?).map_err(VerificationProtocolError::Transport)?;

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
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

                transfer_summary_dispatched = true;

                if missing_chunks.is_empty() {
                    break;
                }
            },
        }
    }

    if received_chunks.len() as u16 != request_size {
        return Err(VerificationProtocolError::Failed(format!(
            "not all chunks received, collected: {}/{request_size}",
            received_chunks.len()
        )));
    }
    info!("Received all chunks");

    received_chunks.sort_by(|a, b| a.index.cmp(&b.index));

    let presentation_request: Vec<u8> = received_chunks
        .into_iter()
        .flat_map(|c| c.payload)
        .collect();

    connected_wallet
        .decrypt(&presentation_request)
        .map_err(|e| {
            VerificationProtocolError::Transport(anyhow!(
                "Failed to decrypt presentation request: {e}"
            ))
        })
}

struct BleVerifierContext {
    task_id: Uuid,
    peer: BLEPeer,
    identity_request: IdentityRequest,
    peripheral: Arc<dyn BlePeripheral>,
    connection_event_stream: Arc<Mutex<ConnectionEventStream>>,
}

fn wallet_connect(
    task_id: Uuid,
    peripheral: Arc<dyn BlePeripheral>,
    keypair: KeyAgreementKey,
) -> BoxFuture<'static, Result<BleVerifierContext, VerificationProtocolError>> {
    async move {
        let mut connection_event_stream = get_connection_event_stream(peripheral.clone()).await;
        let (wallet, identity_request) =
            wait_for_wallet_identify_request(peripheral.clone(), &mut connection_event_stream)
                .await?;
        let (sender_key, receiver_key) = keypair
            .derive_session_secrets(identity_request.key, identity_request.nonce)
            .map_err(VerificationProtocolError::Transport)?;
        let peer = BLEPeer::new(wallet, sender_key, receiver_key, identity_request.nonce);
        Ok(BleVerifierContext {
            task_id,
            peer,
            identity_request,
            peripheral,
            connection_event_stream: Arc::new(Mutex::new(connection_event_stream)),
        })
    }
    .boxed()
}

fn wallet_disconnect(context: Arc<BleVerifierContext>) -> BoxFuture<'static, ()> {
    (async move {
        wallet_disconnect_event(
            &mut *context.connection_event_stream.lock().await,
            &context.peer.device_info.address,
        )
        .await
    })
    .boxed()
}

fn send_presentation_request(
    request: String,
    context: Arc<BleVerifierContext>,
) -> BoxFuture<'static, Result<(), VerificationProtocolError>> {
    (async move {
        write_presentation_request(&request, &context.peer, context.peripheral.clone()).await
    })
    .boxed()
}

fn receive_presentation(
    context: Arc<BleVerifierContext>,
) -> BoxFuture<'static, Result<BleOpenId4VpResponse, VerificationProtocolError>> {
    async move { read_presentation_submission(&context.peer, context.peripheral.clone()).await }
        .boxed()
}

fn interaction_data_from_response(
    nonce: String,
    presentation_definition: OpenID4VPPresentationDefinition,
    openid_request: OpenID4VP20AuthorizationRequest,
    submission: BleOpenId4VpResponse,
    context: Arc<BleVerifierContext>,
) -> Result<Vec<u8>, VerificationProtocolError> {
    let interaction_data = BLEOpenID4VPInteractionData {
        client_id: openid_request.client_id.to_owned(),
        nonce,
        task_id: context.task_id,
        peer: context.peer.clone(),
        openid_request,
        identity_request_nonce: Some(hex::encode(context.identity_request.nonce)),
        presentation_definition,
        presentation_submission: Some(submission),
    };
    serde_json::to_vec(&interaction_data).map_err(|err| {
        VerificationProtocolError::Failed(format!(
            "failed to serialize presentation_submission: {err}"
        ))
    })
}
