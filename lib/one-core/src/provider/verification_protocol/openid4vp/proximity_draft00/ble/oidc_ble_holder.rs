use std::sync::Arc;
use std::time::Duration;
use std::vec;

use anyhow::Context;
use async_trait::async_trait;
use futures::{Stream, StreamExt, TryFutureExt, stream};
use one_crypto::utilities::generate_random_bytes;
use serde_json::Value;
use tokio::select;
use url::Url;
use uuid::Uuid;

use super::{
    BLEParse, BLEPeer, CONTENT_SIZE_UUID, DISCONNECT_UUID, IDENTITY_UUID, IdentityRequest,
    OIDC_BLE_FLOW, REQUEST_SIZE_UUID, SERVICE_UUID, SUBMIT_VC_UUID, TRANSFER_SUMMARY_REPORT_UUID,
    TransferSummaryReport,
};
use crate::config::core_config::TransportType;
use crate::model::interaction::InteractionId;
use crate::provider::bluetooth_low_energy::BleError;
use crate::provider::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicWriteType, DeviceAddress, DeviceInfo,
};
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::PresentationSubmissionMappingDTO;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::KeyAgreementKey;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::dto::{
    BleOpenId4VpResponse, OpenID4VPBleData,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::model::BLEOpenID4VPInteractionData;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::{
    PRESENTATION_REQUEST_UUID, TRANSFER_SUMMARY_REQUEST_UUID,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::dto::{
    Chunk, ChunkExt, Chunks, MessageSize,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::holder_flow::{
    HolderCommonVPInteractionData, ProximityHolderTransport,
};
use crate::provider::verification_protocol::{
    VerificationProtocolError, deserialize_interaction_data,
};
use crate::repository::interaction_repository::InteractionRepository;
use crate::util::ble_resource::{Abort, BleWaiter, OnConflict};

pub(crate) struct BleHolderTransport {
    interaction_repository: Arc<dyn InteractionRepository>,
    ble: BleWaiter,
    url_scheme: String,
}

impl BleHolderTransport {
    pub(crate) fn new(
        url_scheme: String,
        ble: BleWaiter,
        interaction_repository: Arc<dyn InteractionRepository>,
    ) -> Self {
        Self {
            url_scheme,
            interaction_repository,
            ble,
        }
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    async fn enabled(&self) -> Result<bool, VerificationProtocolError> {
        self.ble
            .is_enabled()
            .await
            .map(|s| s.central)
            .map_err(|err| VerificationProtocolError::Transport(err.into()))
    }
}

pub(crate) struct BleHolderContext {
    task_id: Uuid,
    interaction_id: InteractionId,
    identity_request_nonce: [u8; 12],
    ble_peer: BLEPeer,
}

#[async_trait]
impl ProximityHolderTransport for BleHolderTransport {
    type Context = BleHolderContext;

    fn can_handle(&self, url: &Url) -> bool {
        const PRESENTATION_DEFINITION_BLE_NAME: &str = "name";
        const PRESENTATION_DEFINITION_BLE_KEY: &str = "key";
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        self.url_scheme == url.scheme()
            && query_has_key(PRESENTATION_DEFINITION_BLE_NAME)
            && query_has_key(PRESENTATION_DEFINITION_BLE_KEY)
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Ble
    }

    async fn setup(
        &self,
        url: Url,
        interaction_id: InteractionId,
    ) -> Result<Self::Context, VerificationProtocolError> {
        if !self.enabled().await? {
            return Err(VerificationProtocolError::Disabled(
                "BLE adapter not enabled".into(),
            ));
        }

        let query = url
            .query()
            .ok_or(VerificationProtocolError::InvalidRequest(
                "Query cannot be empty".to_string(),
            ))?;

        let OpenID4VPBleData { name, key } = serde_qs::from_str(query)
            .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))?;

        let interaction_repository = self.interaction_repository.clone();
        let result = self
            .ble
            .schedule(*OIDC_BLE_FLOW, |task_id, central, _| async move {
                // setup
                let verifier_public_key: [u8; 32] = hex::decode(&key)
                    .context("Failed to decode verifier public key")
                    .map_err(VerificationProtocolError::Transport)?
                    .as_slice()
                    .try_into()
                    .context("Invalid verifier public key length")
                    .map_err(VerificationProtocolError::Transport)?;

                tracing::debug!("Connecting to verifier: {name}");
                let device_info = connect_to_verifier(&name, &*central)
                    .await
                    .context("failed to connect to verifier")
                    .map_err(VerificationProtocolError::Transport)?;

                subscribe_to_notifications(&*central, &device_info.address).await?;
                let (ble_peer,identity_request_nonce)  = select! {
                    biased;

                    // disconnect
                    _ = verifier_disconnect_event(central.clone(), device_info.address.clone()) => {
                        Err(VerificationProtocolError::Failed("Verifier disconnected".into()))
                    },
                    result = async {
                        tracing::debug!("session_key_and_identity_request");
                        let (identity_request, ble_peer) =
                            session_key_and_identity_request(device_info.clone(), verifier_public_key)?;

                        send(
                            IDENTITY_UUID,
                            identity_request.clone().encode().as_ref(),
                            &ble_peer,
                            &*central,
                            CharacteristicWriteType::WithResponse,
                        )
                            .await?;

                        // Wait to ensure the verifier processed the identity request and updated
                        // the relevant characteristics
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        Ok((ble_peer, identity_request.nonce))
                    } => result
                }?;
                Ok(BleHolderContext { task_id, ble_peer, identity_request_nonce, interaction_id })
            },
  move |central, _| cancel(central, interaction_id, interaction_repository),
              OnConflict::ReplaceIfSameFlow,
              true
            ).await;

        result
            .value_or(VerificationProtocolError::Failed(
                "ble is busy with other flow".into(),
            ))
            .await
            .and_then(|(_, join_result)| {
                join_result.ok_or(VerificationProtocolError::Failed("task aborted".into()))
            })
            .and_then(std::convert::identity)
    }

    async fn receive_authz_request_token(
        &self,
        context: &mut Self::Context,
    ) -> Result<String, VerificationProtocolError> {
        let peer = context.ble_peer.clone();
        let interaction_id = context.interaction_id;
        let interaction_repository = self.interaction_repository.clone();
        self.ble
            .schedule_continuation(
                context.task_id,
                |_, central, _| async move { read_presentation_request(&peer, central).await },
                move |central, _| cancel(central, interaction_id, interaction_repository),
                true,
            )
            .await
            .value_or(VerificationProtocolError::Failed(
                "ble is busy with other flow".into(),
            ))
            .await
            .and_then(|(_, join_result)| {
                join_result.ok_or(VerificationProtocolError::Failed("task aborted".into()))
            })
            .and_then(std::convert::identity)
    }

    fn interaction_data_from_authz_request(
        &self,
        authz_request: OpenID4VP20AuthorizationRequest,
        context: Self::Context,
    ) -> Result<Vec<u8>, VerificationProtocolError> {
        let identity_request_nonce = Some(hex::encode(context.identity_request_nonce));
        serde_json::to_vec(&BLEOpenID4VPInteractionData {
            client_id: authz_request.client_id.to_owned(),
            nonce: authz_request
                .nonce
                .clone()
                .ok_or(VerificationProtocolError::InvalidRequest(
                    "nonce missing".to_string(),
                ))?,
            task_id: context.task_id,
            peer: context.ble_peer,
            presentation_definition: authz_request.presentation_definition.clone().ok_or(
                VerificationProtocolError::InvalidRequest(
                    "presentation_definition missing".to_string(),
                ),
            )?,
            openid_request: authz_request,
            identity_request_nonce,
            presentation_submission: None,
        })
        .map_err(|err| VerificationProtocolError::Failed(err.to_string()))
    }

    fn parse_interaction_data(
        &self,
        interaction_data: Value,
    ) -> Result<HolderCommonVPInteractionData, VerificationProtocolError> {
        let interaction_data: BLEOpenID4VPInteractionData =
            serde_json::from_value(interaction_data)
                .map_err(VerificationProtocolError::JsonError)?;

        Ok(HolderCommonVPInteractionData {
            client_id: interaction_data.client_id,
            presentation_definition: interaction_data.openid_request.presentation_definition,
            nonce: interaction_data.nonce,
            identity_request_nonce: interaction_data.identity_request_nonce,
        })
    }

    async fn submit_presentation(
        &self,
        vp_token: String,
        presentation_submission: PresentationSubmissionMappingDTO,
        interaction_data: Value,
    ) -> Result<(), VerificationProtocolError> {
        let interaction: BLEOpenID4VPInteractionData = serde_json::from_value(interaction_data)
            .map_err(VerificationProtocolError::JsonError)?;
        let peer = interaction.peer.clone();
        self.ble
            .schedule_continuation(
                interaction.task_id,
                {
                    let peer_address = interaction.peer.device_info.address.clone();
                    |_, central, _| async move {
                        let cloned_central = central.clone();

                        let result = select! {
                            biased;

                            _ = verifier_disconnect_event(central.clone(), interaction.peer.device_info.address.clone()) => {
                                Err(VerificationProtocolError::Failed("Verifier disconnected".into()))
                            },
                            result = async move {
                                let response = BleOpenId4VpResponse {
                                    vp_token,
                                    presentation_submission,
                                };

                                let enc_payload = interaction.peer
                                    .encrypt(&response)
                                    .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;

                                let chunks =
                                    Chunks::from_bytes(&enc_payload[..], interaction.peer.device_info.mtu());

                                let payload_len = (chunks.len() as u16).to_be_bytes();
                                send(
                                    CONTENT_SIZE_UUID,
                                    &payload_len,
                                    &interaction.peer,
                                    &*cloned_central,
                                    CharacteristicWriteType::WithResponse,
                                )
                                .await?;

                                for chunk in &chunks {
                                    send(
                                        SUBMIT_VC_UUID,
                                        &chunk.to_bytes(),
                                        &interaction.peer,
                                        &*cloned_central,
                                        CharacteristicWriteType::WithoutResponse,
                                    )
                                    .await?;
                                }

                                // Wait to ensure the verifier has received and processed all chunks
                                tokio::time::sleep(Duration::from_millis(500)).await;

                                let missing_chunks = get_transfer_summary(&interaction.peer, &*cloned_central).await?;

                                if !missing_chunks.is_empty() {
                                    tracing::debug!("Resubmitting {} chunks", missing_chunks.len());
                                    for chunk in chunks.iter().filter(|chunk| missing_chunks.contains(&chunk.index)) {
                                        send(
                                            SUBMIT_VC_UUID,
                                            &chunk.to_bytes(),
                                            &interaction.peer,
                                            &*cloned_central,
                                            CharacteristicWriteType::WithoutResponse,
                                        )
                                        .await?;
                                    }
                                }
                                Ok::<_, VerificationProtocolError>(())
                            } => result
                        };

                        // Give some to the verifier to read everything
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        unsubscribe_and_disconnect(peer_address, central).await;
                        result
                    }
                },
                {
                    move |central, _| async move {
                        let verifier_address = peer.device_info.address.clone();
                        unsubscribe_and_disconnect(verifier_address, central).await;
                    }
                },
                false,
            )
            .await
            .value_or(VerificationProtocolError::Failed(
                "ble is busy with other flow".into(),
            ))
            .await
            .and_then(|(_, join_result)| {
                join_result.ok_or(VerificationProtocolError::Failed("task aborted".into()))
            })
            .and_then(std::convert::identity)
    }

    async fn reject_proof(&self, _: Value) -> Result<(), VerificationProtocolError> {
        self.ble.abort(Abort::Flow(*OIDC_BLE_FLOW)).await;
        Ok(())
    }
}

async fn cancel(
    central: Arc<dyn BleCentral>,
    interaction_id: InteractionId,
    interaction_repository: Arc<dyn InteractionRepository>,
) {
    let Ok(interaction) = interaction_repository
        .get_interaction(&interaction_id, &Default::default())
        .await
        .map_err(|err| VerificationProtocolError::Failed(err.to_string()))
    else {
        return;
    };

    let Ok(interaction_data) = deserialize_interaction_data::<BLEOpenID4VPInteractionData>(
        interaction.as_ref().and_then(|i| i.data.as_ref()),
    ) else {
        return;
    };
    let verifier_address = interaction_data.peer.device_info.address.clone();
    unsubscribe_and_disconnect(verifier_address, central).await;
}

async fn unsubscribe_and_disconnect(peer_address: DeviceAddress, central: Arc<dyn BleCentral>) {
    if let Err(err) = unsubscribe_from_characteristic_notifications(&*central, &peer_address).await
    {
        tracing::warn!("Failed to unsubscribe from characteristic notifications: {err}");
    }

    if let Err(err) = central.disconnect(peer_address).await {
        tracing::warn!("Failed to disconnect BLE central: {err}");
    }
}

#[tracing::instrument(level = "debug", skip(ble_central), err(Debug))]
async fn connect_to_verifier(
    name: &str,
    ble_central: &dyn BleCentral,
) -> Result<DeviceInfo, VerificationProtocolError> {
    if ble_central
        .is_scanning()
        .await
        .context("is_discovering failed")
        .map_err(VerificationProtocolError::Transport)?
    {
        ble_central
            .stop_scan()
            .await
            .context("stop_discovery failed")
            .map_err(VerificationProtocolError::Transport)?;
    }
    tracing::debug!("start_scan");
    ble_central
        .start_scan(Some(vec![SERVICE_UUID.to_string()]))
        .await
        .context("start_discovery failed")
        .map_err(VerificationProtocolError::Transport)?;

    tracing::debug!("Started scanning");

    loop {
        let discovered = ble_central
            .get_discovered_devices()
            .await
            .context("get_discovered_devices failed")
            .map_err(VerificationProtocolError::Transport)?;
        tracing::debug!("Discovered: {}", discovered.len());

        for device in discovered {
            tracing::debug!(
                "local_device_name_matches: {:?} == {name}",
                device.local_device_name
            );

            let local_device_name_matches = device
                .local_device_name
                .map(|advertised_name| advertised_name == name)
                .unwrap_or(false);

            if local_device_name_matches {
                ble_central
                    .stop_scan()
                    .await
                    .context("stop_discovery failed")
                    .map_err(VerificationProtocolError::Transport)?;

                let mtu = ble_central
                    .connect(device.device_address.clone())
                    .await
                    .context("connect failed")
                    .map_err(VerificationProtocolError::Transport)?;

                tracing::debug!("Connected to `{name}`, MTU: {mtu}");

                return Ok(DeviceInfo::new(device.device_address, mtu));
            }
        }
    }
}

async fn subscribe_to_notifications(
    ble_central: &dyn BleCentral,
    verifier_address: &str,
) -> Result<(), VerificationProtocolError> {
    ble_central
        .subscribe_to_characteristic_notifications(
            verifier_address.to_string(),
            SERVICE_UUID.to_string(),
            DISCONNECT_UUID.to_string(),
        )
        .await
        .context("failed to subscribe to disconnect notifications")
        .map_err(VerificationProtocolError::Transport)?;

    ble_central
        .subscribe_to_characteristic_notifications(
            verifier_address.to_string(),
            SERVICE_UUID.to_string(),
            TRANSFER_SUMMARY_REPORT_UUID.to_string(),
        )
        .await
        .context("failed to subscribe to summary report notifications")
        .map_err(VerificationProtocolError::Transport)?;

    Ok(())
}

async fn unsubscribe_from_characteristic_notifications(
    ble_central: &dyn BleCentral,
    verifier_address: &str,
) -> Result<(), VerificationProtocolError> {
    ble_central
        .unsubscribe_from_characteristic_notifications(
            verifier_address.to_string(),
            SERVICE_UUID.to_string(),
            DISCONNECT_UUID.to_string(),
        )
        .await
        .context("failed to unsubscribe from disconnect notification")
        .map_err(VerificationProtocolError::Transport)?;

    ble_central
        .unsubscribe_from_characteristic_notifications(
            verifier_address.to_string(),
            SERVICE_UUID.to_string(),
            TRANSFER_SUMMARY_REPORT_UUID.to_string(),
        )
        .await
        .context("failed to unsubscribe from summary report notification")
        .map_err(VerificationProtocolError::Transport)?;

    Ok(())
}

async fn verifier_disconnect_event(
    ble_central: Arc<dyn BleCentral>,
    verifier_address: String,
) -> Result<(), VerificationProtocolError> {
    loop {
        let notification = ble_central
            .get_notifications(
                verifier_address.clone(),
                SERVICE_UUID.to_string(),
                DISCONNECT_UUID.to_string(),
            )
            .await
            .context("failed to get disconnect notifications")
            .map_err(VerificationProtocolError::Transport)?;

        if !notification.is_empty() {
            return Ok(());
        }
    }
}

fn session_key_and_identity_request(
    verifier_device: DeviceInfo,
    verifier_public_key: [u8; 32],
) -> Result<(IdentityRequest, BLEPeer), VerificationProtocolError> {
    let key_agreement_key = KeyAgreementKey::new_random();
    let public_key = key_agreement_key.public_key_bytes();
    let nonce = generate_random_bytes::<12>();

    let (receiver_key, sender_key) = key_agreement_key
        .derive_session_secrets(verifier_public_key, nonce)
        .map_err(VerificationProtocolError::Transport)?;

    Ok((
        IdentityRequest {
            nonce,
            key: public_key,
        },
        BLEPeer::new(verifier_device, sender_key, receiver_key, nonce),
    ))
}

#[tracing::instrument(level = "debug", skip(ble_central), err(Debug))]
async fn send(
    id: &str,
    data: &[u8],
    verifier: &BLEPeer,
    ble_central: &dyn BleCentral,
    write_type: CharacteristicWriteType,
) -> Result<(), VerificationProtocolError> {
    ble_central
        .write_data(
            verifier.device_info.address.clone(),
            SERVICE_UUID.to_string(),
            id.to_string(),
            data,
            write_type,
        )
        .await
        .context("write_data failed")
        .map_err(VerificationProtocolError::Transport)
}

#[tracing::instrument(level = "debug", skip(ble_central), err(Debug))]
async fn read_presentation_request(
    connected_verifier: &BLEPeer,
    ble_central: Arc<dyn BleCentral>,
) -> Result<String, VerificationProtocolError> {
    let request_size: MessageSize =
        read(REQUEST_SIZE_UUID, connected_verifier, ble_central.clone())
            .parse()
            .map_err(VerificationProtocolError::Transport)
            .await?;

    tracing::debug!("Request size {request_size}");

    let message_stream = read(
        PRESENTATION_REQUEST_UUID,
        connected_verifier,
        ble_central.clone(),
    );
    tokio::pin!(message_stream);

    let mut notification = ble_central.get_notifications(
        connected_verifier.device_info.address.clone(),
        SERVICE_UUID.to_string(),
        TRANSFER_SUMMARY_REPORT_UUID.to_string(),
    );

    let mut received_chunks: Vec<Chunk> = vec![];

    loop {
        select! {
           biased;

           Some(chunk) = message_stream.next(), if received_chunks.len() < request_size.into() => {
                let chunk = chunk.context("Reading presentation request chunk failed").map_err(VerificationProtocolError::Transport)?;
                let chunk = Chunk::from_bytes(chunk.as_slice()).map_err(VerificationProtocolError::Transport)?;
                if received_chunks.iter().any(|c| c.index == chunk.index) {
                    continue;
                } else {
                    received_chunks.push(chunk);
                }
            },
            _ = &mut notification => {
                let missing_chunks = (1..request_size)
                    .filter(|idx| !received_chunks.iter().any(|c| c.index == *idx))
                    .map(|idx| idx.to_be_bytes())
                    .collect::<Vec<[u8; 2]>>()
                    .concat();

                send(
                    TRANSFER_SUMMARY_REQUEST_UUID,
                    missing_chunks.as_ref(),
                    connected_verifier,
                    &*ble_central,
                    CharacteristicWriteType::WithResponse,
                ).await?;

                tracing::debug!(
                    "Sent TRANSFER_SUMMARY_REQUEST_UUID",
                );

                if missing_chunks.is_empty() {
                    break;
                };
            }
        }
    }

    if received_chunks.len() as u16 != request_size {
        return Err(VerificationProtocolError::Failed(
            "not all chunks received".to_string(),
        ));
    }

    received_chunks.sort_by(|a, b| a.index.cmp(&b.index));

    let presentation_request: Vec<u8> = received_chunks
        .into_iter()
        .flat_map(|c| c.payload)
        .collect();

    let decrypted_request_jwt: String =
        connected_verifier
            .decrypt(&presentation_request)
            .map_err(|e| {
                VerificationProtocolError::Failed(format!(
                    "Failed to decrypt presentation request: {e}"
                ))
            })?;

    Ok(decrypted_request_jwt)
}

pub(crate) fn read(
    id: &str,
    wallet: &BLEPeer,
    ble_central: Arc<dyn BleCentral>,
) -> impl Stream<Item = Result<Vec<u8>, BleError>> + Send {
    futures::stream::unfold(
        (
            wallet.device_info.address.clone(),
            id.to_string(),
            ble_central,
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
    )
}

#[tracing::instrument(level = "debug", skip(ble_central) err(Debug))]
async fn get_transfer_summary(
    connected_verifier: &BLEPeer,
    ble_central: &dyn BleCentral,
) -> Result<Vec<u16>, VerificationProtocolError> {
    send(
        TRANSFER_SUMMARY_REQUEST_UUID,
        &[],
        connected_verifier,
        ble_central,
        CharacteristicWriteType::WithResponse,
    )
    .await?;

    let report = ble_central
        .get_notifications(
            connected_verifier.device_info.address.clone(),
            SERVICE_UUID.to_string(),
            TRANSFER_SUMMARY_REPORT_UUID.to_string(),
        )
        .await
        .context("get_notifications failed")
        .map_err(VerificationProtocolError::Transport)?;

    let report: TransferSummaryReport = stream::iter(report)
        .map(Ok)
        .boxed()
        .parse()
        .map_err(VerificationProtocolError::Transport)
        .await?;

    Ok(report)
}
