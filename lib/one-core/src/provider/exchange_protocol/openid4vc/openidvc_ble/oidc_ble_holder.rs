use std::sync::Arc;
use std::time::Duration;
use std::vec;

use anyhow::Context;
use futures::{stream, Stream, StreamExt, TryFutureExt};
use one_providers::exchange_protocol::openid4vc::model::PresentationSubmissionMappingDTO;
use rand::rngs::OsRng;
use rand::Rng;
use shared_types::ProofId;
use time::OffsetDateTime;
use uuid::{uuid, Uuid};

use super::{
    BLEParse, BLEPeer, IdentityRequest, KeyAgreementKey, MessageSize, TransferSummaryReport,
    CONTENT_SIZE_UUID, IDENTITY_UUID, REQUEST_SIZE_UUID, SERVICE_UUID, SUBMIT_VC_UUID,
    TRANSFER_SUMMARY_REPORT_UUID,
};
use crate::model::interaction::Interaction;
use crate::model::proof::{ProofState, ProofStateEnum};
use crate::provider::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::provider::bluetooth_low_energy::low_level::dto::{CharacteristicWriteType, DeviceInfo};
use crate::provider::bluetooth_low_energy::BleError;
use crate::provider::exchange_protocol::openid4vc::dto::{
    Chunk, ChunkExt, Chunks, OpenID4VPPresentationDefinition,
};
use crate::provider::exchange_protocol::openid4vc::model::{
    BLEOpenID4VPInteractionData, BleOpenId4VpResponse,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::{
    PRESENTATION_REQUEST_UUID, TRANSFER_SUMMARY_REQUEST_UUID,
};
use crate::provider::exchange_protocol::{deserialize_interaction_data, ExchangeProtocolError};
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::util::ble_resource::{BleWaiter, OnConflict};

pub struct OpenID4VCBLEHolder {
    pub proof_repository: Arc<dyn ProofRepository>,
    pub interaction_repository: Arc<dyn InteractionRepository>,
    pub ble: BleWaiter,
}

impl OpenID4VCBLEHolder {
    pub fn new(
        proof_repository: Arc<dyn ProofRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        ble: BleWaiter,
    ) -> Self {
        Self {
            proof_repository,
            interaction_repository,
            ble,
        }
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
            .map(|s| s.central)
            .unwrap_or(false);

        if enabled {
            return Ok(true);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
        self.ble
            .is_enabled()
            .await
            .map(|s| s.central)
            .map_err(|err| ExchangeProtocolError::Transport(err.into()))
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn handle_invitation(
        &mut self,
        name: String,
        x25519_public_key_hex: String,
        proof_id: ProofId,
        interaction_id: Uuid,
    ) -> Result<(), ExchangeProtocolError> {
        let flow_id = uuid!(SERVICE_UUID);

        let interaction_repository = self.interaction_repository.clone();

        let result = self
            .ble
            .schedule(
                flow_id,
                |task_id, central, _| async move {
                    let verifier_public_key: [u8; 32] = hex::decode(&x25519_public_key_hex)
                        .context("Failed to decode verifier public key")
                        .map_err(ExchangeProtocolError::Transport)?
                        .as_slice()
                        .try_into()
                        .context("Invalid verifier public key length")
                        .map_err(ExchangeProtocolError::Transport)?;

                    tracing::debug!("Connecting to verifier: {name}");
                    let device_info = connect_to_verifier(&name, &verifier_public_key, &*central)
                        .await
                        .context("failed to connect to verifier")
                        .map_err(ExchangeProtocolError::Transport)?;

                    tracing::debug!("session_key_and_identity_request");
                    let (identity_request, ble_peer) =
                        session_key_and_identity_request(device_info, verifier_public_key)?;

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

                    tracing::debug!("read_presentation_definition");
                    let presentation_definition =
                        read_presentation_definition(&ble_peer, central.clone()).await?;

                    let now = OffsetDateTime::now_utc();

                    Ok::<_, ExchangeProtocolError>(Interaction {
                        id: interaction_id,
                        created_date: now,
                        last_modified: now,
                        host: None,
                        data: Some(
                            serde_json::to_vec(&BLEOpenID4VPInteractionData {
                                task_id,
                                peer: ble_peer,
                                nonce: Some(hex::encode(identity_request.nonce)),
                                presentation_definition: Some(presentation_definition),
                                presentation_submission: None,
                            })
                            .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?,
                        ),
                    })
                },
                move |central, _| async move {
                    let Ok(interaction) = interaction_repository
                        .get_interaction(&interaction_id, &Default::default())
                        .await
                        .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))
                    else {
                        return;
                    };

                    let Ok(interaction_data) =
                        deserialize_interaction_data::<BLEOpenID4VPInteractionData>(
                            interaction.as_ref().and_then(|i| i.data.as_ref()),
                        )
                    else {
                        return;
                    };

                    let _ = central
                        .disconnect(interaction_data.peer.device_info.address.clone())
                        .await;
                },
                OnConflict::ReplaceIfSameFlow,
                true,
            )
            .await
            .value_or(ExchangeProtocolError::Failed(
                "ble is busy with other flow".into(),
            ))
            .await
            .and_then(|(_, join_result)| {
                join_result.ok_or(ExchangeProtocolError::Failed("task aborted".into()))
            })
            .and_then(std::convert::identity);

        match result {
            Ok(interaction) => {
                self.interaction_repository
                    .update_interaction(interaction)
                    .await
                    .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;
                Ok(())
            }
            Err(err) => {
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
                Err(err)
            }
        }
    }

    pub async fn disconnect_from_verifier(&self) {
        self.ble.abort(Some(uuid!(SERVICE_UUID))).await;
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn submit_presentation(
        &self,
        vp_token: String,
        presentation_submission: PresentationSubmissionMappingDTO,
        interaction: &BLEOpenID4VPInteractionData,
    ) -> Result<(), ExchangeProtocolError> {
        self.ble
            .schedule_continuation(
                interaction.task_id,
                {
                    let peer = interaction.peer.clone();
                    move |_, central, _| {
                        async move {
                            let response = BleOpenId4VpResponse {
                                vp_token,
                                presentation_submission,
                            };

                            let enc_payload = peer
                                .encrypt(response)
                                .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

                            let chunks =
                                Chunks::from_bytes(&enc_payload[..], peer.device_info.mtu());

                            let payload_len = (chunks.len() as u16).to_be_bytes();
                            send(
                                CONTENT_SIZE_UUID,
                                &payload_len,
                                &peer,
                                &*central,
                                CharacteristicWriteType::WithResponse,
                            )
                            .await?;

                            for chunk in &chunks {
                                send(
                                    SUBMIT_VC_UUID,
                                    &chunk.to_bytes(),
                                    &peer,
                                    &*central,
                                    CharacteristicWriteType::WithoutResponse,
                                )
                                .await?;
                            }

                            // Wait to ensure the verifier has received and processed all chunks
                            tokio::time::sleep(Duration::from_millis(500)).await;

                            let missing_chunks = get_transfer_summary(&peer, &*central).await?;

                            if !missing_chunks.is_empty() {
                                return Err(ExchangeProtocolError::Failed(
                                    "did not send all chunks".to_string(),
                                ));
                            }

                            // Give some to the verifier to read everything
                            tokio::time::sleep(Duration::from_secs(1)).await;

                            let _ = central.disconnect(peer.device_info.address.clone()).await;

                            Ok::<_, ExchangeProtocolError>(())
                        }
                    }
                },
                {
                    let peer = interaction.peer.clone();
                    move |central, _| async move {
                        let _ = central.disconnect(peer.device_info.address.clone()).await;
                    }
                },
                false,
            )
            .await
            .value_or(ExchangeProtocolError::Failed(
                "ble is busy with other flow".into(),
            ))
            .await
            .and_then(|(_, join_result)| {
                join_result.ok_or(ExchangeProtocolError::Failed("task aborted".into()))
            })
            .and_then(std::convert::identity)
    }
}

#[tracing::instrument(level = "debug", skip(ble_central), err(Debug))]
async fn connect_to_verifier(
    name: &str,
    public_key: &[u8],
    ble_central: &dyn BleCentral,
) -> Result<DeviceInfo, ExchangeProtocolError> {
    if ble_central
        .is_scanning()
        .await
        .context("is_discovering failed")
        .map_err(ExchangeProtocolError::Transport)?
    {
        ble_central
            .stop_scan()
            .await
            .context("stop_discovery failed")
            .map_err(ExchangeProtocolError::Transport)?;
    }
    tracing::debug!("start_scan");
    ble_central
        .start_scan(Some(vec![SERVICE_UUID.to_string()]))
        .await
        .context("start_discovery failed")
        .map_err(ExchangeProtocolError::Transport)?;

    tracing::debug!("Started scanning");

    loop {
        let discovered = ble_central
            .get_discovered_devices()
            .await
            .context("get_discovered_devices failed")
            .map_err(ExchangeProtocolError::Transport)?;
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
                    .map_err(ExchangeProtocolError::Transport)?;

                let mtu = ble_central
                    .connect(device.device_address.clone())
                    .await
                    .context("connect failed")
                    .map_err(ExchangeProtocolError::Transport)?;

                tracing::debug!("Connected to `{name}`, MTU: {mtu}");

                return Ok(DeviceInfo::new(device.device_address, mtu));
            }
        }
    }
}

fn session_key_and_identity_request(
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

#[tracing::instrument(level = "debug", skip(ble_central), err(Debug))]
async fn send(
    id: &str,
    data: &[u8],
    verifier: &BLEPeer,
    ble_central: &dyn BleCentral,
    write_type: CharacteristicWriteType,
) -> Result<(), ExchangeProtocolError> {
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
        .map_err(ExchangeProtocolError::Transport)
}

#[tracing::instrument(level = "debug", skip(ble_central), err(Debug))]
async fn read_presentation_definition(
    connected_verifier: &BLEPeer,
    ble_central: Arc<dyn BleCentral>,
) -> Result<OpenID4VPPresentationDefinition, ExchangeProtocolError> {
    let request_size: MessageSize =
        read(REQUEST_SIZE_UUID, connected_verifier, ble_central.clone())
            .parse()
            .map_err(ExchangeProtocolError::Transport)
            .await?;

    tracing::debug!("Request size {request_size}");

    let message_stream = read(
        PRESENTATION_REQUEST_UUID,
        connected_verifier,
        ble_central.clone(),
    );
    tokio::pin!(message_stream);

    ble_central
        .subscribe_to_characteristic_notifications(
            connected_verifier.device_info.address.clone(),
            SERVICE_UUID.to_string(),
            TRANSFER_SUMMARY_REPORT_UUID.to_string(),
        )
        .await
        .context("subscribe_to_characteristic_notifications failed")
        .map_err(ExchangeProtocolError::Transport)?;

    let mut notification = ble_central.get_notifications(
        connected_verifier.device_info.address.clone(),
        SERVICE_UUID.to_string(),
        TRANSFER_SUMMARY_REPORT_UUID.to_string(),
    );

    let mut received_chunks: Vec<Chunk> = vec![];

    loop {
        tokio::select! {
           biased;

           Some(chunk) = message_stream.next(), if received_chunks.len() < request_size.into() => {
                let chunk = chunk.context("Reading presentation request chunk failed").map_err(ExchangeProtocolError::Transport)?;
                let chunk = Chunk::from_bytes(chunk.as_slice()).map_err(ExchangeProtocolError::Transport)?;
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

    ble_central
        .unsubscribe_from_characteristic_notifications(
            connected_verifier.device_info.address.clone(),
            SERVICE_UUID.to_string(),
            TRANSFER_SUMMARY_REPORT_UUID.to_string(),
        )
        .await
        .context("unsubscribe_from_characteristic_notifications failed")
        .map_err(ExchangeProtocolError::Transport)?;

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
            ExchangeProtocolError::Failed(format!("Failed to decrypt presentation request: {e}"))
        })
}

pub fn read(
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
) -> Result<Vec<u16>, ExchangeProtocolError> {
    ble_central
        .subscribe_to_characteristic_notifications(
            connected_verifier.device_info.address.clone(),
            SERVICE_UUID.to_string(),
            TRANSFER_SUMMARY_REPORT_UUID.to_string(),
        )
        .await
        .context("subscribe_to_characteristic_notifications failed")
        .map_err(ExchangeProtocolError::Transport)?;

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
        .map_err(ExchangeProtocolError::Transport)?;

    let report: TransferSummaryReport = stream::iter(report)
        .map(Ok)
        .boxed()
        .parse()
        .map_err(ExchangeProtocolError::Transport)
        .await?;

    Ok(report)
}
