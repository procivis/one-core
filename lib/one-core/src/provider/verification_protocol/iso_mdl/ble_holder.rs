use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, ProofId};
use tokio::sync::oneshot;
use uuid::Uuid;

use super::ble::{CLIENT_2_SERVER, ISO_MDL_FLOW, SERVER_2_CLIENT, STATE};
use super::common::{
    Chunk, DeviceRequest, EDeviceKey, KeyAgreement, SkDevice, SkReader,
    create_session_transcript_bytes, split_into_chunks, to_cbor,
};
use super::device_engagement::DeviceEngagement;
use super::session::{Command, SessionData, SessionEstablishment, StatusCode};
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::Interaction;
use crate::model::proof::{ProofStateEnum, UpdateProofRequest};
use crate::provider::bluetooth_low_energy::low_level::ble_peripheral::TrackingBlePeripheral;
use crate::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicPermissions, CharacteristicProperties, ConnectionEvent,
    CreateCharacteristicOptions, DeviceAddress, DeviceInfo, ServiceDescription,
};
use crate::provider::presentation_formatter::mso_mdoc::model::DeviceResponse;
use crate::provider::verification_protocol::{
    VerificationProtocolError, deserialize_interaction_data,
};
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ErrorCode::BR_0000;
use crate::service::error::{ErrorCodeMixin, ServiceError};
use crate::util::ble_resource::{BleWaiter, OnConflict, ScheduleResult};
use crate::util::mdoc::{Bstr, EmbeddedCbor};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MdocBleHolderInteractionData {
    // known from the beginning
    pub organisation_id: OrganisationId,
    pub service_uuid: Uuid,

    // currently latest scheduled task identifier
    pub continuation_task_id: Uuid,

    // known only after verifier connects
    pub session: Option<MdocBleHolderInteractionSessionData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MdocBleHolderInteractionSessionData {
    pub sk_device: SkDevice,
    pub sk_reader: SkReader,
    pub device_request_bytes: Vec<u8>,
    pub device_address: DeviceAddress,
    pub mtu: u16,
    pub session_transcript_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct ServerInfo {
    pub task_id: Uuid,
    pub mac_address: Option<String>,
    pub service_uuid: Uuid,
}

/// Initiates mDL advertisement
pub(crate) async fn start_mdl_server(ble: &BleWaiter) -> Result<ServerInfo, ServiceError> {
    let service_uuid = Uuid::new_v4();

    let (task_id, result) = ble
        .schedule(
            *ISO_MDL_FLOW,
            |_, _, peripheral| async move {
                peripheral
                    .start_advertisement(
                        None,
                        vec![ServiceDescription {
                            uuid: service_uuid.to_string(),
                            advertise: true,
                            advertised_service_data: None,
                            characteristics: get_characteristic_options(),
                        }],
                    )
                    .await
            },
            |_, _| async move {},
            OnConflict::ReplaceIfSameFlow,
            true,
        )
        .await
        .value_or(ServiceError::Other("BLE is busy".into()))
        .await?;

    let mac_address = result
        .ok_or(ServiceError::Other("flow was aborted".into()))?
        .map_err(|err| ServiceError::Other(format!("ble error: {err}")))?;

    Ok(ServerInfo {
        task_id,
        mac_address,
        service_uuid,
    })
}

/// Waits for verifier connection + reads device request
pub(crate) async fn receive_mdl_request(
    ble: &BleWaiter,
    device_engagement: EmbeddedCbor<DeviceEngagement>,
    key_pair: KeyAgreement<EDeviceKey>,
    interaction_repository: Arc<dyn InteractionRepository>,
    mut interaction: Interaction,
    proof_repository: Arc<dyn ProofRepository>,
    proof_id: ProofId,
) -> Result<(), ServiceError> {
    let (tx, rx) = oneshot::channel();
    let proof_repository_clone = proof_repository.clone();

    let interaction_data: MdocBleHolderInteractionData =
        deserialize_interaction_data(interaction.data.as_ref())?;

    let ScheduleResult::Scheduled { .. } = ble
        .schedule_continuation(
            interaction_data.continuation_task_id,
            |task_id, _, peripheral| async move {
                let info =
                    wait_for_active_device(&peripheral, interaction_data.service_uuid).await?;

                peripheral
                    .stop_advertisement()
                    .await
                    .context("failed to stop advertisement")
                    .map_err(VerificationProtocolError::Transport)?;

                let result = tx.send(info.clone());
                if let Err(device_info) = result {
                    tracing::warn!("failed to send device info: {device_info:?}");
                }

                let result = async {
                    let session_establishment =
                        read_request(&peripheral, &info, interaction_data.service_uuid).await?;

                    let session_transcript_bytes = create_session_transcript_bytes(
                        device_engagement.clone(),
                        session_establishment.e_reader_key.clone(),
                    )?;

                    let (sk_device, sk_reader) = key_pair
                        .derive_session_keys(
                            session_establishment.e_reader_key.clone().into_inner(),
                            session_transcript_bytes.bytes(),
                        )
                        .context("failed to derive key")
                        .map_err(VerificationProtocolError::Other)?;

                    let device_request_bytes = sk_reader
                        .decrypt(&session_establishment.data.0)
                        .map_err(VerificationProtocolError::Other)?;

                    let device_request: DeviceRequest =
                        ciborium::from_reader(device_request_bytes.as_slice())
                            .context("device request deserialization error")
                            .map_err(VerificationProtocolError::Other)?;

                    if device_request.version != "1.0" {
                        return Err(VerificationProtocolError::Other(anyhow!(
                            "unsupported request version"
                        )));
                    }

                    interaction.data = Some(
                        serde_json::to_vec(&MdocBleHolderInteractionData {
                            continuation_task_id: task_id,
                            session: Some(MdocBleHolderInteractionSessionData {
                                sk_device,
                                sk_reader,
                                device_address: info.address.clone(),
                                device_request_bytes,
                                mtu: info.mtu(),
                                session_transcript_bytes: session_transcript_bytes.into_bytes(),
                            }),
                            ..interaction_data
                        })
                        .context("interaction serialization error")
                        .map_err(VerificationProtocolError::Other)?,
                    );

                    interaction_repository
                        .update_interaction(interaction.into())
                        .await
                        .context("failed to save interaction")
                        .map_err(VerificationProtocolError::Other)?;

                    proof_repository
                        .update_proof(
                            &proof_id,
                            UpdateProofRequest {
                                state: Some(ProofStateEnum::Requested),
                                ..Default::default()
                            },
                            None,
                        )
                        .await
                        .context("failed to update proof state")
                        .map_err(VerificationProtocolError::Other)?;

                    Ok::<_, VerificationProtocolError>(())
                }
                .await;

                if let Err(ref err) = result {
                    let error_metadata = HistoryErrorMetadata {
                        error_code: err.error_code(),
                        message: err.to_string(),
                    };
                    set_proof_error(&*proof_repository, &proof_id, error_metadata).await;
                    notify_end(&peripheral, Some(&info), interaction_data.service_uuid).await;
                }

                result
            },
            move |_, peripheral| async move {
                let error_metadata = HistoryErrorMetadata {
                    error_code: BR_0000,
                    message: "Propose proof was cancelled".to_string(),
                };
                set_proof_error(&*proof_repository_clone, &proof_id, error_metadata).await;
                notify_end(
                    &peripheral,
                    rx.await.ok().as_ref(),
                    interaction_data.service_uuid,
                )
                .await;
            },
            true,
        )
        .await
    else {
        return Err(ServiceError::Other("ble flow was interrupted".into()));
    };

    Ok(())
}

pub(crate) async fn send_mdl_response(
    ble: &BleWaiter,
    device_response: DeviceResponse,
    interaction_data: MdocBleHolderInteractionData,
) -> Result<(), VerificationProtocolError> {
    let interaction_session_data =
        interaction_data
            .session
            .ok_or(VerificationProtocolError::Failed(
                "interaction_session_data missing".to_string(),
            ))?;

    let device_response_bytes = to_cbor(&device_response)?;

    let encrypted_device_response = interaction_session_data
        .sk_device
        .encrypt(&device_response_bytes)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let session_data = SessionData {
        data: Some(Bstr(encrypted_device_response)),
        status: Some(StatusCode::SessionTermination),
    };
    let session_data_bytes = to_cbor(&session_data)?;

    let chunks = split_into_chunks(session_data_bytes, interaction_session_data.mtu as _)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let (_, result) = ble
        .schedule_continuation(
            interaction_data.continuation_task_id,
            |_, _, peripheral| async move {
                for chunk in chunks {
                    peripheral
                        .notify_characteristic_data(
                            interaction_session_data.device_address.clone(),
                            interaction_data.service_uuid.to_string(),
                            SERVER_2_CLIENT.into(),
                            &chunk,
                        )
                        .await
                        .map_err(|e| {
                            VerificationProtocolError::Failed(format!(
                                "Unable to send response: {e}"
                            ))
                        })?;
                }

                // End command signal not necessary, since we signal SessionTermination via SessionData status

                // Wait for device disconnection here (but this means blocking UI)
                tokio::time::sleep(Duration::from_millis(200)).await;

                Ok::<_, VerificationProtocolError>(())
            },
            move |_, _| async move {},
            false,
        )
        .await
        .value_or(VerificationProtocolError::Failed(
            "BLE was interrupted".into(),
        ))
        .await?;

    result.ok_or(VerificationProtocolError::Failed(
        "BLE flow was aborted".into(),
    ))??;

    Ok(())
}

async fn wait_for_active_device(
    peripheral: &TrackingBlePeripheral,
    service_uuid: Uuid,
) -> Result<DeviceInfo, VerificationProtocolError> {
    loop {
        let connected_devices = peripheral
            .get_connection_change_events()
            .await
            .context("failed to get connection change events")
            .map_err(VerificationProtocolError::Transport)?
            .into_iter()
            .filter_map(|info| match info {
                ConnectionEvent::Connected { device_info } => Some(device_info),
                ConnectionEvent::Disconnected { .. } => None,
            });

        for connected_device in connected_devices {
            tracing::debug!("device connected: {connected_device:?}");

            if wait_for_start(peripheral, &connected_device, service_uuid).await? {
                return Ok(connected_device);
            }
        }
    }
}

/// Wait for Start command according to ISO 18013-5 (8.3.3.1.1.6 Data retrieval)
///
/// - returns `true` if Start command was written
/// - returns `false` if no command was written and reconnection should happen
async fn wait_for_start(
    peripheral: &TrackingBlePeripheral,
    info: &DeviceInfo,
    service_uuid: Uuid,
) -> Result<bool, VerificationProtocolError> {
    let command_written = match peripheral
        .get_characteristic_writes(
            info.address.clone(),
            service_uuid.to_string(),
            STATE.to_string(),
        )
        .await
    {
        Ok(writes) => writes.concat(),
        Err(err) => {
            tracing::warn!("Failed to receive State command: {err}");
            // according to ISO 18013-5 (8.3.3.1.1.8 Connection re-establishment),
            // re-connection in this phase is allowed
            return Ok(false);
        }
    };

    let command: Command = command_written
        .try_into()
        .map_err(VerificationProtocolError::Transport)?;

    if command == Command::Start {
        Ok(true)
    } else {
        Err(VerificationProtocolError::Transport(anyhow!(
            "invalid command"
        )))
    }
}

async fn read_request(
    peripheral: &TrackingBlePeripheral,
    info: &DeviceInfo,
    service_uuid: Uuid,
) -> Result<SessionEstablishment, VerificationProtocolError> {
    let mut result = vec![];

    loop {
        let data = peripheral
            .get_characteristic_writes(
                info.address.clone(),
                service_uuid.to_string(),
                CLIENT_2_SERVER.into(),
            )
            .await
            .context("failed to read request")
            .map_err(VerificationProtocolError::Transport)?;

        for msg in data {
            let chunk: Chunk = msg
                .try_into()
                .map_err(VerificationProtocolError::Transport)?;
            match chunk {
                Chunk::Next(payload) => result.extend(payload),
                Chunk::Last(payload) => {
                    result.extend(payload);

                    return ciborium::from_reader(result.as_slice())
                        .context("deserialization error")
                        .map_err(VerificationProtocolError::Other);
                }
            }
        }
    }
}

pub(crate) async fn notify_end(
    peripheral: &TrackingBlePeripheral,
    device_info: Option<&DeviceInfo>,
    service_uuid: Uuid,
) {
    if let Some(device_info) = device_info {
        let result = peripheral
            .notify_characteristic_data(
                device_info.address.clone(),
                service_uuid.to_string(),
                STATE.into(),
                &[Command::End as _],
            )
            .await;
        if let Err(err) = result {
            tracing::warn!("Failed to notify characteristic data: {err}");
        }
    }
}

pub(crate) async fn set_proof_error(
    proof_repository: &dyn ProofRepository,
    proof_id: &ProofId,
    error_metadata: HistoryErrorMetadata,
) {
    if let Err(err) = proof_repository
        .update_proof(
            proof_id,
            UpdateProofRequest {
                state: Some(ProofStateEnum::Error),
                ..Default::default()
            },
            Some(error_metadata),
        )
        .await
    {
        tracing::warn!("failed to set proof to error: {err}");
    }
}

fn get_characteristic_options() -> Vec<CreateCharacteristicOptions> {
    vec![
        CreateCharacteristicOptions {
            uuid: STATE.into(),
            permissions: vec![
                CharacteristicPermissions::Read,
                CharacteristicPermissions::Write,
            ],
            properties: vec![
                CharacteristicProperties::Notify,
                CharacteristicProperties::WriteWithoutResponse,
            ],
            initial_value: None,
        },
        CreateCharacteristicOptions {
            uuid: CLIENT_2_SERVER.into(),
            permissions: vec![CharacteristicPermissions::Write],
            properties: vec![CharacteristicProperties::WriteWithoutResponse],
            initial_value: None,
        },
        CreateCharacteristicOptions {
            uuid: SERVER_2_CLIENT.into(),
            permissions: vec![CharacteristicPermissions::Read],
            properties: vec![CharacteristicProperties::Notify],
            initial_value: None,
        },
    ]
}
