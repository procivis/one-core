use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Context};
use one_providers::common_models::proof::OpenProof;
use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, ProofId};
use time::OffsetDateTime;
use tokio::sync::oneshot;
use uuid::Uuid;

use super::ble::{CLIENT_2_SERVER, SERVER_2_CLIENT, STATE};
use super::common::{
    create_session_transcript_bytes, split_into_chunks, to_cbor, Chunk, DeviceRequest, EDeviceKey,
    KeyAgreement, SkDevice, SkReader,
};
use super::session::{Command, SessionData, SessionEstablishment, StatusCode};
use crate::model::interaction::Interaction;
use crate::model::proof::{ProofState, ProofStateEnum};
use crate::provider::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicPermissions, CharacteristicProperties, ConnectionEvent,
    CreateCharacteristicOptions, DeviceAddress, DeviceInfo, ServiceDescription,
};
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{Bstr, DeviceResponse};
use crate::provider::exchange_protocol::{deserialize_interaction_data, ExchangeProtocolError};
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ServiceError;
use crate::util::ble_resource::{BleWaiter, OnConflict, ScheduleResult};

pub(crate) static ISO_MDL_HOLDER_FLOW: LazyLock<Uuid> = LazyLock::new(Uuid::new_v4);

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
            *ISO_MDL_HOLDER_FLOW,
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
            |_, peripheral| async move {
                let _ = peripheral.stop_server().await;
            },
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
    device_engagement_bytes: Vec<u8>,
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
                let info = wait_for_device(&*peripheral, interaction_data.service_uuid).await;

                if info.is_err() {
                    let _ = peripheral.stop_server().await;
                }

                let info = info?;

                let _ = tx.send(info.clone());

                let result = async {
                    let session_establishment =
                        read_request(&*peripheral, &info, interaction_data.service_uuid).await?;

                    let transcript = create_session_transcript_bytes(
                        device_engagement_bytes,
                        session_establishment.e_reader_key.to_owned(),
                    )?;

                    let (sk_device, sk_reader) = key_pair
                        .derive_session_keys(
                            session_establishment.e_reader_key.into_inner(),
                            &transcript,
                        )
                        .context("failed to derive key")
                        .map_err(ExchangeProtocolError::Other)?;

                    let device_request_bytes = sk_reader
                        .decrypt(&session_establishment.data.0)
                        .map_err(ExchangeProtocolError::Other)?;

                    let device_request: DeviceRequest =
                        ciborium::from_reader(device_request_bytes.as_slice())
                            .context("device request deserialization error")
                            .map_err(ExchangeProtocolError::Other)?;

                    if device_request.version != "1.0" {
                        return Err(ExchangeProtocolError::Other(anyhow!(
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
                            }),
                            ..interaction_data
                        })
                        .context("interaction serialization error")
                        .map_err(ExchangeProtocolError::Other)?,
                    );

                    interaction_repository
                        .update_interaction(interaction)
                        .await
                        .context("failed to save interaction")
                        .map_err(ExchangeProtocolError::Other)?;

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
                        .context("failed to update proof state")
                        .map_err(ExchangeProtocolError::Other)?;

                    Ok::<_, ExchangeProtocolError>(())
                }
                .await;

                if result.is_err() {
                    set_proof_error(&*proof_repository, &proof_id).await;
                    abort(&*peripheral, Some(&info), interaction_data.service_uuid).await;
                }

                result
            },
            move |_, peripheral| async move {
                set_proof_error(&*proof_repository_clone, &proof_id).await;
                abort(
                    &*peripheral,
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
    proof: &OpenProof,
) -> Result<(), ExchangeProtocolError> {
    let interaction_data: MdocBleHolderInteractionData = deserialize_interaction_data(
        proof
            .interaction
            .as_ref()
            .and_then(|interaction| interaction.data.as_ref()),
    )?;

    let interaction_session_data =
        interaction_data
            .session
            .ok_or(ExchangeProtocolError::Failed(
                "interaction_session_data missing".to_string(),
            ))?;

    let device_response_bytes = to_cbor(&device_response)?;

    let encrypted_device_response = interaction_session_data
        .sk_device
        .encrypt(&device_response_bytes)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let session_data = SessionData {
        data: Some(Bstr(encrypted_device_response)),
        status: Some(StatusCode::SessionTermination),
    };
    let session_data_bytes = to_cbor(&session_data)?;

    let chunks = split_into_chunks(session_data_bytes, interaction_session_data.mtu as _)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

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
                            ExchangeProtocolError::Failed(format!("Unable to send response: {e}"))
                        })?;
                }

                // End command signal not necessary, since we signal SessionTermination via SessionData status

                // TODO: probably we should somehow wait for device disconnection here (but this would mean blocking UI)

                peripheral.stop_server().await.map_err(|e| {
                    ExchangeProtocolError::Failed(format!("Unable to stop server: {e}"))
                })?;

                Ok::<_, ExchangeProtocolError>(())
            },
            move |_, peripheral| async move {
                let _ = peripheral.stop_server().await;
            },
            false,
        )
        .await
        .value_or(ExchangeProtocolError::Failed("BLE was interrupted".into()))
        .await?;

    result.ok_or(ExchangeProtocolError::Failed("BLE flow was aborted".into()))??;

    Ok(())
}

async fn wait_for_device(
    peripheral: &dyn BlePeripheral,
    service_uuid: Uuid,
) -> Result<DeviceInfo, ExchangeProtocolError> {
    let info = loop {
        if let Some(info) = peripheral
            .get_connection_change_events()
            .await
            .context("failed to get connection change events")
            .map_err(ExchangeProtocolError::Transport)?
            .into_iter()
            .filter_map(|info| match info {
                ConnectionEvent::Connected { device_info } => Some(device_info),
                ConnectionEvent::Disconnected { .. } => None,
            })
            .next()
        {
            break info;
        }
    };

    peripheral
        .stop_advertisement()
        .await
        .context("failed to stop advertisement")
        .map_err(ExchangeProtocolError::Transport)?;

    wait_for_start(peripheral, &info, service_uuid).await?;

    Ok(info)
}

async fn wait_for_start(
    peripheral: &dyn BlePeripheral,
    info: &DeviceInfo,
    service_uuid: Uuid,
) -> Result<(), ExchangeProtocolError> {
    let command: Command = peripheral
        .get_characteristic_writes(
            info.address.clone(),
            service_uuid.to_string(),
            STATE.to_string(),
        )
        .await
        .context("failed to read client state")
        .map_err(ExchangeProtocolError::Transport)?
        .concat()
        .try_into()
        .map_err(ExchangeProtocolError::Transport)?;

    if command == Command::Start {
        Ok(())
    } else {
        Err(ExchangeProtocolError::Transport(anyhow!("invalid command")))
    }
}

async fn read_request(
    peripheral: &dyn BlePeripheral,
    info: &DeviceInfo,
    service_uuid: Uuid,
) -> Result<SessionEstablishment, ExchangeProtocolError> {
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
            .map_err(ExchangeProtocolError::Transport)?;

        for msg in data {
            let chunk: Chunk = msg.try_into().map_err(ExchangeProtocolError::Transport)?;
            match chunk {
                Chunk::Next(payload) => result.extend(payload),
                Chunk::Last(payload) => {
                    result.extend(payload);

                    return ciborium::from_reader(result.as_slice())
                        .context("deserialization error")
                        .map_err(ExchangeProtocolError::Other);
                }
            }
        }
    }
}

pub(crate) async fn abort(
    peripheral: &dyn BlePeripheral,
    device_info: Option<&DeviceInfo>,
    service_uuid: Uuid,
) {
    if let Some(device_info) = device_info {
        let _ = peripheral
            .notify_characteristic_data(
                device_info.address.clone(),
                service_uuid.to_string(),
                STATE.into(),
                &[Command::End as _],
            )
            .await;
    }
    let _ = peripheral.stop_server().await;
}

pub async fn set_proof_error(proof_repository: &dyn ProofRepository, proof_id: &ProofId) {
    let now = OffsetDateTime::now_utc();
    let _ = proof_repository
        .set_proof_state(
            proof_id,
            ProofState {
                created_date: now,
                last_modified: now,
                state: ProofStateEnum::Error,
            },
        )
        .await;
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
