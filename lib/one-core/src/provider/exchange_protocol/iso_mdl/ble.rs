use std::sync::Arc;

use anyhow::{anyhow, Context};
use one_providers::exchange_protocol::openid4vc::ExchangeProtocolError;
use serde::de::DeserializeOwned;
use shared_types::ProofId;
use time::OffsetDateTime;
use tokio::sync::oneshot;
use uuid::Uuid;

use super::common::{
    create_session_transcript_bytes, Chunk, DeviceRequest, EDeviceKey, KeyAgreement, ServerInfo,
};
use super::device_engagement::DeviceEngagement;
use super::session::{Command, SessionEstablishment};
use crate::model::interaction::Interaction;
use crate::model::proof::{ProofState, ProofStateEnum};
use crate::provider::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicPermissions, CharacteristicProperties, ConnectionEvent,
    CreateCharacteristicOptions, DeviceInfo, ServiceDescription,
};
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ServiceError;
use crate::service::proof::dto::MdocBleInteractionData;
use crate::util::ble_resource::{BleWaiter, OnConflict, ScheduleResult};

const STATE: &str = "00000001-A123-48CE-896B-4C76973373E6";
const CLIENT_2_SERVER: &str = "00000002-A123-48CE-896B-4C76973373E6";
const SERVER_2_CLIENT: &str = "00000003-A123-48CE-896B-4C76973373E6";

pub async fn start_server(ble: &BleWaiter) -> Result<ServerInfo, ServiceError> {
    let service_id = Uuid::new_v4();

    let (task_id, result) = ble
        .schedule(
            service_id,
            |_, _, peripheral| async move {
                peripheral
                    .start_advertisement(
                        None,
                        vec![ServiceDescription {
                            uuid: service_id.to_string(),
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

    let mac = result
        .ok_or(ServiceError::Other("flow was aborted".into()))?
        .map_err(|err| ServiceError::Other(format!("ble error: {err}")))?;

    Ok(ServerInfo {
        task_id,
        mac,
        service_id,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn connect(
    ble: &BleWaiter,
    old_task_id: Uuid,
    service_id: Uuid,
    device_engagement: DeviceEngagement,
    key_pair: KeyAgreement<EDeviceKey>,
    interaction_repository: Arc<dyn InteractionRepository>,
    mut interaction: Interaction,
    proof_repository: Arc<dyn ProofRepository>,
    proof_id: ProofId,
) -> Result<(), ServiceError> {
    let (tx, rx) = oneshot::channel();
    let proof_repository_clone = proof_repository.clone();

    let ScheduleResult::Scheduled { .. } = ble
        .schedule_continuation(
            old_task_id,
            |task_id, _, peripheral| async move {
                let info = wait_for_device(&*peripheral, service_id).await;

                if info.is_err() {
                    let _ = peripheral.stop_server().await;
                }

                let info = info?;

                let _ = tx.send(info.clone());

                let result = async {
                    let data: SessionEstablishment =
                        read_request(&*peripheral, &info, service_id).await?;

                    let transcript =
                        create_session_transcript_bytes(&device_engagement, &data.e_reader_key.0)?;

                    let (sk_device, sk_reader) = key_pair
                        .derive_session_keys(data.e_reader_key.0, &transcript)
                        .context("failed to derive key")
                        .map_err(ExchangeProtocolError::Other)?;

                    let decoded = sk_reader
                        .decrypt(&data.data.0)
                        .map_err(ExchangeProtocolError::Other)?;

                    let device_request: DeviceRequest = ciborium::from_reader(decoded.as_slice())
                        .context("device request deserialization error")
                        .map_err(ExchangeProtocolError::Other)?;

                    if device_request.version != "1.0" {
                        return Err(ExchangeProtocolError::Other(anyhow!(
                            "unsupported request version"
                        )));
                    }

                    interaction.data = Some(
                        serde_json::to_vec(&MdocBleInteractionData {
                            service_id,
                            task_id,
                            sk_device,
                            sk_reader,
                            device_request,
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
                    abort_and_set_proof_error(
                        &*peripheral,
                        &*proof_repository,
                        &proof_id,
                        Some(&info),
                        service_id,
                    )
                    .await;
                }

                result
            },
            move |_, peripheral| async move {
                abort_and_set_proof_error(
                    &*peripheral,
                    &*proof_repository_clone,
                    &proof_id,
                    rx.await.ok().as_ref(),
                    service_id,
                )
                .await;
            },
            true,
        )
        .await
    else {
        return Err(ServiceError::Other("ble flow was interupted".into()));
    };

    Ok(())
}

async fn wait_for_device(
    peripheral: &dyn BlePeripheral,
    service_id: Uuid,
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

    wait_for_start(peripheral, &info, service_id).await?;

    Ok(info)
}

async fn wait_for_start(
    peripheral: &dyn BlePeripheral,
    info: &DeviceInfo,
    service_id: Uuid,
) -> Result<(), ExchangeProtocolError> {
    let command: Command = peripheral
        .get_characteristic_writes(
            info.address.clone(),
            service_id.to_string(),
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

async fn read_request<T>(
    peripheral: &dyn BlePeripheral,
    info: &DeviceInfo,
    service_id: Uuid,
) -> Result<T, ExchangeProtocolError>
where
    T: DeserializeOwned,
{
    let mut result = vec![];

    'outer: loop {
        let data = peripheral
            .get_characteristic_writes(
                info.address.clone(),
                service_id.to_string(),
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

                    break 'outer ciborium::from_reader(result.as_slice())
                        .context("deserialization error")
                        .map_err(ExchangeProtocolError::Other);
                }
            }
        }
    }
}

pub async fn abort_and_set_proof_error(
    peripheral: &dyn BlePeripheral,
    proof_repository: &dyn ProofRepository,
    proof_id: &ProofId,
    device_info: Option<&DeviceInfo>,
    service_id: Uuid,
) {
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

    if let Some(device_info) = device_info {
        let _ = peripheral
            .notify_characteristic_data(
                device_info.address.clone(),
                service_id.to_string(),
                STATE.into(),
                &[Command::End as _],
            )
            .await;
    }
    let _ = peripheral.stop_server().await;
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
