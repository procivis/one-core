use std::collections::HashMap;
use std::iter;
use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Context};
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_providers::common_models::NESTED_CLAIM_MARKER;
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::did::provider::DidMethodProvider;
use one_providers::exchange_protocol::openid4vc::ExchangeProtocolError;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use one_providers::revocation::provider::RevocationMethodProvider;
use serde::de::DeserializeOwned;
use shared_types::{OrganisationId, ProofId};
use time::OffsetDateTime;
use tokio::sync::oneshot;
use uuid::Uuid;

use super::common::{
    create_session_transcript_bytes, to_cbor, Chunk, DeviceRequest, DocRequest, EDeviceKey,
    EReaderKey, ItemsRequest, KeyAgreement, ServerInfo,
};
use super::device_engagement::{BleOptions, DeviceEngagement};
use super::session::{Command, SessionData, SessionEstablishment};
use crate::model::interaction::Interaction;
use crate::model::proof::{Proof, ProofState, ProofStateEnum};
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::provider::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::provider::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicPermissions, CharacteristicProperties, CharacteristicWriteType, ConnectionEvent,
    CreateCharacteristicOptions, DeviceInfo, PeripheralDiscoveryData, ServiceDescription,
};
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{Bstr, EmbeddedCbor};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ServiceError;
use crate::service::proof::dto::MdocBleInteractionData;
use crate::service::ssi_verifier::utils::accept_proof;
use crate::service::ssi_verifier::validator::validate_proof;
use crate::util::ble_resource::{BleWaiter, OnConflict, ScheduleResult};

pub static ISO_MDL_FLOW: LazyLock<Uuid> = LazyLock::new(Uuid::new_v4);

const STATE: &str = "00000001-A123-48CE-896B-4C76973373E6";
const CLIENT_2_SERVER: &str = "00000002-A123-48CE-896B-4C76973373E6";
const SERVER_2_CLIENT: &str = "00000003-A123-48CE-896B-4C76973373E6";

pub async fn start_server(ble: &BleWaiter) -> Result<ServerInfo, ServiceError> {
    let service_id = Uuid::new_v4();

    let (task_id, result) = ble
        .schedule(
            *ISO_MDL_FLOW,
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
    organisation_id: OrganisationId,
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
                        read_request_peripheral(&*peripheral, &info, service_id).await?;

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
                            device_request: device_request.into(),
                            organisation_id,
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
        return Err(ServiceError::Other("ble flow was interrupted".into()));
    };

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn start_client(
    ble: &BleWaiter,
    ble_options: BleOptions,
    device_engagement: DeviceEngagement,
    schema: ProofSchema,
    proof: Proof,
    proof_repository: Arc<dyn ProofRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
) -> Result<(), ServiceError> {
    ble.schedule(
        *ISO_MDL_FLOW,
        move |_, central, _| async move {
            let (device, mtu_size) =
                connect_to_server(&*central, ble_options.peripheral_server_uuid.to_string())
                    .await?;

            let key_pair = KeyAgreement::<EReaderKey>::new();
            let reader_key = key_pair.reader_key().clone();

            let transcript = create_session_transcript_bytes(&device_engagement, &reader_key)?;

            let (sk_device, sk_reader) = key_pair
                .derive_session_keys(device_engagement.security.key_bytes.0, &transcript)
                .context("failed to derive key")
                .map_err(ExchangeProtocolError::Other)?;

            let device_request = to_cbor(&DeviceRequest {
                version: "1.0".into(),
                doc_request: schema
                    .input_schemas
                    .clone()
                    .context("missing input_schemas")?
                    .into_iter()
                    .map(schema_to_doc_request)
                    .collect::<anyhow::Result<_>>()?,
            })?;

            let device_request = sk_device.encrypt(&device_request)?;

            send_session_establishment(
                &*central,
                &device,
                ble_options.peripheral_server_uuid.to_string(),
                mtu_size,
                reader_key,
                device_request,
            )
            .await?;

            let session_data = read_request_central::<SessionData>(
                &*central,
                &device,
                ble_options.peripheral_server_uuid.to_string(),
            )
            .await?
            .data
            .context("data is missing")?
            .0;

            let decrypted = sk_reader.decrypt(&session_data)?;
            let presentation_content = Base64UrlSafeNoPadding::encode_to_string(decrypted)?;
            let holder_did = proof.holder_did.clone().context("holder did is missing")?;

            let proved_claims = validate_proof(
                &schema,
                &holder_did,
                &presentation_content,
                &*formatter_provider,
                key_algorithm_provider,
                did_method_provider,
                revocation_method_provider,
            )
            .await?;

            accept_proof(
                proof.clone(),
                proved_claims,
                holder_did,
                &*did_repository,
                &*credential_repository,
                &*proof_repository,
            )
            .await?;

            Ok::<_, anyhow::Error>(())
        },
        |_, _| async {},
        OnConflict::ReplaceIfSameFlow,
        false,
    )
    .await;

    Ok(())
}

async fn connect_to_server(
    central: &dyn BleCentral,
    server_id: String,
) -> anyhow::Result<(PeripheralDiscoveryData, usize)> {
    central.start_scan(Some(vec![server_id.clone()])).await?;

    let device = central
        .get_discovered_devices()
        .await?
        .pop()
        .context("no discovered devices")?;

    central.stop_scan().await?;

    let mtu_size = central.connect(device.device_address.clone()).await?;

    central
        .subscribe_to_characteristic_notifications(
            device.device_address.clone(),
            server_id.clone(),
            STATE.into(),
        )
        .await?;

    central
        .subscribe_to_characteristic_notifications(
            device.device_address.clone(),
            server_id.clone(),
            SERVER_2_CLIENT.into(),
        )
        .await?;

    central
        .write_data(
            device.device_address.clone(),
            server_id,
            STATE.into(),
            &[Command::Start as _],
            CharacteristicWriteType::WithoutResponse,
        )
        .await?;

    Ok((device, mtu_size as _))
}

async fn send_session_establishment(
    central: &dyn BleCentral,
    device: &PeripheralDiscoveryData,
    server_id: String,
    mtu_size: usize,
    key: EReaderKey,
    device_request: Vec<u8>,
) -> anyhow::Result<()> {
    let session_establishment = to_cbor(&SessionEstablishment {
        e_reader_key: EmbeddedCbor(key),
        data: Bstr(device_request),
    })?;

    let mut chunks = session_establishment.chunks(mtu_size - 3);

    let last = Chunk::Last(chunks.next_back().context("no chunks")?.to_vec());

    let chunks: Vec<Vec<u8>> = chunks
        .map(|slice| Chunk::Next(slice.to_vec()))
        .chain(iter::once(last))
        .map(Into::into)
        .collect();

    for chunk in chunks {
        central
            .write_data(
                device.device_address.clone(),
                server_id.clone(),
                CLIENT_2_SERVER.into(),
                &chunk,
                CharacteristicWriteType::WithoutResponse,
            )
            .await?
    }

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

async fn read_request_peripheral<T>(
    peripheral: &dyn BlePeripheral,
    info: &DeviceInfo,
    service_id: Uuid,
) -> Result<T, ExchangeProtocolError>
where
    T: DeserializeOwned,
{
    let mut result = vec![];

    loop {
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

                    return ciborium::from_reader(result.as_slice())
                        .context("deserialization error")
                        .map_err(ExchangeProtocolError::Other);
                }
            }
        }
    }
}

async fn read_request_central<T>(
    central: &dyn BleCentral,
    info: &PeripheralDiscoveryData,
    service_id: String,
) -> Result<T, ExchangeProtocolError>
where
    T: DeserializeOwned,
{
    let mut result = vec![];

    loop {
        let data = central
            .get_notifications(
                info.device_address.clone(),
                service_id.clone(),
                SERVER_2_CLIENT.into(),
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

fn schema_to_doc_request(input: ProofInputSchema) -> anyhow::Result<DocRequest> {
    let credential = input
        .credential_schema
        .context("credential_schema is missing")?;
    let claim_schemas = input.claim_schemas.context("claim_schemas is missing")?;

    let mut name_spaces = HashMap::new();

    for claim_schema in claim_schemas {
        let (namespace, element_identifier) = claim_schema
            .schema
            .key
            .split_once(NESTED_CLAIM_MARKER)
            .context("missing root object")?;

        let element_identifier: String = element_identifier
            .chars()
            .take_while(|c| *c != NESTED_CLAIM_MARKER)
            .collect();
        name_spaces
            .entry(namespace.to_string())
            .or_insert_with(HashMap::new)
            .insert(element_identifier, true);
    }

    Ok(DocRequest {
        items_request: EmbeddedCbor(ItemsRequest {
            doc_type: credential.schema_id,
            name_spaces,
        }),
    })
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
