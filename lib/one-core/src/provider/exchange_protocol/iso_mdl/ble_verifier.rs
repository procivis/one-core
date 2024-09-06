use std::collections::{HashMap, HashSet};

use anyhow::Context;
use one_providers::exchange_protocol::openid4vc::ExchangeProtocolError;

use super::ble::{CLIENT_2_SERVER, ISO_MDL_FLOW, SERVER_2_CLIENT, STATE};
use super::common::{
    create_session_transcript_bytes, split_into_chunks, to_cbor, Chunk, DeviceRequest, DocRequest,
    EReaderKey, ItemsRequest, KeyAgreement, SkDevice,
};
use super::device_engagement::{BleOptions, DeviceEngagement};
use super::session::{Command, SessionData, SessionEstablishment};
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::{self, DatatypeType};
use crate::model::proof::Proof;
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::provider::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicWriteType, PeripheralDiscoveryData,
};
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    Bstr, DeviceResponse, EmbeddedCbor,
};
use crate::service::error::ServiceError;
use crate::util::ble_resource::{BleWaiter, OnConflict};

#[derive(Debug, Clone)]
pub(crate) struct VerifierSession {
    pub reader_key: EReaderKey,
    #[allow(dead_code)]
    pub device_request: DeviceRequest,
    pub device_request_encrypted: Vec<u8>,
    pub sk_device: SkDevice,
}

pub(crate) fn setup_verifier_session(
    device_engagement: DeviceEngagement,
    schema: &ProofSchema,
    config: &core_config::CoreConfig,
) -> Result<VerifierSession, ExchangeProtocolError> {
    let key_pair = KeyAgreement::<EReaderKey>::new();
    let reader_key = key_pair.reader_key().clone();

    let transcript = create_session_transcript_bytes(&device_engagement, &reader_key)?;

    let (sk_device, sk_reader) = key_pair
        .derive_session_keys(device_engagement.security.key_bytes.0, &transcript)
        .context("failed to derive key")
        .map_err(ExchangeProtocolError::Other)?;

    let device_request = DeviceRequest {
        version: "1.0".into(),
        doc_request: schema
            .input_schemas
            .as_ref()
            .context("missing input_schemas")
            .map_err(ExchangeProtocolError::Other)?
            .iter()
            .map(|schema| proof_input_schema_to_doc_request(schema.to_owned(), config))
            .collect::<anyhow::Result<_>>()
            .map_err(ExchangeProtocolError::Other)?,
    };

    let device_request_bytes = to_cbor(&device_request)?;

    let device_request_encrypted = sk_reader
        .encrypt(&device_request_bytes)
        .map_err(ExchangeProtocolError::Other)?;

    Ok(VerifierSession {
        reader_key,
        device_request,
        device_request_encrypted,
        sk_device,
    })
}

/// Main background task on mDL verifier
/// All from initializing connection to handling response
pub(crate) async fn start_client(
    ble: &BleWaiter,
    ble_options: BleOptions,
    verifier_session: VerifierSession,
    _proof: Proof,
) -> Result<(), ServiceError> {
    ble.schedule(
        *ISO_MDL_FLOW,
        move |_, central, _| async move {
            // TODO: proper error-handling (any error results in proof state Error + (ev. signaling End command) + disconnect)

            let (device, mtu_size) =
                connect_to_server(&*central, ble_options.peripheral_server_uuid.to_string())
                    .await?;

            send_session_establishment(
                &*central,
                &device,
                ble_options.peripheral_server_uuid.to_string(),
                mtu_size,
                verifier_session.reader_key,
                verifier_session.device_request_encrypted,
            )
            .await?;

            // TODO:
            // set proof state - requested

            let session_data = read_response(
                &*central,
                &device,
                ble_options.peripheral_server_uuid.to_string(),
            )
            .await?;

            // TODO:
            // signal End command (if session termination not signaled via response)
            // disconnect

            let decrypted = verifier_session
                .sk_device
                .decrypt(&session_data.data.context("data is missing")?.0)?;
            let _device_response: DeviceResponse = ciborium::from_reader(&decrypted[..])?;

            // TODO:
            // validate DeviceResponse content
            // if valid, fill proof claims + credentials
            // set proof state

            Ok::<_, anyhow::Error>(())
        },
        move |_, _| async move {
            // TODO:
            // stop scanning if still scanning
            // if State Start signaled, signal End command
            // disconnect (if connected)
            // set proof state - Error
        },
        OnConflict::ReplaceIfSameFlow,
        false,
    )
    .await;

    Ok(())
}

async fn connect_to_server(
    central: &dyn BleCentral,
    service_uuid: String,
) -> anyhow::Result<(PeripheralDiscoveryData, usize)> {
    central.start_scan(Some(vec![service_uuid.clone()])).await?;

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
            service_uuid.clone(),
            STATE.into(),
        )
        .await?;

    central
        .subscribe_to_characteristic_notifications(
            device.device_address.clone(),
            service_uuid.clone(),
            SERVER_2_CLIENT.into(),
        )
        .await?;

    central
        .write_data(
            device.device_address.clone(),
            service_uuid,
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
    service_uuid: String,
    mtu_size: usize,
    key: EReaderKey,
    device_request_encrypted: Vec<u8>,
) -> anyhow::Result<()> {
    let session_establishment = SessionEstablishment {
        e_reader_key: EmbeddedCbor(key),
        data: Bstr(device_request_encrypted),
    };

    let session_establishment_bytes = to_cbor(&session_establishment)?;

    for chunk in split_into_chunks(session_establishment_bytes, mtu_size)? {
        central
            .write_data(
                device.device_address.clone(),
                service_uuid.clone(),
                CLIENT_2_SERVER.into(),
                &chunk,
                CharacteristicWriteType::WithoutResponse,
            )
            .await?
    }

    Ok(())
}

async fn read_response(
    central: &dyn BleCentral,
    info: &PeripheralDiscoveryData,
    service_uuid: String,
) -> Result<SessionData, ExchangeProtocolError> {
    let mut result = vec![];

    loop {
        let data = central
            .get_notifications(
                info.device_address.clone(),
                service_uuid.clone(),
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

fn proof_input_schema_to_doc_request(
    input: ProofInputSchema,
    config: &core_config::CoreConfig,
) -> anyhow::Result<DocRequest> {
    let credential_schema = input
        .credential_schema
        .context("credential_schema is missing")?;

    let claim_schemas = credential_schema
        .claim_schemas
        .context("claim_schemas is missing")?;

    let object_datatypes = config
        .datatype
        .iter()
        .filter_map(|(key, field)| (field.r#type == DatatypeType::Object).then_some(key))
        .collect::<HashSet<_>>();

    let mut name_spaces = HashMap::new();

    // TODO: revisit proof-schema claims nesting representation
    for claim_schema in claim_schemas.iter().filter(|schema| {
        !object_datatypes.contains(&schema.schema.data_type.as_str())
            || schema.schema.key.contains(NESTED_CLAIM_MARKER)
    }) {
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
            doc_type: credential_schema.schema_id,
            name_spaces,
        }),
    })
}
