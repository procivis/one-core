use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use shared_types::ProofId;
use time::OffsetDateTime;
use tokio::sync::oneshot;
use uuid::Uuid;

use super::ble::{CLIENT_2_SERVER, ISO_MDL_FLOW, SERVER_2_CLIENT, STATE};
use super::common::{
    create_session_transcript_bytes, split_into_chunks, to_cbor, Chunk, DeviceRequest, DocRequest,
    EReaderKey, ItemsRequest, KeyAgreement, SkDevice,
};
use super::device_engagement::{BleOptions, DeviceEngagement};
use super::session::{Command, SessionData, SessionEstablishment, StatusCode};
use crate::common_mapper::{encode_cbor_base64, NESTED_CLAIM_MARKER};
use crate::config::core_config::{self, DatatypeType};
use crate::model::proof::{Proof, ProofState, ProofStateEnum, UpdateProofRequest};
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::provider::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicWriteType, DeviceAddress, PeripheralDiscoveryData,
};
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    Bstr, DeviceResponse, EmbeddedCbor, SessionTranscript,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ServiceError;
use crate::util::ble_resource::{BleWaiter, OnConflict};

#[derive(Debug, Clone)]
pub(crate) struct VerifierSession {
    pub reader_key: EmbeddedCbor<EReaderKey>,
    pub session_transcript: SessionTranscript,
    pub device_request_encrypted: Vec<u8>,
    pub sk_device: SkDevice,
}

pub(crate) fn setup_verifier_session(
    device_engagement: EmbeddedCbor<DeviceEngagement>,
    schema: &ProofSchema,
    config: &core_config::CoreConfig,
) -> Result<VerifierSession, ExchangeProtocolError> {
    let key_pair = KeyAgreement::<EReaderKey>::new();

    let reader_key = EmbeddedCbor::new(key_pair.reader_key().clone())
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let session_transcript_bytes =
        create_session_transcript_bytes(device_engagement.to_owned(), reader_key.to_owned())?;

    let (sk_device, sk_reader) = key_pair
        .derive_session_keys(
            device_engagement
                .into_inner()
                .security
                .key_bytes
                .into_inner(),
            session_transcript_bytes.bytes(),
        )
        .context("failed to derive key")
        .map_err(ExchangeProtocolError::Other)?;

    let device_request = DeviceRequest {
        version: "1.0".into(),
        doc_requests: schema
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
        session_transcript: session_transcript_bytes.into_inner(),
        device_request_encrypted,
        sk_device,
    })
}

/// Main background task on mDL verifier
/// All from initializing connection to handling response
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_client(
    ble: &BleWaiter,
    ble_options: BleOptions,
    verifier_session: VerifierSession,
    proof: Proof,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    proof_repository: Arc<dyn ProofRepository>,
) -> Result<(), ServiceError> {
    let peripheral_server_uuid = ble_options.peripheral_server_uuid.to_owned();
    let proof_id = proof.id.to_owned();
    let proof_repository_clone = proof_repository.clone();

    let (sender, receiver) = oneshot::channel();

    ble.schedule(
        *ISO_MDL_FLOW,
        move |_, central, _| async move {
            if let Err(_error) = verifier_flow(
                ble_options,
                verifier_session,
                &proof,
                &*central,
                sender,
                credential_formatter_provider.clone(),
                did_method_provider.clone(),
                key_algorithm_provider.clone(),
                credential_repository.clone(),
                did_repository.clone(),
                proof_repository.clone(),
            )
            .await
            {
                let _ = proof_repository
                    .update_proof(update_proof_request(proof.id, ProofStateEnum::Error))
                    .await;
                // TODO: log error?
            }
        },
        move |central, _| async move {
            if let Ok(true) = central.is_scanning().await {
                let _ = central.stop_scan().await;
            }
            {
                if let Ok(device_info) = receiver.await {
                    send_end_and_disconnect(&device_info, &peripheral_server_uuid, &*central).await;
                }
            }

            let _ = proof_repository_clone
                .update_proof(update_proof_request(proof_id, ProofStateEnum::Error))
                .await;
        },
        OnConflict::ReplaceIfSameFlow,
        false,
    )
    .await;

    Ok(())
}

/// This function does whole flow from verifier's side (connecting, sending request, receiving
/// and parsing response)
///
/// It's split into smaller functions to simplify error handling - depending on place of failure
/// we may need to send End command, disconnect BLE central and set proof state to error
#[allow(clippy::too_many_arguments)]
async fn verifier_flow(
    ble_options: BleOptions,
    verifier_session: VerifierSession,
    proof: &Proof,
    central: &dyn BleCentral,
    sender: oneshot::Sender<PeripheralDiscoveryData>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    proof_repository: Arc<dyn ProofRepository>,
) -> Result<(), anyhow::Error> {
    let (device, mtu_size) =
        connect_to_server(central, ble_options.peripheral_server_uuid.to_string()).await?;

    let _ = sender.send(device.to_owned());

    let peripheral_server_uuid = ble_options.peripheral_server_uuid;

    let result = process_proof(
        ble_options,
        verifier_session,
        proof,
        central,
        &device,
        mtu_size,
        credential_formatter_provider,
        did_method_provider,
        key_algorithm_provider,
        credential_repository,
        did_repository,
        proof_repository,
    )
    .await;
    if let Err(_error) = &result {
        send_end_and_disconnect(&device, &peripheral_server_uuid, central).await;
    }

    result
}

#[allow(clippy::too_many_arguments)]
async fn process_proof(
    ble_options: BleOptions,
    verifier_session: VerifierSession,
    proof: &Proof,
    central: &dyn BleCentral,
    device: &PeripheralDiscoveryData,
    mtu_size: usize,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    proof_repository: Arc<dyn ProofRepository>,
) -> Result<(), anyhow::Error> {
    send_session_establishment(
        central,
        device,
        ble_options.peripheral_server_uuid.to_string(),
        mtu_size,
        verifier_session.reader_key,
        verifier_session.device_request_encrypted,
    )
    .await?;

    proof_repository
        .update_proof(update_proof_request(proof.id, ProofStateEnum::Requested))
        .await?;

    let session_data = read_response(
        central,
        device,
        ble_options.peripheral_server_uuid.to_string(),
    )
    .await?;

    let received_status_termination = session_data
        .status
        .is_some_and(|status| status == StatusCode::SessionTermination);
    if !received_status_termination {
        let _ = send_end(
            device.device_address.to_owned(),
            &ble_options.peripheral_server_uuid,
            central,
        )
        .await;
    }
    let _ = central.disconnect(device.device_address.to_owned()).await;

    let decrypted = verifier_session
        .sk_device
        .decrypt(&session_data.data.context("data is missing")?.0)?;
    let device_response: DeviceResponse = ciborium::from_reader(&decrypted[..])?;

    let mut new_state = match (
        device_response
            .documents
            .as_ref()
            .is_some_and(|documents| !documents.is_empty()),
        device_response
            .document_errors
            .as_ref()
            .is_some_and(|errors| !errors.is_empty()),
    ) {
        (true, false) => ProofStateEnum::Accepted,
        (false, true) => ProofStateEnum::Rejected,
        (_, _) => ProofStateEnum::Error,
    };

    if new_state == ProofStateEnum::Accepted {
        if let Err(_error) = fill_proof_claims_and_credentials(
            device_response,
            proof,
            verifier_session.session_transcript,
            credential_formatter_provider,
            did_method_provider.clone(),
            key_algorithm_provider.clone(),
            credential_repository,
            did_repository,
            proof_repository.clone(),
        )
        .await
        {
            // todo: log error?
            new_state = ProofStateEnum::Error;
        }
    }

    proof_repository
        .update_proof(update_proof_request(proof.id, new_state))
        .await?;

    Ok::<_, anyhow::Error>(())
}

async fn send_end(
    device_address: DeviceAddress,
    peripheral_server_uuid: &Uuid,
    central: &dyn BleCentral,
) -> Result<(), anyhow::Error> {
    central
        .write_data(
            device_address,
            peripheral_server_uuid.to_string(),
            STATE.into(),
            &[Command::End as _],
            CharacteristicWriteType::WithoutResponse,
        )
        .await
        .context("send end")
}

async fn send_end_and_disconnect(
    device_info: &PeripheralDiscoveryData,
    peripheral_server_uuid: &Uuid,
    central: &dyn BleCentral,
) {
    let _ = send_end(
        device_info.device_address.clone(),
        peripheral_server_uuid,
        central,
    )
    .await;
    let _ = central.disconnect(device_info.device_address.clone()).await;
}

#[allow(clippy::too_many_arguments)]
async fn fill_proof_claims_and_credentials(
    device_response: DeviceResponse,
    proof: &Proof,
    session_transcript: SessionTranscript,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    proof_repository: Arc<dyn ProofRepository>,
) -> Result<(), anyhow::Error> {
    let proof_schema = proof.schema.as_ref().ok_or(ServiceError::MappingError(
        "proof_schema is None".to_string(),
    ))?;

    let encoded = encode_cbor_base64(&device_response)?;

    let (holder_did, proved_claims) = super::verify_proof::validate_proof(
        proof_schema,
        &encoded,
        session_transcript,
        &*credential_formatter_provider,
        key_algorithm_provider,
        did_method_provider,
    )
    .await?;

    super::verify_proof::accept_proof(
        proof.clone(),
        proved_claims,
        holder_did,
        &*did_repository,
        &*credential_repository,
        &*proof_repository,
    )
    .await?;

    // todo: history log accepted

    Ok(())
}

fn update_proof_request(id: ProofId, new_state: ProofStateEnum) -> UpdateProofRequest {
    let now = OffsetDateTime::now_utc();
    UpdateProofRequest {
        id,
        holder_did_id: None,
        verifier_did_id: None,
        state: Some(ProofState {
            created_date: now,
            last_modified: now,
            state: new_state,
        }),
        interaction: None,
        redirect_uri: None,
    }
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
    e_reader_key: EmbeddedCbor<EReaderKey>,
    device_request_encrypted: Vec<u8>,
) -> anyhow::Result<()> {
    let session_establishment = SessionEstablishment {
        e_reader_key,
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
        items_request: EmbeddedCbor::new(ItemsRequest {
            doc_type: credential_schema.schema_id,
            name_spaces,
        })?,
    })
}
