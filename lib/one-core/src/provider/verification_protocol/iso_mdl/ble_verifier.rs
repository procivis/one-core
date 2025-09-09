use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Error};
use shared_types::ProofId;
use time::OffsetDateTime;
use tokio::sync::oneshot;
use uuid::Uuid;

use super::ble::{CLIENT_2_SERVER, ISO_MDL_FLOW, SERVER_2_CLIENT, STATE};
use super::common::{
    Chunk, DeviceRequest, DocRequest, EReaderKey, ItemsRequest, KeyAgreement, SkDevice,
    create_session_transcript_bytes, split_into_chunks, to_cbor,
};
use super::device_engagement::{BleOptions, DeviceEngagement};
use super::session::{Command, SessionData, SessionEstablishment, StatusCode};
use crate::common_mapper::{NESTED_CLAIM_MARKER, encode_cbor_base64};
use crate::model::history::HistoryErrorMetadata;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::provider::bluetooth_low_energy::low_level::ble_central::{
    BleCentral, TrackingBleCentral,
};
use crate::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicWriteType, DeviceAddress, PeripheralDiscoveryData,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::mso_mdoc::model::DeviceResponse;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
    Handover, SessionTranscript,
};
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::error::ErrorCode::BR_0000;
use crate::service::error::ServiceError;
use crate::util::ble_resource::{BleWaiter, OnConflict, ScheduleResult};
use crate::util::mdoc::{Bstr, EmbeddedCbor};

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
    handover: Option<Handover>,
) -> Result<VerifierSession, VerificationProtocolError> {
    let key_pair = KeyAgreement::<EReaderKey>::new();

    let reader_key = EmbeddedCbor::new(key_pair.reader_key().clone())
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let session_transcript_bytes = create_session_transcript_bytes(
        device_engagement.to_owned(),
        reader_key.to_owned(),
        handover,
    )?;

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
        .map_err(VerificationProtocolError::Other)?;

    let device_request = DeviceRequest {
        version: "1.0".into(),
        doc_requests: schema
            .input_schemas
            .as_ref()
            .context("missing input_schemas")
            .map_err(VerificationProtocolError::Other)?
            .iter()
            .map(proof_input_schema_to_doc_request)
            .collect::<anyhow::Result<_>>()
            .map_err(VerificationProtocolError::Other)?,
    };

    let device_request_bytes = to_cbor(&device_request)?;

    let device_request_encrypted = sk_reader
        .encrypt(&device_request_bytes)
        .map_err(VerificationProtocolError::Other)?;

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
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    certificate_repository: Arc<dyn CertificateRepository>,
    key_repository: Arc<dyn KeyRepository>,
) -> Result<(), ServiceError> {
    let peripheral_server_uuid = ble_options.peripheral_server_uuid.to_owned();

    let (sender, receiver) = oneshot::channel();

    let schedule_result = ble
        .schedule(
            *ISO_MDL_FLOW,
            move |_, central, _| async move {
                let result = verifier_flow(
                    ble_options,
                    verifier_session,
                    &proof,
                    &central,
                    sender,
                    credential_formatter_provider.clone(),
                    presentation_formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    credential_repository.clone(),
                    did_repository.clone(),
                    identifier_repository.clone(),
                    proof_repository.clone(),
                    certificate_validator.clone(),
                    certificate_repository.clone(),
                    &*key_repository,
                )
                .await;

                if let Err(error) = &result {
                    {
                        let message = format!("mDL verifier failure: {error:#?}");
                        tracing::info!(message);
                        let error_metadata = HistoryErrorMetadata {
                            error_code: BR_0000,
                            message,
                        };
                        if let Err(err) =
                            set_proof_to_error(&*proof_repository, proof.id, error_metadata).await
                        {
                            tracing::warn!("failed to set proof to error: {err}");
                        }
                    }
                };

                result
            },
            move |central, _| async move {
                let message = "Cancelling mDL verifier flow".to_string();
                tracing::info!(message);
                if let Ok(device_info) = receiver.await {
                    send_end(
                        device_info.device_address.clone(),
                        &peripheral_server_uuid,
                        &central,
                    )
                    .await;
                }
            },
            OnConflict::ReplaceIfSameFlow,
            false,
        )
        .await;

    if matches!(schedule_result, ScheduleResult::Busy) {
        return Err(ServiceError::Other("BLE is busy".into()));
    }

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
    central: &TrackingBleCentral,
    sender: oneshot::Sender<PeripheralDiscoveryData>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    certificate_repository: Arc<dyn CertificateRepository>,
    key_repository: &dyn KeyRepository,
) -> Result<(), anyhow::Error> {
    let (device, mtu_size) =
        connect_to_server(central, ble_options.peripheral_server_uuid.to_string()).await?;

    if let Err(err) = sender.send(device.to_owned()) {
        tracing::warn!("failed to send device discovery data: {err:?}");
    }

    let peripheral_server_uuid = ble_options.peripheral_server_uuid;

    let result = process_proof(
        ble_options,
        verifier_session,
        proof,
        central,
        &device,
        mtu_size,
        credential_formatter_provider,
        presentation_formatter_provider,
        did_method_provider,
        key_algorithm_provider,
        credential_repository,
        did_repository,
        identifier_repository,
        proof_repository,
        certificate_validator,
        certificate_repository,
        key_repository,
    )
    .await;
    if let Err(_error) = &result {
        send_end(
            device.device_address.clone(),
            &peripheral_server_uuid,
            central,
        )
        .await;
    }

    result
}

#[allow(clippy::too_many_arguments)]
async fn process_proof(
    ble_options: BleOptions,
    verifier_session: VerifierSession,
    proof: &Proof,
    central: &TrackingBleCentral,
    device: &PeripheralDiscoveryData,
    mtu_size: usize,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    certificate_repository: Arc<dyn CertificateRepository>,
    key_repository: &dyn KeyRepository,
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
        .update_proof(
            &proof.id,
            UpdateProofRequest {
                state: Some(ProofStateEnum::Requested),
                requested_date: Some(Some(OffsetDateTime::now_utc())),
                ..Default::default()
            },
            None,
        )
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
        send_end(
            device.device_address.to_owned(),
            &ble_options.peripheral_server_uuid,
            central,
        )
        .await;
    }
    if let Err(err) = central.disconnect(device.device_address.to_owned()).await {
        tracing::warn!("failed to disconnect BLE central: {err}");
    }

    let decrypted = verifier_session
        .sk_device
        .decrypt(&session_data.data.context("data is missing")?.0)?;
    let device_response: DeviceResponse = ciborium::from_reader(&decrypted[..])?;

    let empty_documents = device_response
        .documents
        .as_ref()
        .is_some_and(|documents| documents.is_empty());
    let has_errors = device_response
        .document_errors
        .as_ref()
        .is_some_and(|errors| !errors.is_empty());

    if !empty_documents && has_errors {
        let error_metadata = HistoryErrorMetadata {
            error_code: BR_0000,
            message: format!(
                "Response received with documents and document errors: {device_response:?}"
            ),
        };
        set_proof_to_error(&*proof_repository, proof.id, error_metadata).await?;
        return Ok(());
    }

    if empty_documents {
        if has_errors {
            proof_repository
                .update_proof(
                    &proof.id,
                    UpdateProofRequest {
                        state: Some(ProofStateEnum::Rejected),
                        ..Default::default()
                    },
                    None,
                )
                .await?;
        } else {
            let error_metadata = HistoryErrorMetadata {
                error_code: BR_0000,
                message: "Response documents are empty but no errors are provided".to_string(),
            };
            set_proof_to_error(&*proof_repository, proof.id, error_metadata).await?;
        }

        return Ok(());
    }

    if let Err(error) = fill_proof_claims_and_credentials(
        device_response,
        proof,
        verifier_session.session_transcript,
        &*credential_formatter_provider,
        &*presentation_formatter_provider,
        did_method_provider,
        key_algorithm_provider,
        credential_repository,
        did_repository,
        identifier_repository,
        &*proof_repository,
        certificate_validator,
        certificate_repository,
        key_repository,
    )
    .await
    {
        let message = format!("mDL proof parsing failure: {error:#?}");
        tracing::info!(message);
        let error_metadata = HistoryErrorMetadata {
            error_code: BR_0000,
            message,
        };
        set_proof_to_error(&*proof_repository, proof.id, error_metadata).await?;
    }

    Ok(())
}

async fn set_proof_to_error(
    proof_repository: &dyn ProofRepository,
    proof_id: ProofId,
    error_metadata: HistoryErrorMetadata,
) -> Result<(), Error> {
    proof_repository
        .update_proof(
            &proof_id,
            UpdateProofRequest {
                state: Some(ProofStateEnum::Error),
                ..Default::default()
            },
            Some(error_metadata),
        )
        .await?;
    Ok(())
}

async fn send_end(
    device_address: DeviceAddress,
    peripheral_server_uuid: &Uuid,
    central: &TrackingBleCentral,
) {
    if let Err(err) = central
        .write_data(
            device_address,
            peripheral_server_uuid.to_string(),
            STATE.into(),
            &[Command::End as _],
            CharacteristicWriteType::WithoutResponse,
        )
        .await
    {
        tracing::warn!("failed to write end: {err}");
    }
}

#[allow(clippy::too_many_arguments)]
async fn fill_proof_claims_and_credentials(
    device_response: DeviceResponse,
    proof: &Proof,
    session_transcript: SessionTranscript,
    credential_formatter_provider: &dyn CredentialFormatterProvider,
    presentation_formatter_provider: &dyn PresentationFormatterProvider,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    proof_repository: &dyn ProofRepository,
    certificate_validator: Arc<dyn CertificateValidator>,
    certificate_repository: Arc<dyn CertificateRepository>,
    key_repository: &dyn KeyRepository,
) -> Result<(), anyhow::Error> {
    let proof_schema = proof.schema.as_ref().ok_or(ServiceError::MappingError(
        "proof_schema is None".to_string(),
    ))?;

    let encoded = encode_cbor_base64(&device_response)?;

    let (holder_identifier, proved_claims) = super::verify_proof::validate_proof(
        proof_schema,
        &encoded,
        session_transcript,
        credential_formatter_provider,
        presentation_formatter_provider,
        &key_algorithm_provider,
        did_method_provider.clone(),
        certificate_validator.clone(),
    )
    .await?;

    super::verify_proof::accept_proof(
        proof.clone(),
        proved_claims,
        holder_identifier,
        &*did_repository,
        &*identifier_repository,
        &*did_method_provider,
        &*credential_repository,
        proof_repository,
        &*certificate_validator,
        &*certificate_repository,
        key_repository,
        &*key_algorithm_provider,
    )
    .await?;

    // todo: history log accepted

    Ok(())
}

async fn connect_to_server(
    central: &TrackingBleCentral,
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
    central: &TrackingBleCentral,
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
    central: &TrackingBleCentral,
    info: &PeripheralDiscoveryData,
    service_uuid: String,
) -> Result<SessionData, VerificationProtocolError> {
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

fn proof_input_schema_to_doc_request(input: &ProofInputSchema) -> anyhow::Result<DocRequest> {
    let proof_claim_schemas = input
        .claim_schemas
        .as_ref()
        .context("claim_schemas is missing")?;

    let credential_schema = input
        .credential_schema
        .as_ref()
        .context("credential_schema is missing")?;

    let mut name_spaces = HashMap::new();
    for proof_claim_schema in proof_claim_schemas {
        let key = &proof_claim_schema.schema.key;
        let claim_keys = if key.contains(NESTED_CLAIM_MARKER) {
            // defining an element
            vec![key]
        } else {
            // defining a whole namespace
            credential_schema
                .claim_schemas
                .as_ref()
                .context("claim_schemas missing in credential_schema")?
                .iter()
                .map(|claim_schema| &claim_schema.schema.key)
                .filter(|k| k.starts_with(&format!("{key}{NESTED_CLAIM_MARKER}")))
                .collect()
        };

        for claim_key in claim_keys {
            let path: Vec<_> = claim_key.splitn(3, NESTED_CLAIM_MARKER).collect();

            let namespace = path[0].to_string();
            let element_identifier = path[1].to_string();
            name_spaces
                .entry(namespace)
                .or_insert_with(HashMap::new)
                .insert(element_identifier, true);
        }
    }

    Ok(DocRequest {
        items_request: EmbeddedCbor::new(ItemsRequest {
            doc_type: credential_schema.schema_id.to_owned(),
            name_spaces,
        })?,
    })
}
