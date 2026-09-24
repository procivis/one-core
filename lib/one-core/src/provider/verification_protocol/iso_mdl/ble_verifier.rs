use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Error};
use coset::iana::HeaderParameter;
use coset::{HeaderBuilder, ProtectedHeader};
use shared_types::ProofId;
use tokio::sync::oneshot;
use uuid::Uuid;

use super::ble::{CLIENT_2_SERVER, ISO_MDL_FLOW, SERVER_2_CLIENT, STATE};
use super::common::{
    Chunk, DeviceRequest, DocRequest, EReaderKey, ItemsRequest, KeyAgreement, SkDevice,
    create_session_transcript_bytes, split_into_chunks, to_cbor,
};
use super::device_engagement::{BleOptions, DeviceEngagement};
use super::session::{Command, SessionData, SessionEstablishment, StatusCode};
use crate::error::ContextWithErrorCode;
use crate::error::ErrorCode::BR_0000;
use crate::mapper::{NESTED_CLAIM_MARKER, encode_cbor_base64};
use crate::model::certificate::Certificate;
use crate::model::history::HistoryErrorMetadata;
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::proto::bluetooth_low_energy::ble_resource::{BleWaiter, OnConflict, ScheduleResult};
use crate::proto::bluetooth_low_energy::low_level::ble_central::{BleCentral, TrackingBleCentral};
use crate::proto::bluetooth_low_energy::low_level::dto::{
    CharacteristicWriteType, DeviceAddress, PeripheralDiscoveryData,
};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::cose::{CoseSign1, CoseSign1Builder};
use crate::proto::ecosystem_resolver::EcosystemResolver;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::provider::credential_formatter::mdoc_formatter::util::{
    Bstr, EmbeddedCbor, build_algorithm_header_value,
};
use crate::provider::credential_formatter::mdoc_formatter::{
    HeaderBuilderExt, build_x5chain_header_value,
};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::mso_mdoc::model::{
    DeviceResponse, ReaderAuthentication,
};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
    Handover, SessionTranscript,
};
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::proof_repository::ProofRepository;

#[derive(Debug, Clone)]
pub(crate) struct VerifierSession {
    pub reader_key: EmbeddedCbor<EReaderKey>,
    pub session_transcript: SessionTranscript,
    pub device_request_encrypted: Vec<u8>,
    pub sk_device: SkDevice,
}

pub(crate) struct IsoMdlVerifier {
    pub identifier: Identifier,
    pub key: Key,
    pub certificate: Certificate,
    pub auth_fn: AuthenticationFn,
}

pub(crate) async fn setup_verifier_session(
    device_engagement: EmbeddedCbor<DeviceEngagement>,
    schema: &ProofSchema,
    handover: Option<Handover>,
    verifier: Option<&IsoMdlVerifier>,
) -> Result<VerifierSession, VerificationProtocolError> {
    let key_pair =
        KeyAgreement::<EReaderKey>::generate().map_err(VerificationProtocolError::Other)?;

    let reader_key = EmbeddedCbor::new(key_pair.reader_key().clone())?;

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

    let mut doc_requests = vec![];
    let input_schemas = schema.input_schemas.as_ref().await?;
    for input_schema in &input_schemas {
        doc_requests.push(
            proof_input_schema_to_doc_request(
                input_schema,
                session_transcript_bytes.inner(),
                verifier,
            )
            .await?,
        );
    }

    let device_request = DeviceRequest {
        version: Default::default(),
        doc_requests,
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
#[expect(clippy::too_many_arguments)]
pub(crate) async fn start_client(
    ble: &BleWaiter,
    ble_options: BleOptions,
    verifier_session: VerifierSession,
    proof: Proof,
    interaction: Interaction,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    ecosystem_resolver: Arc<dyn EcosystemResolver>,
) -> Result<(), VerificationProtocolError> {
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
                    &interaction,
                    &central,
                    sender,
                    credential_formatter_provider.clone(),
                    presentation_formatter_provider.clone(),
                    did_method_provider.clone(),
                    key_algorithm_provider.clone(),
                    credential_repository.clone(),
                    proof_repository.clone(),
                    certificate_validator.clone(),
                    identifier_creator.clone(),
                    ecosystem_resolver.clone(),
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
        return Err(VerificationProtocolError::Failed("BLE is busy".into()));
    }

    Ok(())
}

/// This function does whole flow from verifier's side (connecting, sending request, receiving
/// and parsing response)
///
/// It's split into smaller functions to simplify error handling - depending on place of failure
/// we may need to send End command, disconnect BLE central and set proof state to error
#[expect(clippy::too_many_arguments)]
async fn verifier_flow(
    ble_options: BleOptions,
    verifier_session: VerifierSession,
    proof: &Proof,
    interaction: &Interaction,
    central: &TrackingBleCentral,
    sender: oneshot::Sender<PeripheralDiscoveryData>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    ecosystem_resolver: Arc<dyn EcosystemResolver>,
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
        interaction,
        central,
        &device,
        mtu_size,
        credential_formatter_provider,
        presentation_formatter_provider,
        did_method_provider,
        key_algorithm_provider,
        credential_repository,
        proof_repository,
        certificate_validator,
        identifier_creator,
        ecosystem_resolver,
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

#[expect(clippy::too_many_arguments)]
async fn process_proof(
    ble_options: BleOptions,
    verifier_session: VerifierSession,
    proof: &Proof,
    interaction: &Interaction,
    central: &TrackingBleCentral,
    device: &PeripheralDiscoveryData,
    mtu_size: usize,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    ecosystem_resolver: Arc<dyn EcosystemResolver>,
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
                requested_date: Some(Some(crate::clock::now_utc())),
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
        interaction,
        verifier_session.session_transcript,
        &*credential_formatter_provider,
        &*presentation_formatter_provider,
        did_method_provider,
        key_algorithm_provider,
        credential_repository,
        &*proof_repository,
        certificate_validator,
        identifier_creator,
        ecosystem_resolver,
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

#[expect(clippy::too_many_arguments)]
async fn fill_proof_claims_and_credentials(
    device_response: DeviceResponse,
    proof: &Proof,
    interaction: &Interaction,
    session_transcript: SessionTranscript,
    credential_formatter_provider: &dyn CredentialFormatterProvider,
    presentation_formatter_provider: &dyn PresentationFormatterProvider,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: &dyn ProofRepository,
    certificate_validator: Arc<dyn CertificateValidator>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    ecosystem_resolver: Arc<dyn EcosystemResolver>,
) -> Result<(), anyhow::Error> {
    let proof_schema = proof
        .schema
        .as_ref()
        .context("proof_schema is None".to_string())?
        .as_ref()
        .await?;

    let encoded = encode_cbor_base64(&device_response)?;

    let proved_credentials = super::verify_proof::validate_proof(
        &proof_schema,
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
        interaction,
        proved_credentials,
        &*credential_repository,
        proof_repository,
        identifier_creator,
        &*ecosystem_resolver,
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
            .error_while("waiting for Server2Client notification")?;

        for msg in data {
            let chunk: Chunk = msg.try_into().map_err(VerificationProtocolError::Other)?;
            match chunk {
                Chunk::Next(payload) => result.extend(payload),
                Chunk::Last(payload) => {
                    result.extend(payload);

                    return Ok(ciborium::from_reader(result.as_slice())?);
                }
            }
        }
    }
}

async fn proof_input_schema_to_doc_request(
    input: &ProofInputSchema,
    session_transcript: &SessionTranscript,
    verifier: Option<&IsoMdlVerifier>,
) -> Result<DocRequest, VerificationProtocolError> {
    let proof_claim_schemas = input.claim_schemas.as_ref().await?;
    let credential_schema = input.credential_schema.as_ref().await?;
    let formats = credential_schema.formats.as_ref().await?;
    let format = formats.first().ok_or(VerificationProtocolError::Failed(
        "formats is empty".to_string(),
    ))?;
    let mappings = format.claim_mappings.as_ref().await?;
    let mappings_by_schema_id: HashMap<_, _> = mappings
        .into_iter()
        .map(|m| (m.claim_schema_id, m))
        .collect();

    let mut name_spaces = HashMap::new();
    for proof_claim_schema in &proof_claim_schemas {
        let mapping = mappings_by_schema_id
            .get(&proof_claim_schema.schema.id)
            .ok_or_else(|| {
                VerificationProtocolError::Failed(format!(
                    "no mapping found for schema {} and format {}",
                    proof_claim_schema.schema.id, format.id
                ))
            })?;
        let Some(namespace) = &mapping.namespace else {
            return Err(VerificationProtocolError::Failed(format!(
                "mapping {} has no namespace",
                proof_claim_schema.schema.id
            )));
        };
        let element_identifier =
            if let Some((root, _)) = mapping.technical_key.rsplit_once(NESTED_CLAIM_MARKER) {
                root
            } else {
                &mapping.technical_key
            };

        name_spaces
            .entry(namespace.to_owned())
            .or_insert_with(HashMap::new)
            .insert(element_identifier.to_owned(), true);
    }

    let items_request = EmbeddedCbor::new(ItemsRequest {
        doc_type: credential_schema.schema_id().await?,
        name_spaces,
        request_info: None,
    })?;

    let reader_auth = match verifier {
        None => None,
        Some(verifier) => Some(
            prepare_reader_auth(
                session_transcript.to_owned(),
                items_request.clone(),
                verifier,
            )
            .await?,
        ),
    };

    Ok(DocRequest {
        items_request,
        reader_auth,
    })
}

pub(super) async fn prepare_reader_auth(
    session_transcript: SessionTranscript,
    items_request: EmbeddedCbor<ItemsRequest>,
    verifier: &IsoMdlVerifier,
) -> Result<CoseSign1, VerificationProtocolError> {
    let algorithm = verifier
        .auth_fn
        .get_key_algorithm()
        .error_while("getting key algorithm")?;

    let reader_authentication = ReaderAuthentication {
        session_transcript,
        items_request,
    };
    let reader_authentication_bytes = EmbeddedCbor::new(reader_authentication)?.into_bytes();

    let protected_headers = HeaderBuilder::new()
        .algorithm(
            build_algorithm_header_value(algorithm).error_while("creating algorithm header")?,
        )
        .build();

    let unprotected_headers = HeaderBuilder::new()
        .add_header(
            HeaderParameter::X5Chain,
            build_x5chain_header_value(&verifier.certificate.chain, None)
                .await
                .error_while("creating x5chain")?,
        )
        .build();

    let cose_sign1 = CoseSign1Builder::new()
        .protected(ProtectedHeader {
            original_data: None,
            header: protected_headers,
        })
        .unprotected(unprotected_headers)
        .try_create_detached_signature_with_provider(
            &reader_authentication_bytes,
            &[],
            verifier.auth_fn.as_ref(),
        )
        .await
        .error_while("creating signature")?
        .build();

    Ok(cose_sign1.into())
}
