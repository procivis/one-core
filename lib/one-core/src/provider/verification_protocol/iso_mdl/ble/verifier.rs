use std::collections::HashMap;
use std::sync::Arc;

use coset::iana::HeaderParameter;
use coset::{HeaderBuilder, ProtectedHeader};
use tokio::sync::oneshot;
use uuid::Uuid;

use super::common::{
    ConnectedPeer, PeerInfo, read_session_message, send_end, send_session_message,
};
use super::{ISO_MDL_FLOW, central, central_client_mode, peripheral, peripheral_server_mode};
use crate::error::ContextWithErrorCode;
use crate::error::ErrorCode::BR_0000;
use crate::mapper::{NESTED_CLAIM_MARKER, encode_cbor_base64};
use crate::model::certificate::Certificate;
use crate::model::history::HistoryErrorMetadata;
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum, UpdateProofRequest};
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::model::relation::OptionalRelatedExt;
use crate::proto::bluetooth_low_energy::ble_resource::{BleWaiter, OnConflict, ScheduleResult};
use crate::proto::bluetooth_low_energy::low_level::ble_central::{BleCentral, TrackingBleCentral};
use crate::proto::bluetooth_low_energy::low_level::ble_peripheral::TrackingBlePeripheral;
use crate::proto::bluetooth_low_energy::low_level::dto::ServiceDescription;
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
use crate::provider::verification_protocol::iso_mdl::common::{
    DeviceRequest, DocRequest, EphemeralSessionKey, ItemsRequest, KeyAgreementKey, SkDevice,
    create_session_transcript_bytes, set_proof_to_error, to_cbor,
};
use crate::provider::verification_protocol::iso_mdl::device_engagement::{
    BleOptionsV1, DeviceEngagement,
};
use crate::provider::verification_protocol::iso_mdl::session::{SessionData, SessionEstablishment};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::proof_repository::ProofRepository;

#[derive(Debug, Clone)]
pub(crate) struct VerifierSession {
    reader_key: EmbeddedCbor<EphemeralSessionKey>,
    e_device_key_bytes: EmbeddedCbor<EphemeralSessionKey>,
    session_transcript: SessionTranscript,
    device_request_encrypted: Vec<u8>,
    sk_device: SkDevice,
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
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<VerifierSession, VerificationProtocolError> {
    let e_device_key_bytes = device_engagement.inner().security.e_device_key_bytes();
    let e_device_key = e_device_key_bytes.inner();
    let key_algorithm = e_device_key.get_algorithm(key_algorithm_provider)?;
    let reader_key =
        KeyAgreementKey::generate(key_algorithm.as_ref()).error_while("generating EReaderKey")?;

    let e_reader_key = EmbeddedCbor::new(reader_key.ephemeral_key().clone())?;

    let session_transcript_bytes = create_session_transcript_bytes(
        device_engagement.to_owned(),
        e_reader_key.to_owned(),
        handover,
    )?;

    let (sk_device, sk_reader) = reader_key
        .derive_session_keys(
            e_device_key,
            session_transcript_bytes.bytes(),
            key_algorithm_provider,
        )
        .await
        .error_while("deriving session keys")?;

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

    let device_request_encrypted = sk_reader.encrypt(&device_request_bytes)?;

    Ok(VerifierSession {
        reader_key: e_reader_key,
        e_device_key_bytes: e_device_key_bytes.to_owned(),
        session_transcript: session_transcript_bytes.into_inner(),
        device_request_encrypted,
        sk_device,
    })
}

/// Main background task on mDL verifier
/// All from initializing connection to handling response
#[expect(clippy::too_many_arguments)]
pub(crate) async fn handle_ble_verifier(
    ble: &BleWaiter,
    ble_options: BleOptionsV1,
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
    let (sender, receiver) = oneshot::channel();

    let schedule_result = ble
        .schedule(
            *ISO_MDL_FLOW,
            move |_, central, peripheral| async move {
                let result = verifier_flow(
                    ble_options,
                    verifier_session,
                    &proof,
                    &interaction,
                    &central,
                    &peripheral,
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
                    tracing::info!(%error, "mDL verifier failure");
                    set_proof_to_error(&*proof_repository, &proof.id, error.into()).await;
                };

                result
            },
            move |central, peripheral| async move {
                tracing::info!("Cancelling mDL verifier flow");
                if let Ok(connected_holder) = receiver.await {
                    send_end(
                        ProofRole::Verifier,
                        &central,
                        &peripheral,
                        Some(&connected_holder),
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
/// we may need to send End command, disconnect and set proof state to error
#[expect(clippy::too_many_arguments)]
#[tracing::instrument(level = "debug", skip_all, err(level = "info"))]
async fn verifier_flow(
    ble_options: BleOptionsV1,
    verifier_session: VerifierSession,
    proof: &Proof,
    interaction: &Interaction,
    central: &TrackingBleCentral,
    peripheral: &TrackingBlePeripheral,
    sender: oneshot::Sender<ConnectedPeer>,
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
    let connected_holder = connect_based_on_options(
        central,
        peripheral,
        ble_options,
        &verifier_session.e_device_key_bytes,
    )
    .await?;

    if let Err(err) = sender.send(connected_holder.to_owned()) {
        tracing::warn!("failed to send device discovery data: {err:?}");
    }

    let result = process_proof(
        verifier_session,
        proof,
        interaction,
        central,
        peripheral,
        &connected_holder,
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
            ProofRole::Verifier,
            central,
            peripheral,
            Some(&connected_holder),
        )
        .await;
    }

    result
}

#[expect(clippy::too_many_arguments)]
#[tracing::instrument(level = "debug", skip_all, err(level = "info"))]
async fn process_proof(
    verifier_session: VerifierSession,
    proof: &Proof,
    interaction: &Interaction,
    central: &TrackingBleCentral,
    peripheral: &TrackingBlePeripheral,
    connected_holder: &ConnectedPeer,
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
    let session_establishment = SessionEstablishment {
        e_reader_key: verifier_session.reader_key,
        data: Bstr(verifier_session.device_request_encrypted),
    };

    send_session_message(
        ProofRole::Verifier,
        central,
        peripheral,
        &session_establishment,
        connected_holder,
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
        .await
        .error_while("updating proof")?;

    let session_data: SessionData =
        read_session_message(ProofRole::Verifier, central, peripheral, connected_holder).await?;

    let should_terminate_session = session_data.status.is_some();
    if !should_terminate_session {
        send_end(
            ProofRole::Verifier,
            central,
            peripheral,
            Some(connected_holder),
        )
        .await;
    }

    // terminate connection
    match connected_holder {
        ConnectedPeer::CentralClientMode(_) => {
            if let Err(err) = peripheral.stop_server().await {
                tracing::warn!(%err, "failed to stop BLE peripheral");
            }
        }
        ConnectedPeer::PeripheralServerMode(PeerInfo { address, .. }) => {
            if let Err(err) = central.disconnect(address.to_owned()).await {
                tracing::warn!(%err, "failed to disconnect BLE central");
            }
        }
    };

    let decrypted = verifier_session.sk_device.decrypt(
        &session_data
            .data
            .ok_or(VerificationProtocolError::Failed(
                "session data is missing".to_string(),
            ))?
            .0,
    )?;
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
        set_proof_to_error(&*proof_repository, &proof.id, error_metadata).await;
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
                .await
                .error_while("updating proof")?;
        } else {
            let error_metadata = HistoryErrorMetadata {
                error_code: BR_0000,
                message: "Response documents are empty but no errors are provided".to_string(),
            };
            set_proof_to_error(&*proof_repository, &proof.id, error_metadata).await;
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
        tracing::info!(%error, "mDL proof parsing failure");
        set_proof_to_error(&*proof_repository, &proof.id, (&error).into()).await;
    }

    Ok(())
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
) -> Result<(), VerificationProtocolError> {
    let proof_schema = proof.schema.as_required_ref().await?;

    let encoded = encode_cbor_base64(&device_response).error_while("encoding device response")?;

    let proved_credentials =
        crate::provider::verification_protocol::iso_mdl::verify_proof::validate_proof(
            &proof_schema,
            &encoded,
            session_transcript,
            credential_formatter_provider,
            presentation_formatter_provider,
            &key_algorithm_provider,
            did_method_provider.clone(),
            certificate_validator.clone(),
        )
        .await
        .error_while("validating proof")?;

    crate::provider::verification_protocol::iso_mdl::verify_proof::accept_proof(
        proof,
        interaction,
        proved_credentials,
        &*credential_repository,
        proof_repository,
        identifier_creator.as_ref(),
        &*ecosystem_resolver,
    )
    .await
    .error_while("accepting proof")?;

    Ok(())
}

async fn connect_peripheral_server_mode(
    central: &TrackingBleCentral,
    service_uuid: &Uuid,
) -> Result<ConnectedPeer, VerificationProtocolError> {
    central
        .start_scan(Some(vec![service_uuid.to_string()]))
        .await
        .error_while("starting BLE scan")?;

    let connected_holder = central::wait_for_connection(
        central,
        service_uuid,
        peripheral_server_mode::SERVER_2_CLIENT,
        peripheral_server_mode::STATE,
    )
    .await?;

    Ok(ConnectedPeer::PeripheralServerMode(connected_holder))
}

async fn connect_central_client_mode(
    peripheral: &TrackingBlePeripheral,
    service_uuid: &Uuid,
    e_device_key_bytes: &EmbeddedCbor<EphemeralSessionKey>,
) -> Result<ConnectedPeer, VerificationProtocolError> {
    peripheral
        .start_advertisement(
            None,
            vec![ServiceDescription {
                uuid: service_uuid.to_string(),
                advertise: true,
                advertised_service_data: None,
                characteristics: central_client_mode::get_characteristic_options(),
            }],
        )
        .await
        .error_while("starting BLE advertisement")?;

    let ident_value = central_client_mode::derive_ident_value(e_device_key_bytes)?;
    tracing::debug!("Setting Ident value: {ident_value:?}");
    peripheral
        .set_characteristic_data(
            service_uuid.to_string(),
            central_client_mode::IDENT.into(),
            &ident_value,
        )
        .await
        .error_while("setting Ident value")?;

    let device_info =
        peripheral::wait_for_active_device(peripheral, service_uuid, central_client_mode::STATE)
            .await?;
    let max_payload_size = device_info.max_payload_size() as _;
    Ok(ConnectedPeer::CentralClientMode(PeerInfo {
        address: device_info.address,
        max_payload_size,
        service_uuid: *service_uuid,
    }))
}

#[tracing::instrument(level = "debug", skip_all, err(level = "info"))]
async fn connect_based_on_options(
    central: &TrackingBleCentral,
    peripheral: &TrackingBlePeripheral,
    ble_options: BleOptionsV1,
    e_device_key_bytes: &EmbeddedCbor<EphemeralSessionKey>,
) -> Result<ConnectedPeer, VerificationProtocolError> {
    // ISO 18013-5, 8.3.3.1.1.1
    // If the mdoc indicates during device engagement that it supports both modes, the mdoc reader should select the mdoc central client mode.
    let connected_holder = match (
        ble_options.central_client_uuid,
        ble_options.peripheral_server_uuid,
    ) {
        (Some(central_client_uuid), _) => {
            tracing::debug!("Using mdoc central client mode, service: {central_client_uuid}");
            connect_central_client_mode(peripheral, &central_client_uuid, e_device_key_bytes)
                .await?
        }
        (_, Some(peripheral_server_uuid)) => {
            tracing::debug!("Using mdoc peripheral server mode, service: {peripheral_server_uuid}");
            connect_peripheral_server_mode(central, &peripheral_server_uuid).await?
        }
        (None, None) => {
            return Err(VerificationProtocolError::Failed(
                "No BLE mode advertised".to_string(),
            ));
        }
    };

    tracing::debug!("Connected to: {connected_holder:?}");
    Ok(connected_holder)
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

pub(crate) async fn prepare_reader_auth(
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
