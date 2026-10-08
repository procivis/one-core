use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, ProofId};
use tokio::sync::oneshot;
use uuid::Uuid;

use super::common::{
    ConnectedPeer, PeerInfo, read_session_message, send_end, send_session_message,
};
use super::{ISO_MDL_FLOW, central, central_client_mode, peripheral, peripheral_server_mode};
use crate::config::core_config::VerificationEngagement;
use crate::error::ErrorCode::BR_0000;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::model::proof::{ProofRole, ProofStateEnum, UpdateProofRequest};
use crate::proto::bluetooth_low_energy::ble_resource::{BleWaiter, OnConflict, ScheduleResult};
use crate::proto::bluetooth_low_energy::low_level::ble_central::{BleCentral, TrackingBleCentral};
use crate::proto::bluetooth_low_energy::low_level::ble_peripheral::TrackingBlePeripheral;
use crate::proto::bluetooth_low_energy::low_level::dto::ServiceDescription;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::ecosystem_resolver::EcosystemResolver;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::nfc::static_handover_handler::NfcStaticHandoverHandler;
use crate::provider::credential_formatter::mdoc_formatter::util::{Bstr, EmbeddedCbor};
use crate::provider::credential_formatter::model::VerificationFn;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::mso_mdoc::model::DeviceResponse;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::nfc::NFCHandover;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
    Handover, SessionTranscript,
};
use crate::provider::verification_protocol::iso_mdl::BleMode;
use crate::provider::verification_protocol::iso_mdl::common::{
    DeviceRequest, EphemeralSessionKey, KeyAgreementKey, SkDevice, SkReader,
    create_session_transcript_bytes, set_proof_to_error, to_cbor,
};
use crate::provider::verification_protocol::iso_mdl::device_engagement::{
    BleOptionsV1, DeviceEngagement,
};
use crate::provider::verification_protocol::iso_mdl::holder_trust::resolve_verifier_and_trust;
use crate::provider::verification_protocol::iso_mdl::session::{
    SessionData, SessionEstablishment, StatusCode,
};
use crate::provider::verification_protocol::{
    VerificationProtocolError, deserialize_interaction_data,
};
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MdocBleHolderInteractionData {
    // known from the beginning
    pub organisation_id: OrganisationId,
    pub service_uuid: Uuid,
    pub engagement: HashSet<VerificationEngagement>,
    pub mode: BleMode,

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
    pub session_transcript_bytes: Vec<u8>,
    pub connected_verifier: ConnectedPeer,
}

#[derive(Debug, Clone)]
pub(crate) struct BleHolderSession {
    pub task_id: Uuid,
    pub mac_address: Option<String>,
    pub service_uuid: Uuid,
    pub mode: BleMode,
}

impl From<&BleHolderSession> for BleOptionsV1 {
    fn from(value: &BleHolderSession) -> Self {
        Self {
            peripheral_server_uuid: (value.mode != BleMode::Central).then_some(value.service_uuid),
            central_client_uuid: (value.mode != BleMode::Peripheral).then_some(value.service_uuid),
            peripheral_server_mac_address: if value.mode != BleMode::Central {
                value.mac_address.to_owned()
            } else {
                None
            },
        }
    }
}

/// Initiates BLE advertisement or scanning based on requested BLE mode
pub(crate) async fn start_mdl_holder(
    ble: &BleWaiter,
    mode: BleMode,
) -> Result<BleHolderSession, VerificationProtocolError> {
    let service_uuid = Uuid::new_v4();

    let (task_id, result) = ble
        .schedule(
            *ISO_MDL_FLOW,
            |_, central, peripheral| async move {
                let result = if mode != BleMode::Central {
                    peripheral
                        .start_advertisement(
                            None,
                            vec![ServiceDescription {
                                uuid: service_uuid.to_string(),
                                advertise: true,
                                advertised_service_data: None,
                                characteristics: peripheral_server_mode::get_characteristic_options(
                                ),
                            }],
                        )
                        .await
                        .error_while("starting BLE advertisement")?
                } else {
                    None
                };

                if mode != BleMode::Peripheral {
                    central
                        .start_scan(Some(vec![service_uuid.to_string()]))
                        .await
                        .error_while("starting BLE scanning")?;
                }

                Ok::<_, VerificationProtocolError>(result)
            },
            |_, _| async move {},
            OnConflict::ReplaceIfSameFlow,
            true,
        )
        .await
        .value_or(VerificationProtocolError::Failed("BLE is busy".into()))
        .await?;

    let mac_address =
        result.ok_or(VerificationProtocolError::Failed("flow was aborted".into()))??;

    Ok(BleHolderSession {
        task_id,
        mac_address,
        service_uuid,
        mode,
    })
}

pub(crate) struct NfcHceSession {
    pub handler: Arc<NfcStaticHandoverHandler>,
    pub hce: Arc<dyn NfcHce>,
    pub select_message: Vec<u8>,
    pub device_engagement: EmbeddedCbor<DeviceEngagement>,
}

/// Waits for verifier connection + reads device request
///
/// In the end the proof will change to Requested state
#[expect(clippy::too_many_arguments)]
pub(crate) async fn receive_mdl_request(
    ble: &BleWaiter,
    device_key: KeyAgreementKey,
    interaction_repository: Arc<dyn InteractionRepository>,
    interaction: Interaction,
    proof_repository: Arc<dyn ProofRepository>,
    proof_id: ProofId,
    qr_engagement: Option<EmbeddedCbor<DeviceEngagement>>,
    nfc_engagement: Option<NfcHceSession>,
    ecosystem_resolver: Arc<dyn EcosystemResolver>,
    certificate_validator: Arc<dyn CertificateValidator>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    verify_fn: VerificationFn,
) -> Result<(), VerificationProtocolError> {
    let interaction_data: MdocBleHolderInteractionData =
        deserialize_interaction_data(interaction.data.as_ref())
            .error_while("parsing interaction data")?;

    // share connection with the cancellation handler
    let (connection_sender, connection_receiver) = oneshot::channel();
    let proof_repository_clone = proof_repository.clone();

    let ScheduleResult::Scheduled { .. } = ble
        .schedule_continuation(
            interaction_data.continuation_task_id,
            |task_id, central, peripheral| async move {
                let result = wait_to_finish_engagement(
                    &central,
                    &peripheral,
                    interaction_data.mode,
                    interaction_data.service_uuid,
                    &qr_engagement,
                    &nfc_engagement,
                )
                .await;

                let connected_verifier = match result {
                    Ok(connected_verifier) => connected_verifier,
                    Err(err) => {
                        set_proof_to_error(&*proof_repository, &proof_id, (&err).into()).await;
                        return Err(err);
                    }
                };

                // stop other BLE mode when connection established
                if interaction_data.mode == BleMode::Both
                    && let Err(error) = match &connected_verifier {
                        ConnectedPeer::CentralClientMode(_) => {
                            peripheral.stop_advertisement().await
                        }
                        ConnectedPeer::PeripheralServerMode(_) => central.stop_scan().await,
                    }
                {
                    tracing::warn!(%error, "Failed to cancel other BLE mode");
                }

                // share connection details with the cancellation handler
                if connection_sender.send(connected_verifier.clone()).is_err() {
                    tracing::warn!("failed to send device info: {connected_verifier:?}");
                }

                let result = async {
                    let (engagement_type, device_engagement, handover) =
                        resolve_engagement(qr_engagement, nfc_engagement).await?;

                    let (device_request, session_data, session_transcript) = obtain_device_request(
                        &central,
                        &peripheral,
                        &connected_verifier,
                        device_key,
                        device_engagement,
                        handover,
                        key_algorithm_provider.as_ref(),
                    )
                    .await?;

                    let (verifier_identifier, ecosystem) = resolve_verifier_and_trust(
                        &device_request,
                        &session_transcript,
                        proof_id,
                        &interaction,
                        ecosystem_resolver.as_ref(),
                        certificate_validator.as_ref(),
                        identifier_creator.as_ref(),
                        &verify_fn,
                    )
                    .await?;

                    let interaction_data = serde_json::to_vec(&MdocBleHolderInteractionData {
                        continuation_task_id: task_id,
                        session: Some(session_data),
                        ..interaction_data
                    })?;

                    interaction_repository
                        .update_interaction(
                            interaction.id,
                            UpdateInteractionRequest {
                                data: Some(Some(interaction_data)),
                                ..Default::default()
                            },
                        )
                        .await
                        .error_while("updating interaction")?;

                    proof_repository
                        .update_proof(
                            &proof_id,
                            UpdateProofRequest {
                                state: Some(ProofStateEnum::Requested),
                                engagement: Some(Some(engagement_type.to_string())),
                                verifier_identifier_id: verifier_identifier.map(|i| i.id),
                                ecosystem: Some(ecosystem),
                                ..Default::default()
                            },
                            None,
                        )
                        .await
                        .error_while("updating proof")?;

                    Ok::<_, VerificationProtocolError>(())
                }
                .await;

                if let Err(error) = &result {
                    set_proof_to_error(&*proof_repository, &proof_id, error.into()).await;

                    // if specific error while parsing the request occurs, send a proper feedback to verifier
                    let status_code = match error {
                        VerificationProtocolError::EncryptionError(_) => {
                            Some(StatusCode::SessionEncryptionError)
                        }
                        VerificationProtocolError::CBORSerialization(_)
                        | VerificationProtocolError::CBORParsing(_) => {
                            Some(StatusCode::CborDecodingError)
                        }

                        _ => None,
                    };

                    if let Some(status_code) = status_code {
                        let session_data = SessionData {
                            data: None,
                            status: Some(status_code),
                        };

                        if let Err(err) = send_session_data(
                            &central,
                            &peripheral,
                            session_data,
                            &connected_verifier,
                        )
                        .await
                        {
                            tracing::warn!(%err, "Failed to send closing session data");
                        }
                    } else {
                        // otherwise just notify end of session
                        send_end(
                            ProofRole::Holder,
                            &central,
                            &peripheral,
                            Some(&connected_verifier),
                        )
                        .await;
                    }
                }

                result
            },
            move |central, peripheral| async move {
                let error_metadata = HistoryErrorMetadata {
                    error_code: BR_0000,
                    message: "Propose proof was cancelled".to_string(),
                };
                set_proof_to_error(&*proof_repository_clone, &proof_id, error_metadata).await;
                send_end(
                    ProofRole::Holder,
                    &central,
                    &peripheral,
                    connection_receiver.await.ok().as_ref(),
                )
                .await;
            },
            true,
        )
        .await
    else {
        return Err(VerificationProtocolError::Failed(
            "ble flow was interrupted".into(),
        ));
    };

    Ok(())
}

async fn resolve_engagement(
    qr_engagement: Option<EmbeddedCbor<DeviceEngagement>>,
    nfc_engagement: Option<NfcHceSession>,
) -> Result<
    (
        VerificationEngagement,
        EmbeddedCbor<DeviceEngagement>,
        Option<Handover>,
    ),
    VerificationProtocolError,
> {
    // by default treat as QR-code engagement
    let mut engagement_type = VerificationEngagement::QrCode;
    let mut engagement = qr_engagement;
    let mut handover = None;

    match nfc_engagement {
        None => {
            // NFC not used, the engagement must have been via QR-code
        }
        Some(NfcHceSession {
            handler,
            hce,
            select_message,
            device_engagement,
        }) => {
            if handler
                .message_read()
                .error_while("checking message read")?
            {
                // the NFC select message was read by a remote device, continue as NFC engaged
                engagement_type = VerificationEngagement::NFC;
                engagement = Some(device_engagement);
                handover = Some(Handover::Nfc(NFCHandover {
                    select_message: Bstr(select_message),
                    request_message: None,
                }));
            } else {
                // no NFC contact, the engagement must have been via QR-code
                hce.stop_hosting(true)
                    .await
                    .error_while("stopping NFC hosting")?;
            }
        }
    };

    Ok((
        engagement_type,
        engagement.ok_or(VerificationProtocolError::Failed(
            "Missing device engagement".to_string(),
        ))?,
        handover,
    ))
}

async fn obtain_device_request(
    central: &TrackingBleCentral,
    peripheral: &TrackingBlePeripheral,
    connected_verifier: &ConnectedPeer,
    device_key: KeyAgreementKey,
    device_engagement: EmbeddedCbor<DeviceEngagement>,
    handover: Option<Handover>,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<
    (
        DeviceRequest,
        MdocBleHolderInteractionSessionData,
        SessionTranscript,
    ),
    VerificationProtocolError,
> {
    let session_establishment: SessionEstablishment =
        read_session_message(ProofRole::Holder, central, peripheral, connected_verifier).await?;

    let session_transcript_bytes = create_session_transcript_bytes(
        device_engagement,
        session_establishment.e_reader_key.clone(),
        handover,
    )?;

    let (sk_device, sk_reader) = device_key
        .derive_session_keys(
            session_establishment.e_reader_key.inner(),
            session_transcript_bytes.bytes(),
            key_algorithm_provider,
        )
        .await?;

    let device_request_bytes = sk_reader.decrypt(&session_establishment.data.0)?;

    let device_request = ciborium::from_reader(device_request_bytes.as_slice())?;

    let session_data = MdocBleHolderInteractionSessionData {
        sk_device,
        sk_reader,
        connected_verifier: connected_verifier.clone(),
        device_request_bytes,
        session_transcript_bytes: session_transcript_bytes.bytes().to_vec(),
    };

    Ok((
        device_request,
        session_data,
        session_transcript_bytes.into_inner(),
    ))
}

pub(crate) async fn send_device_response(
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
        .encrypt(&device_response_bytes)?;

    let session_data = SessionData {
        data: Some(Bstr(encrypted_device_response)),
        status: Some(StatusCode::SessionTermination),
    };

    let (_, result) = ble
        .schedule_continuation(
            interaction_data.continuation_task_id,
            |_, central, peripheral| async move {
                send_session_data(
                    &central,
                    &peripheral,
                    session_data,
                    &interaction_session_data.connected_verifier,
                )
                .await
            },
            |_, _| async {},
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

async fn send_session_data(
    central: &TrackingBleCentral,
    peripheral: &TrackingBlePeripheral,
    session_data: SessionData,
    connected_verifier: &ConnectedPeer,
) -> Result<(), VerificationProtocolError> {
    // sending error status code means session should be terminated right after
    // ISO 18013-5, Table 20
    let should_disconnect_after = session_data.status.is_some();

    send_session_message(
        ProofRole::Holder,
        central,
        peripheral,
        &session_data,
        connected_verifier,
    )
    .await?;

    // wait for disconnection with an arbitrary timeout
    // on some OS's the disconnection events are not reported right away
    if should_disconnect_after {
        const DISCONNECTION_TIMEOUT: Duration = Duration::from_secs(1);

        match connected_verifier {
            ConnectedPeer::CentralClientMode(connection) => {
                central::wait_for_end_command(
                    central,
                    connection,
                    central_client_mode::STATE,
                    DISCONNECTION_TIMEOUT,
                )
                .await;

                if let Err(err) = central.disconnect(connection.address.to_owned()).await {
                    tracing::warn!("failed to disconnect BLE central: {err}");
                }
            }
            ConnectedPeer::PeripheralServerMode(connection) => {
                peripheral::wait_for_disconnection(peripheral, connection, DISCONNECTION_TIMEOUT)
                    .await;
            }
        }
    }

    Ok(())
}

async fn wait_for_central_client_mode(
    central: &TrackingBleCentral,
    service_uuid: &Uuid,
    e_device_key_bytes: &EmbeddedCbor<EphemeralSessionKey>,
) -> Result<ConnectedPeer, VerificationProtocolError> {
    let verifier_device = central::wait_for_connection(
        central,
        service_uuid,
        central_client_mode::SERVER_2_CLIENT,
        central_client_mode::STATE,
    )
    .await?;

    let expected_ident = central_client_mode::derive_ident_value(e_device_key_bytes)?;
    let actual_ident = central
        .read_data(
            verifier_device.address.to_owned(),
            service_uuid.to_string(),
            central_client_mode::IDENT.into(),
        )
        .await
        .error_while("reading Ident")?;

    if expected_ident != actual_ident {
        return Err(VerificationProtocolError::Failed(
            "Ident validation failed".to_string(),
        ));
    }

    Ok(ConnectedPeer::CentralClientMode(verifier_device))
}

async fn wait_for_peripheral_server_mode(
    peripheral: &TrackingBlePeripheral,
    service_uuid: &Uuid,
) -> Result<ConnectedPeer, VerificationProtocolError> {
    let device_info =
        peripheral::wait_for_active_device(peripheral, service_uuid, peripheral_server_mode::STATE)
            .await?;
    let max_payload_size = device_info.max_payload_size() as _;
    Ok(ConnectedPeer::PeripheralServerMode(PeerInfo {
        address: device_info.address,
        max_payload_size,
        service_uuid: *service_uuid,
    }))
}

async fn wait_for_connected_verifier(
    central: &TrackingBleCentral,
    peripheral: &TrackingBlePeripheral,
    service_uuid: &Uuid,
    mode: BleMode,
    e_device_key_bytes: &EmbeddedCbor<EphemeralSessionKey>,
) -> Result<ConnectedPeer, VerificationProtocolError> {
    let connected_verifier = match mode {
        BleMode::Peripheral => wait_for_peripheral_server_mode(peripheral, service_uuid).await,
        BleMode::Central => {
            wait_for_central_client_mode(central, service_uuid, e_device_key_bytes).await
        }
        BleMode::Both => {
            tokio::select! {
                connection = wait_for_peripheral_server_mode(peripheral, service_uuid) => connection,
                connection = wait_for_central_client_mode(central, service_uuid,e_device_key_bytes) => connection,
            }
        }
    }?;

    tracing::debug!("Connected to: {connected_verifier:?}");
    Ok(connected_verifier)
}

async fn wait_to_finish_engagement(
    central: &TrackingBleCentral,
    peripheral: &TrackingBlePeripheral,
    mode: BleMode,
    service_uuid: Uuid,
    qr_engagement: &Option<EmbeddedCbor<DeviceEngagement>>,
    nfc_engagement: &Option<NfcHceSession>,
) -> Result<ConnectedPeer, VerificationProtocolError> {
    let device_engagement = match (qr_engagement, nfc_engagement) {
        (None, None) => {
            return Err(VerificationProtocolError::Failed(
                "No engagement".to_string(),
            ));
        }
        (Some(qr), _) => qr,
        (_, Some(nfc)) => &nfc.device_engagement,
    };
    let connected_verifier_future = wait_for_connected_verifier(
        central,
        peripheral,
        &service_uuid,
        mode,
        device_engagement.inner().security.e_device_key_bytes(),
    );

    match (qr_engagement, nfc_engagement) {
        (None, None) => Err(VerificationProtocolError::Failed(
            "No engagement".to_string(),
        )),
        // if running only NFC engagement, failure of NFC session means failure of the whole proof flow
        (None, Some(nfc_only)) => {
            let session_failure_future =
                nfc_only
                    .handler
                    .session_failure()
                    .ok_or(VerificationProtocolError::Failed(
                        "NFC session failure receiver not available".to_string(),
                    ))?;
            tokio::select! {
                connected_verifier = connected_verifier_future => connected_verifier,
                failure_reason = session_failure_future => {
                    Err(match failure_reason {
                        Ok(nfc_error) => nfc_error.error_while("NFC engagement").into(),
                        Err(rcv_error) => VerificationProtocolError::Failed(format!("NFC session failure: {rcv_error}")),
                    })
                }
            }
        }
        // if running QR engagement, then we can ignore NFC failure since QR-code engagement is still possible
        (Some(_qr), _) => connected_verifier_future.await,
    }
}
