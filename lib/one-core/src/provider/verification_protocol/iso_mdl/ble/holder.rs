use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, ProofId};
use tokio::sync::oneshot;
use uuid::Uuid;

use super::{ISO_MDL_FLOW, central, central_client_mode, peripheral, peripheral_server_mode};
use crate::config::core_config::VerificationEngagement;
use crate::error::ErrorCode::BR_0000;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::model::proof::{ProofStateEnum, UpdateProofRequest};
use crate::proto::bluetooth_low_energy::ble_resource::{BleWaiter, OnConflict, ScheduleResult};
use crate::proto::bluetooth_low_energy::low_level::ble_central::{BleCentral, TrackingBleCentral};
use crate::proto::bluetooth_low_energy::low_level::ble_peripheral::TrackingBlePeripheral;
use crate::proto::bluetooth_low_energy::low_level::dto::{
    DeviceAddress, DeviceInfo, ServiceDescription,
};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::ecosystem_resolver::EcosystemResolver;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::nfc::static_handover_handler::NfcStaticHandoverHandler;
use crate::provider::credential_formatter::mdoc_formatter::util::{Bstr, EmbeddedCbor};
use crate::provider::credential_formatter::model::VerificationFn;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::mso_mdoc::model::DeviceResponse;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::Handover;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::nfc::NFCHandover;
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
    pub device_address: DeviceAddress,
    pub mtu: usize,
    pub session_transcript_bytes: Vec<u8>,
    pub peripheral_server_mode: bool,
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
            client_central_uuid: (value.mode != BleMode::Peripheral).then_some(value.service_uuid),
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
    let (tx, rx) = oneshot::channel();
    let proof_repository_clone = proof_repository.clone();

    let interaction_data: MdocBleHolderInteractionData =
        deserialize_interaction_data(interaction.data.as_ref())
            .error_while("parsing interaction data")?;

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

                let result = tx.send(connected_verifier.clone());
                if let Err(connected_verifier) = result {
                    tracing::warn!("failed to send device info: {connected_verifier:?}");
                }

                let result = async {
                    let (engagement_type, handover, device_engagement) = match nfc_engagement {
                        None => {
                            // NFC not used, the engagement must have been via QR-code
                            (VerificationEngagement::QrCode, None, qr_engagement)
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
                                (
                                    VerificationEngagement::NFC,
                                    Some(Handover::Nfc(NFCHandover {
                                        select_message: Bstr(select_message),
                                        request_message: None,
                                    })),
                                    Some(device_engagement),
                                )
                            } else {
                                // no NFC contact, the engagement must have been via QR-code
                                hce.stop_hosting(true)
                                    .await
                                    .error_while("stopping NFC hosting")?;

                                (VerificationEngagement::QrCode, None, qr_engagement)
                            }
                        }
                    };

                    let device_engagement = device_engagement.ok_or(
                        VerificationProtocolError::Failed("Missing device engagement".to_string()),
                    )?;

                    let session_establishment = read_request(
                        &central,
                        &peripheral,
                        &connected_verifier,
                        &interaction_data.service_uuid,
                    )
                    .await?;

                    let session_transcript_bytes = create_session_transcript_bytes(
                        device_engagement,
                        session_establishment.e_reader_key.clone(),
                        handover,
                    )?;

                    let (sk_device, sk_reader) = device_key
                        .derive_session_keys(
                            session_establishment.e_reader_key.inner(),
                            session_transcript_bytes.bytes(),
                            key_algorithm_provider.as_ref(),
                        )
                        .await?;

                    let device_request_bytes = sk_reader.decrypt(&session_establishment.data.0)?;

                    let device_request: DeviceRequest =
                        ciborium::from_reader(device_request_bytes.as_slice())?;

                    let (verifier_identifier, ecosystem) = resolve_verifier_and_trust(
                        &device_request,
                        session_transcript_bytes.inner(),
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
                        session: Some(MdocBleHolderInteractionSessionData {
                            sk_device,
                            sk_reader,
                            device_address: connected_verifier.address().clone(),
                            device_request_bytes,
                            mtu: connected_verifier.mtu_size(),
                            session_transcript_bytes: session_transcript_bytes.into_bytes(),
                            peripheral_server_mode: matches!(
                                connected_verifier,
                                ConnectedVerifier::PeripheralServerMode(..)
                            ),
                        }),
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

                if let Err(ref err) = result {
                    set_proof_to_error(&*proof_repository, &proof_id, err.into()).await;
                    send_end(
                        &central,
                        &peripheral,
                        Some(&connected_verifier),
                        &interaction_data.service_uuid,
                    )
                    .await;
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
                    &central,
                    &peripheral,
                    rx.await.ok().as_ref(),
                    &interaction_data.service_uuid,
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
        .encrypt(&device_response_bytes)?;

    let session_data = SessionData {
        data: Some(Bstr(encrypted_device_response)),
        status: Some(StatusCode::SessionTermination),
    };

    let (_, result) = ble
        .schedule_continuation(
            interaction_data.continuation_task_id,
            |_, central, peripheral| async move {
                if interaction_session_data.peripheral_server_mode {
                    peripheral::write_chunked(
                        &session_data,
                        &peripheral,
                        &interaction_session_data.device_address,
                        &interaction_data.service_uuid,
                        peripheral_server_mode::SERVER_2_CLIENT,
                        interaction_session_data.mtu,
                    )
                    .await?;

                    // Wait for device disconnection here (but this means blocking UI)
                    tokio::time::sleep(Duration::from_millis(200)).await;
                } else {
                    central::write_chunked(
                        &session_data,
                        &central,
                        &interaction_session_data.device_address,
                        &interaction_data.service_uuid,
                        central_client_mode::CLIENT_2_SERVER,
                        interaction_session_data.mtu,
                    )
                    .await?;

                    if let Err(err) = central
                        .disconnect(interaction_session_data.device_address)
                        .await
                    {
                        tracing::warn!("failed to disconnect BLE central: {err}");
                    }
                }

                // End command signal not necessary, since we signal SessionTermination via SessionData status

                Ok::<_, VerificationProtocolError>(())
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

#[derive(Debug, Clone)]
enum ConnectedVerifier {
    CentralClientMode(DeviceAddress, usize),
    PeripheralServerMode(DeviceInfo),
}

impl ConnectedVerifier {
    fn address(&self) -> &DeviceAddress {
        match &self {
            Self::CentralClientMode(address, _) => address,
            Self::PeripheralServerMode(info) => &info.address,
        }
    }

    fn mtu_size(&self) -> usize {
        match &self {
            Self::CentralClientMode(_, mtu_size) => *mtu_size,
            Self::PeripheralServerMode(info) => info.mtu() as _,
        }
    }
}

async fn wait_for_central_client_mode(
    central: &TrackingBleCentral,
    service_uuid: &Uuid,
    e_device_key_bytes: &EmbeddedCbor<EphemeralSessionKey>,
) -> Result<ConnectedVerifier, VerificationProtocolError> {
    let (device, mtu_size) = central::wait_for_connection(
        central,
        service_uuid,
        central_client_mode::SERVER_2_CLIENT,
        central_client_mode::STATE,
    )
    .await?;

    let expected_ident = central_client_mode::derive_ident_value(e_device_key_bytes)?;
    let actual_ident = central
        .read_data(
            device.device_address.to_owned(),
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

    Ok(ConnectedVerifier::CentralClientMode(
        device.device_address,
        mtu_size,
    ))
}

async fn wait_for_peripheral_server_mode(
    peripheral: &TrackingBlePeripheral,
    service_uuid: &Uuid,
) -> Result<ConnectedVerifier, VerificationProtocolError> {
    Ok(ConnectedVerifier::PeripheralServerMode(
        peripheral::wait_for_active_device(peripheral, service_uuid, peripheral_server_mode::STATE)
            .await?,
    ))
}

async fn wait_for_connected_verifier(
    central: &TrackingBleCentral,
    peripheral: &TrackingBlePeripheral,
    service_uuid: &Uuid,
    mode: BleMode,
    e_device_key_bytes: &EmbeddedCbor<EphemeralSessionKey>,
) -> Result<ConnectedVerifier, VerificationProtocolError> {
    match mode {
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
    }
}

async fn wait_to_finish_engagement(
    central: &TrackingBleCentral,
    peripheral: &TrackingBlePeripheral,
    mode: BleMode,
    service_uuid: Uuid,
    qr_engagement: &Option<EmbeddedCbor<DeviceEngagement>>,
    nfc_engagement: &Option<NfcHceSession>,
) -> Result<ConnectedVerifier, VerificationProtocolError> {
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

async fn read_request(
    central: &TrackingBleCentral,
    peripheral: &TrackingBlePeripheral,
    connected_verifier: &ConnectedVerifier,
    service_uuid: &Uuid,
) -> Result<SessionEstablishment, VerificationProtocolError> {
    match connected_verifier {
        ConnectedVerifier::CentralClientMode(_, _) => {
            central::read_chunked(
                central,
                connected_verifier.address(),
                service_uuid,
                central_client_mode::SERVER_2_CLIENT,
            )
            .await
        }
        ConnectedVerifier::PeripheralServerMode(_) => {
            peripheral::read_chunked(
                peripheral,
                connected_verifier.address(),
                service_uuid,
                peripheral_server_mode::CLIENT_2_SERVER,
            )
            .await
        }
    }
}

async fn send_end(
    central: &TrackingBleCentral,
    peripheral: &TrackingBlePeripheral,
    connected_verifier: Option<&ConnectedVerifier>,
    service_uuid: &Uuid,
) {
    let Some(connected_verifier) = connected_verifier else {
        return;
    };

    match connected_verifier {
        ConnectedVerifier::CentralClientMode(_, _) => {
            central::send_end_command(
                central,
                connected_verifier.address(),
                service_uuid,
                central_client_mode::STATE,
            )
            .await
        }
        ConnectedVerifier::PeripheralServerMode(_) => {
            peripheral::notify_end(
                peripheral,
                connected_verifier.address(),
                service_uuid,
                peripheral_server_mode::STATE,
            )
            .await
        }
    }
}
