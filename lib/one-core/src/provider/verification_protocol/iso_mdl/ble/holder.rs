use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, ProofId};
use tokio::sync::oneshot;
use uuid::Uuid;

use super::ISO_MDL_FLOW;
use super::peripheral::{notify_end, read_chunked, wait_for_active_device, write_chunked};
use super::peripheral_server_mode::{
    CLIENT_2_SERVER, SERVER_2_CLIENT, STATE, get_characteristic_options,
};
use crate::config::core_config::VerificationEngagement;
use crate::error::ErrorCode::BR_0000;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::model::proof::{ProofStateEnum, UpdateProofRequest};
use crate::proto::bluetooth_low_energy::ble_resource::{BleWaiter, OnConflict, ScheduleResult};
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
use crate::provider::verification_protocol::iso_mdl::common::{
    DeviceRequest, KeyAgreementKey, SkDevice, SkReader, create_session_transcript_bytes,
    set_proof_to_error, to_cbor,
};
use crate::provider::verification_protocol::iso_mdl::device_engagement::DeviceEngagement;
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
    pub session_transcript_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct ServerInfo {
    pub task_id: Uuid,
    pub mac_address: Option<String>,
    pub service_uuid: Uuid,
}

/// Initiates mDL advertisement
pub(crate) async fn start_mdl_server(
    ble: &BleWaiter,
    service_uuid: Uuid,
) -> Result<ServerInfo, VerificationProtocolError> {
    let (task_id, result) = ble
        .schedule(
            *ISO_MDL_FLOW,
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
            |_, _| async move {},
            OnConflict::ReplaceIfSameFlow,
            true,
        )
        .await
        .value_or(VerificationProtocolError::Failed("BLE is busy".into()))
        .await?;

    let mac_address = result
        .ok_or(VerificationProtocolError::Failed("flow was aborted".into()))?
        .error_while("starting BLE server")?;

    Ok(ServerInfo {
        task_id,
        mac_address,
        service_uuid,
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
            |task_id, _, peripheral| async move {
                let result = wait_to_finish_engagement(
                    &peripheral,
                    interaction_data.service_uuid,
                    &qr_engagement,
                    &nfc_engagement,
                )
                .await;

                let info = match result {
                    Ok(info) => info,
                    Err(err) => {
                        set_proof_to_error(&*proof_repository, &proof_id, (&err).into()).await;
                        return Err(err);
                    }
                };

                let result = tx.send(info.clone());
                if let Err(device_info) = result {
                    tracing::warn!("failed to send device info: {device_info:?}");
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

                    let session_establishment =
                        read_request(&peripheral, &info, interaction_data.service_uuid).await?;

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
                            device_address: info.address.clone(),
                            device_request_bytes,
                            mtu: info.mtu(),
                            session_transcript_bytes: session_transcript_bytes.into_bytes(),
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
                    notify_end(
                        &peripheral,
                        Some(&info.address),
                        &interaction_data.service_uuid,
                        STATE,
                    )
                    .await;
                }

                result
            },
            move |_, peripheral| async move {
                let error_metadata = HistoryErrorMetadata {
                    error_code: BR_0000,
                    message: "Propose proof was cancelled".to_string(),
                };
                set_proof_to_error(&*proof_repository_clone, &proof_id, error_metadata).await;
                notify_end(
                    &peripheral,
                    rx.await.ok().as_ref().map(|info| &info.address),
                    &interaction_data.service_uuid,
                    STATE,
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
            |_, _, peripheral| async move {
                write_chunked(
                    &session_data,
                    &peripheral,
                    &interaction_session_data.device_address,
                    &interaction_data.service_uuid,
                    SERVER_2_CLIENT,
                    interaction_session_data.mtu as _,
                )
                .await?;

                // End command signal not necessary, since we signal SessionTermination via SessionData status

                // Wait for device disconnection here (but this means blocking UI)
                tokio::time::sleep(Duration::from_millis(200)).await;

                Ok::<_, VerificationProtocolError>(())
            },
            move |_, _| async move {},
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

async fn wait_to_finish_engagement(
    peripheral: &TrackingBlePeripheral,
    service_uuid: Uuid,
    qr_engagement: &Option<EmbeddedCbor<DeviceEngagement>>,
    nfc_engagement: &Option<NfcHceSession>,
) -> Result<DeviceInfo, VerificationProtocolError> {
    let connected_device_future = wait_for_active_device(peripheral, &service_uuid, STATE);

    let info = match (qr_engagement, nfc_engagement) {
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
                connected_device = connected_device_future => connected_device,
                failure_reason = session_failure_future => {
                    Err(match failure_reason {
                        Ok(nfc_error) => nfc_error.error_while("NFC engagement").into(),
                        Err(rcv_error) => VerificationProtocolError::Failed(format!("NFC session failure: {rcv_error}")),
                    })
                }
            }
        }
        // if running QR engagement, then we can ignore NFC failure since QR-code engagement is still possible
        (Some(_qr), _) => connected_device_future.await,
    }?;

    peripheral
        .stop_advertisement()
        .await
        .error_while("stopping BLE advertisement")?;

    Ok(info)
}

async fn read_request(
    peripheral: &TrackingBlePeripheral,
    info: &DeviceInfo,
    service_uuid: Uuid,
) -> Result<SessionEstablishment, VerificationProtocolError> {
    read_chunked(peripheral, &info.address, &service_uuid, CLIENT_2_SERVER).await
}
