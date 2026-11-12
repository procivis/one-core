use std::sync::Arc;

use tokio::sync::oneshot;
use uuid::Uuid;

use super::common::{
    ConnectedPeer, PeerInfo, read_session_message, send_end, send_session_message,
};
use super::{ISO_MDL_FLOW, central, central_client_mode, peripheral, peripheral_server_mode};
use crate::error::ContextWithErrorCode;
use crate::model::interaction::Interaction;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum, UpdateProofRequest};
use crate::model::proof_schema::ProofSchema;
use crate::proto::bluetooth_low_energy::ble_resource::{BleWaiter, OnConflict, ScheduleResult};
use crate::proto::bluetooth_low_energy::low_level::ble_central::{BleCentral, TrackingBleCentral};
use crate::proto::bluetooth_low_energy::low_level::ble_peripheral::TrackingBlePeripheral;
use crate::proto::bluetooth_low_energy::low_level::dto::ServiceDescription;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::ecosystem_resolver::EcosystemResolver;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::mdoc_formatter::util::{Bstr, EmbeddedCbor};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
    Handover, SessionTranscript,
};
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::IsoMdlVerifier;
use crate::provider::verification_protocol::iso_mdl::common::{
    EphemeralSessionKey, KeyAgreementKey, SkDevice, create_session_transcript_bytes,
    set_proof_to_error, to_cbor,
};
use crate::provider::verification_protocol::iso_mdl::device_engagement::{
    BleOptionsV1, DeviceEngagement,
};
use crate::provider::verification_protocol::iso_mdl::session::{SessionData, SessionEstablishment};
use crate::provider::verification_protocol::iso_mdl::verifier::{
    create_device_request, process_device_response,
};
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

pub(crate) async fn setup_verifier_session(
    device_engagement: EmbeddedCbor<DeviceEngagement>,
    schema: &ProofSchema,
    handover: Handover,
    verifier: Option<&IsoMdlVerifier>,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    blob_storage_provider: &dyn BlobStorageProvider,
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

    let device_request = create_device_request(
        schema,
        verifier,
        session_transcript_bytes.inner(),
        blob_storage_provider,
    )
    .await?;

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
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
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
                    credential_formatter_provider,
                    presentation_formatter_provider,
                    did_method_provider,
                    key_algorithm_provider,
                    credential_repository,
                    proof_repository.clone(),
                    certificate_validator,
                    identifier_creator,
                    ecosystem_resolver,
                    revocation_method_provider,
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
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
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
        revocation_method_provider,
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
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
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
    let device_response = ciborium::from_reader(&decrypted[..])?;

    process_device_response(
        device_response,
        verifier_session.session_transcript,
        proof,
        interaction,
        credential_formatter_provider.as_ref(),
        presentation_formatter_provider.as_ref(),
        did_method_provider,
        key_algorithm_provider,
        credential_repository.as_ref(),
        proof_repository.as_ref(),
        certificate_validator,
        identifier_creator,
        ecosystem_resolver.as_ref(),
        revocation_method_provider.as_ref(),
    )
    .await?;

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
