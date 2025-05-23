use std::sync::Arc;
use std::time::Duration;
use std::vec;

use anyhow::Context;
use futures::{Stream, StreamExt, TryFutureExt, stream};
use one_crypto::utilities::generate_random_bytes;
use shared_types::{DidValue, ProofId};
use time::OffsetDateTime;
use tokio::select;
use uuid::Uuid;

use super::{
    BLEParse, BLEPeer, CONTENT_SIZE_UUID, DISCONNECT_UUID, IDENTITY_UUID, IdentityRequest,
    OIDC_BLE_FLOW, REQUEST_SIZE_UUID, SERVICE_UUID, SUBMIT_VC_UUID, TRANSFER_SUMMARY_REPORT_UUID,
    TransferSummaryReport,
};
use crate::common_mapper::{DidRole, get_or_create_did_and_identifier};
use crate::model::history::HistoryErrorMetadata;
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::model::proof::{ProofStateEnum, UpdateProofRequest};
use crate::provider::bluetooth_low_energy::BleError;
use crate::provider::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicWriteType, DeviceAddress, DeviceInfo,
};
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::VerificationFn;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::model::PresentationSubmissionMappingDTO;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::KeyAgreementKey;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::dto::BleOpenId4VpResponse;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::model::BLEOpenID4VPInteractionData;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::{
    PRESENTATION_REQUEST_UUID, TRANSFER_SUMMARY_REQUEST_UUID,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::dto::{
    Chunk, ChunkExt, Chunks, MessageSize,
};
use crate::provider::verification_protocol::{
    VerificationProtocolError, deserialize_interaction_data,
};
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ErrorCodeMixin;
use crate::util::ble_resource::{Abort, BleWaiter, OnConflict};

pub(crate) struct OpenID4VCBLEHolder {
    pub proof_repository: Arc<dyn ProofRepository>,
    pub did_repository: Arc<dyn DidRepository>,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub interaction_repository: Arc<dyn InteractionRepository>,
    pub ble: BleWaiter,
}

impl OpenID4VCBLEHolder {
    pub(crate) fn new(
        proof_repository: Arc<dyn ProofRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        did_repository: Arc<dyn DidRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        ble: BleWaiter,
    ) -> Self {
        Self {
            proof_repository,
            interaction_repository,
            did_repository,
            identifier_repository,
            did_method_provider,
            ble,
        }
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub(crate) async fn enabled(&self) -> Result<bool, VerificationProtocolError> {
        self.ble
            .is_enabled()
            .await
            .map(|s| s.central)
            .map_err(|err| VerificationProtocolError::Transport(err.into()))
    }

    #[tracing::instrument(level = "debug", skip(self, verification_fn), err(Debug))]
    pub(crate) async fn handle_invitation(
        &mut self,
        name: String,
        x25519_public_key_hex: String,
        proof_id: ProofId,
        verification_fn: VerificationFn,
        interaction_id: Uuid,
        organisation: Organisation,
    ) -> Result<Identifier, VerificationProtocolError> {
        let interaction_repository = self.interaction_repository.clone();
        let did_repository = self.did_repository.clone();
        let identifier_repository = self.identifier_repository.clone();
        let did_method_provider = self.did_method_provider.clone();

        let result = self
            .ble
            .schedule(
                *OIDC_BLE_FLOW,
                |task_id, central, _| async move {
                    let verifier_public_key: [u8; 32] = hex::decode(&x25519_public_key_hex)
                        .context("Failed to decode verifier public key")
                        .map_err(VerificationProtocolError::Transport)?
                        .as_slice()
                        .try_into()
                        .context("Invalid verifier public key length")
                        .map_err(VerificationProtocolError::Transport)?;

                    tracing::debug!("Connecting to verifier: {name}");
                    let device_info = connect_to_verifier(&name, &verifier_public_key, &*central)
                        .await
                        .context("failed to connect to verifier")
                        .map_err(VerificationProtocolError::Transport)?;

                    subscribe_to_notifications(&*central, &device_info.address).await?;

                    let interaction = select! {
                        biased;

                        _ = verifier_disconnect_event(central.clone(), device_info.address.clone()) => {
                            Err(VerificationProtocolError::Failed("Verifier disconnected".into()))
                        },
                        interaction_data = async {
                            tracing::debug!("session_key_and_identity_request");
                            let (identity_request, ble_peer) =
                                session_key_and_identity_request(device_info.clone(), verifier_public_key)?;

                            send(
                                IDENTITY_UUID,
                                identity_request.clone().encode().as_ref(),
                                &ble_peer,
                                &*central,
                                CharacteristicWriteType::WithResponse,
                            )
                            .await?;

                            // Wait to ensure the verifier processed the identity request and updated
                            // the relevant characteristics
                            tokio::time::sleep(Duration::from_millis(200)).await;

                            tracing::debug!("read_presentation_definition");
                            let request =
                                read_presentation_request(&ble_peer, verification_fn, central.clone())
                                    .await?;

                            let now = OffsetDateTime::now_utc();
                            let organisation = Some(organisation);
                            let (_, verifier_identifier) = {
                                let did_value = DidValue::from_did_url(request.client_id.as_str())
                                    .map_err(|_| {
                                        VerificationProtocolError::InvalidRequest(format!(
                                            "invalid client_id: {}",
                                            request.client_id
                                        ))
                                    })?;

                                    get_or_create_did_and_identifier(&*did_method_provider, &*did_repository, &*identifier_repository, &organisation, &did_value, DidRole::Verifier)
                                    .await
                                    .map_err(|_| {
                                        VerificationProtocolError::Failed(format!(
                                            "failed to resolve or create did: {}",
                                            request.client_id
                                        ))
                                    })?
                            };

                            Ok((verifier_identifier, Interaction {
                                id: interaction_id,
                                created_date: now,
                                last_modified: now,
                                host: None,
                                organisation,
                                data: Some(
                                    serde_json::to_vec(&BLEOpenID4VPInteractionData {
                                        client_id: request.client_id.to_owned(),
                                        nonce: request.nonce.clone().ok_or(
                                            VerificationProtocolError::InvalidRequest(
                                                "nonce missing".to_string(),
                                            ),
                                        )?,
                                        task_id,
                                        peer: ble_peer,
                                        presentation_definition:  request.presentation_definition.clone().ok_or(
                                                VerificationProtocolError::InvalidRequest(
                                                    "presentation_definition missing".to_string(),
                                                ),
                                            )?,
                                        openid_request: request,
                                        identity_request_nonce: Some(hex::encode(identity_request.nonce)),
                                        presentation_submission: None,
                                    })
                                    .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?,
                                ),
                            }))
                        } => interaction_data
                    };

                    if interaction.is_err() {
                        unsubscribe_and_disconnect(device_info.address, central).await;
                    }

                    interaction
                },
                move |central, _| async move {
                    let Ok(interaction) = interaction_repository
                        .get_interaction(&interaction_id, &Default::default())
                        .await
                        .map_err(|err| VerificationProtocolError::Failed(err.to_string()))
                    else {
                        return;
                    };

                    let Ok(interaction_data) =
                        deserialize_interaction_data::<BLEOpenID4VPInteractionData>(
                            interaction.as_ref().and_then(|i| i.data.as_ref()),
                        )
                    else {
                        return;
                    };
                    let verifier_address = interaction_data.peer.device_info.address.clone();
                    unsubscribe_and_disconnect(verifier_address, central).await;
                },
                OnConflict::ReplaceIfSameFlow,
                true,
            )
            .await
            .value_or(VerificationProtocolError::Failed(
                "ble is busy with other flow".into(),
            ))
            .await
            .and_then(|(_, join_result)| {
                join_result.ok_or(VerificationProtocolError::Failed("task aborted".into()))
            })
            .and_then(std::convert::identity);

        match result {
            Ok((verifier_identifier, interaction)) => {
                self.interaction_repository
                    .update_interaction(interaction.into())
                    .await
                    .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;
                Ok(verifier_identifier)
            }
            Err(err) => {
                if let Err(err) = self
                    .proof_repository
                    .update_proof(
                        &proof_id,
                        UpdateProofRequest {
                            state: Some(ProofStateEnum::Error),
                            ..Default::default()
                        },
                        Some(HistoryErrorMetadata {
                            error_code: err.error_code(),
                            message: err.to_string(),
                        }),
                    )
                    .await
                {
                    tracing::warn!("failed setting proof to error: {err}");
                }
                Err(err)
            }
        }
    }

    pub(crate) async fn disconnect_from_verifier(&self) {
        self.ble.abort(Abort::Flow(*OIDC_BLE_FLOW)).await;
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub(crate) async fn submit_presentation(
        &self,
        vp_token: String,
        presentation_submission: PresentationSubmissionMappingDTO,
        interaction: &BLEOpenID4VPInteractionData,
    ) -> Result<(), VerificationProtocolError> {
        self.ble
            .schedule_continuation(
                interaction.task_id,
                {
                    let peer_address = interaction.peer.device_info.address.clone();
                    let interaction = interaction.clone();

                    |_, central, _| async move {
                        let cloned_central = central.clone();

                        let result = select! {
                            biased;

                            _ = verifier_disconnect_event(central.clone(), interaction.peer.device_info.address.clone()) => {
                                Err(VerificationProtocolError::Failed("Verifier disconnected".into()))
                            },
                            result = async move {
                                let response = BleOpenId4VpResponse {
                                    vp_token,
                                    presentation_submission,
                                };

                                let enc_payload = interaction.peer
                                    .encrypt(&response)
                                    .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;

                                let chunks =
                                    Chunks::from_bytes(&enc_payload[..], interaction.peer.device_info.mtu());

                                let payload_len = (chunks.len() as u16).to_be_bytes();
                                send(
                                    CONTENT_SIZE_UUID,
                                    &payload_len,
                                    &interaction.peer,
                                    &*cloned_central,
                                    CharacteristicWriteType::WithResponse,
                                )
                                .await?;

                                for chunk in &chunks {
                                    send(
                                        SUBMIT_VC_UUID,
                                        &chunk.to_bytes(),
                                        &interaction.peer,
                                        &*cloned_central,
                                        CharacteristicWriteType::WithoutResponse,
                                    )
                                    .await?;
                                }

                                // Wait to ensure the verifier has received and processed all chunks
                                tokio::time::sleep(Duration::from_millis(500)).await;

                                let missing_chunks = get_transfer_summary(&interaction.peer, &*cloned_central).await?;

                                if !missing_chunks.is_empty() {
                                    tracing::debug!("Resubmitting {} chunks", missing_chunks.len());
                                    for chunk in chunks.iter().filter(|chunk| missing_chunks.contains(&chunk.index)) {
                                        send(
                                            SUBMIT_VC_UUID,
                                            &chunk.to_bytes(),
                                            &interaction.peer,
                                            &*cloned_central,
                                            CharacteristicWriteType::WithoutResponse,
                                        )
                                        .await?;
                                    }
                                }
                                Ok::<_, VerificationProtocolError>(())
                            } => result
                        };

                        // Give some to the verifier to read everything
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        unsubscribe_and_disconnect(peer_address, central).await;
                        result
                    }
                },
                {
                    let peer = interaction.peer.clone();
                    move |central, _| async move {
                        let verifier_address = peer.device_info.address.clone();
                        unsubscribe_and_disconnect(verifier_address, central).await;
                    }
                },
                false,
            )
            .await
            .value_or(VerificationProtocolError::Failed(
                "ble is busy with other flow".into(),
            ))
            .await
            .and_then(|(_, join_result)| {
                join_result.ok_or(VerificationProtocolError::Failed("task aborted".into()))
            })
            .and_then(std::convert::identity)
    }
}
async fn unsubscribe_and_disconnect(peer_address: DeviceAddress, central: Arc<dyn BleCentral>) {
    if let Err(err) = unsubscribe_from_characteristic_notifications(&*central, &peer_address).await
    {
        tracing::warn!("Failed to unsubscribe from characteristic notifications: {err}");
    }

    if let Err(err) = central.disconnect(peer_address).await {
        tracing::warn!("Failed to disconnect BLE central: {err}");
    }
}

#[tracing::instrument(level = "debug", skip(ble_central), err(Debug))]
async fn connect_to_verifier(
    name: &str,
    public_key: &[u8],
    ble_central: &dyn BleCentral,
) -> Result<DeviceInfo, VerificationProtocolError> {
    if ble_central
        .is_scanning()
        .await
        .context("is_discovering failed")
        .map_err(VerificationProtocolError::Transport)?
    {
        ble_central
            .stop_scan()
            .await
            .context("stop_discovery failed")
            .map_err(VerificationProtocolError::Transport)?;
    }
    tracing::debug!("start_scan");
    ble_central
        .start_scan(Some(vec![SERVICE_UUID.to_string()]))
        .await
        .context("start_discovery failed")
        .map_err(VerificationProtocolError::Transport)?;

    tracing::debug!("Started scanning");

    loop {
        let discovered = ble_central
            .get_discovered_devices()
            .await
            .context("get_discovered_devices failed")
            .map_err(VerificationProtocolError::Transport)?;
        tracing::debug!("Discovered: {}", discovered.len());

        for device in discovered {
            tracing::debug!(
                "local_device_name_matches: {:?} == {name}",
                device.local_device_name
            );

            let local_device_name_matches = device
                .local_device_name
                .map(|advertised_name| advertised_name == name)
                .unwrap_or(false);

            if local_device_name_matches {
                ble_central
                    .stop_scan()
                    .await
                    .context("stop_discovery failed")
                    .map_err(VerificationProtocolError::Transport)?;

                let mtu = ble_central
                    .connect(device.device_address.clone())
                    .await
                    .context("connect failed")
                    .map_err(VerificationProtocolError::Transport)?;

                tracing::debug!("Connected to `{name}`, MTU: {mtu}");

                return Ok(DeviceInfo::new(device.device_address, mtu));
            }
        }
    }
}

async fn subscribe_to_notifications(
    ble_central: &dyn BleCentral,
    verifier_address: &str,
) -> Result<(), VerificationProtocolError> {
    ble_central
        .subscribe_to_characteristic_notifications(
            verifier_address.to_string(),
            SERVICE_UUID.to_string(),
            DISCONNECT_UUID.to_string(),
        )
        .await
        .context("failed to subscribe to disconnect notifications")
        .map_err(VerificationProtocolError::Transport)?;

    ble_central
        .subscribe_to_characteristic_notifications(
            verifier_address.to_string(),
            SERVICE_UUID.to_string(),
            TRANSFER_SUMMARY_REPORT_UUID.to_string(),
        )
        .await
        .context("failed to subscribe to summary report notifications")
        .map_err(VerificationProtocolError::Transport)?;

    Ok(())
}

async fn unsubscribe_from_characteristic_notifications(
    ble_central: &dyn BleCentral,
    verifier_address: &str,
) -> Result<(), VerificationProtocolError> {
    ble_central
        .unsubscribe_from_characteristic_notifications(
            verifier_address.to_string(),
            SERVICE_UUID.to_string(),
            DISCONNECT_UUID.to_string(),
        )
        .await
        .context("failed to unsubscribe from disconnect notification")
        .map_err(VerificationProtocolError::Transport)?;

    ble_central
        .unsubscribe_from_characteristic_notifications(
            verifier_address.to_string(),
            SERVICE_UUID.to_string(),
            TRANSFER_SUMMARY_REPORT_UUID.to_string(),
        )
        .await
        .context("failed to unsubscribe from summary report notification")
        .map_err(VerificationProtocolError::Transport)?;

    Ok(())
}

async fn verifier_disconnect_event(
    ble_central: Arc<dyn BleCentral>,
    verifier_address: String,
) -> Result<(), VerificationProtocolError> {
    loop {
        let notification = ble_central
            .get_notifications(
                verifier_address.clone(),
                SERVICE_UUID.to_string(),
                DISCONNECT_UUID.to_string(),
            )
            .await
            .context("failed to get disconnect notifications")
            .map_err(VerificationProtocolError::Transport)?;

        if !notification.is_empty() {
            return Ok(());
        }
    }
}

fn session_key_and_identity_request(
    verifier_device: DeviceInfo,
    verifier_public_key: [u8; 32],
) -> Result<(IdentityRequest, BLEPeer), VerificationProtocolError> {
    let key_agreement_key = KeyAgreementKey::new_random();
    let public_key = key_agreement_key.public_key_bytes();
    let nonce = generate_random_bytes::<12>();

    let (receiver_key, sender_key) = key_agreement_key
        .derive_session_secrets(verifier_public_key, nonce)
        .map_err(VerificationProtocolError::Transport)?;

    Ok((
        IdentityRequest {
            nonce,
            key: public_key,
        },
        BLEPeer::new(verifier_device, sender_key, receiver_key, nonce),
    ))
}

#[tracing::instrument(level = "debug", skip(ble_central), err(Debug))]
async fn send(
    id: &str,
    data: &[u8],
    verifier: &BLEPeer,
    ble_central: &dyn BleCentral,
    write_type: CharacteristicWriteType,
) -> Result<(), VerificationProtocolError> {
    ble_central
        .write_data(
            verifier.device_info.address.clone(),
            SERVICE_UUID.to_string(),
            id.to_string(),
            data,
            write_type,
        )
        .await
        .context("write_data failed")
        .map_err(VerificationProtocolError::Transport)
}

#[tracing::instrument(level = "debug", skip(ble_central, verification_fn), err(Debug))]
async fn read_presentation_request(
    connected_verifier: &BLEPeer,
    verification_fn: VerificationFn,
    ble_central: Arc<dyn BleCentral>,
) -> Result<OpenID4VP20AuthorizationRequest, VerificationProtocolError> {
    let request_size: MessageSize =
        read(REQUEST_SIZE_UUID, connected_verifier, ble_central.clone())
            .parse()
            .map_err(VerificationProtocolError::Transport)
            .await?;

    tracing::debug!("Request size {request_size}");

    let message_stream = read(
        PRESENTATION_REQUEST_UUID,
        connected_verifier,
        ble_central.clone(),
    );
    tokio::pin!(message_stream);

    let mut notification = ble_central.get_notifications(
        connected_verifier.device_info.address.clone(),
        SERVICE_UUID.to_string(),
        TRANSFER_SUMMARY_REPORT_UUID.to_string(),
    );

    let mut received_chunks: Vec<Chunk> = vec![];

    loop {
        tokio::select! {
           biased;

           Some(chunk) = message_stream.next(), if received_chunks.len() < request_size.into() => {
                let chunk = chunk.context("Reading presentation request chunk failed").map_err(VerificationProtocolError::Transport)?;
                let chunk = Chunk::from_bytes(chunk.as_slice()).map_err(VerificationProtocolError::Transport)?;
                if received_chunks.iter().any(|c| c.index == chunk.index) {
                    continue;
                } else {
                    received_chunks.push(chunk);
                }
            },
            _ = &mut notification => {
                let missing_chunks = (1..request_size)
                    .filter(|idx| !received_chunks.iter().any(|c| c.index == *idx))
                    .map(|idx| idx.to_be_bytes())
                    .collect::<Vec<[u8; 2]>>()
                    .concat();

                send(
                    TRANSFER_SUMMARY_REQUEST_UUID,
                    missing_chunks.as_ref(),
                    connected_verifier,
                    &*ble_central,
                    CharacteristicWriteType::WithResponse,
                ).await?;

                tracing::debug!(
                    "Sent TRANSFER_SUMMARY_REQUEST_UUID",
                );

                if missing_chunks.is_empty() {
                    break;
                };
            }
        }
    }

    if received_chunks.len() as u16 != request_size {
        return Err(VerificationProtocolError::Failed(
            "not all chunks received".to_string(),
        ));
    }

    received_chunks.sort_by(|a, b| a.index.cmp(&b.index));

    let presentation_request: Vec<u8> = received_chunks
        .into_iter()
        .flat_map(|c| c.payload)
        .collect();

    let decrypted_request_jwt: String =
        connected_verifier
            .decrypt(&presentation_request)
            .map_err(|e| {
                VerificationProtocolError::Failed(format!(
                    "Failed to decrypt presentation request: {e}"
                ))
            })?;

    let authz_request = Jwt::<OpenID4VP20AuthorizationRequest>::build_from_token(
        &decrypted_request_jwt,
        Some(&verification_fn),
        None,
    )
    .await
    .map_err(|e| {
        VerificationProtocolError::Failed(format!("Failed to parse presentation request: {e}"))
    })?;
    Ok(authz_request.payload.custom)
}

pub(crate) fn read(
    id: &str,
    wallet: &BLEPeer,
    ble_central: Arc<dyn BleCentral>,
) -> impl Stream<Item = Result<Vec<u8>, BleError>> + Send {
    futures::stream::unfold(
        (
            wallet.device_info.address.clone(),
            id.to_string(),
            ble_central,
            vec![],
        ),
        move |(address, id, ble_central, previous_message)| async move {
            loop {
                let data = ble_central
                    .read_data(address.clone(), SERVICE_UUID.to_string(), id.clone())
                    .await;

                if let Ok(data) = data.as_ref() {
                    if previous_message.eq(data) {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                }

                return Some((
                    data.clone(),
                    (address, id, ble_central, data.unwrap_or_default()),
                ));
            }
        },
    )
}

#[tracing::instrument(level = "debug", skip(ble_central) err(Debug))]
async fn get_transfer_summary(
    connected_verifier: &BLEPeer,
    ble_central: &dyn BleCentral,
) -> Result<Vec<u16>, VerificationProtocolError> {
    send(
        TRANSFER_SUMMARY_REQUEST_UUID,
        &[],
        connected_verifier,
        ble_central,
        CharacteristicWriteType::WithResponse,
    )
    .await?;

    let report = ble_central
        .get_notifications(
            connected_verifier.device_info.address.clone(),
            SERVICE_UUID.to_string(),
            TRANSFER_SUMMARY_REPORT_UUID.to_string(),
        )
        .await
        .context("get_notifications failed")
        .map_err(VerificationProtocolError::Transport)?;

    let report: TransferSummaryReport = stream::iter(report)
        .map(Ok)
        .boxed()
        .parse()
        .map_err(VerificationProtocolError::Transport)
        .await?;

    Ok(report)
}
