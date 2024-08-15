use std::time::Duration;

use anyhow::Context;
use futures::{stream, StreamExt, TryFutureExt};
use one_providers::exchange_protocol::openid4vc::model::PresentationSubmissionMappingDTO;

use crate::provider::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::provider::bluetooth_low_energy::low_level::dto::CharacteristicWriteType;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::Bstr;
use crate::provider::exchange_protocol::iso_mdl::common::to_cbor;
use crate::provider::exchange_protocol::iso_mdl::session::{SessionData, StatusCode};
use crate::provider::exchange_protocol::openid4vc::dto::{ChunkExt, Chunks};
use crate::provider::exchange_protocol::openid4vc::model::{
    BLEOpenID4VPInteractionData, BleOpenId4VpResponse,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::TRANSFER_SUMMARY_REQUEST_UUID;
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::{
    BLEParse, BLEPeer, TransferSummaryReport, CONTENT_SIZE_UUID, SERVICE_UUID, SUBMIT_VC_UUID,
    TRANSFER_SUMMARY_REPORT_UUID,
};
use crate::provider::exchange_protocol::ExchangeProtocolError;
use crate::util::ble_resource::BleWaiter;

pub struct IsoMdlBleHolder {
    pub ble: BleWaiter,
}

impl IsoMdlBleHolder {
    pub fn new(ble: BleWaiter) -> Self {
        Self { ble }
    }

    // The native implementation is loaded lazily. It sometimes happens that
    // on the first call to this method, the native implementation is not loaded yet.
    // This causes the method to return false even though the adapter is enabled.
    // To work around this, we retry the call after a short delay.
    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn enabled(&self) -> Result<bool, ExchangeProtocolError> {
        let enabled = self
            .ble
            .is_enabled()
            .await
            .map(|s| s.central)
            .unwrap_or(false);

        if enabled {
            return Ok(true);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
        self.ble
            .is_enabled()
            .await
            .map(|s| s.central)
            .map_err(|err| ExchangeProtocolError::Transport(err.into()))
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn submit_presentation(
        &self,
        vp_token: String,
        presentation_submission: PresentationSubmissionMappingDTO,
        interaction: &BLEOpenID4VPInteractionData,
    ) -> Result<(), ExchangeProtocolError> {
        self.ble
            .schedule_continuation(
                interaction.task_id,
                {
                    let peer = interaction.peer.clone();
                    move |_, central, peripheral| {
                        async move {
                            let response = BleOpenId4VpResponse {
                                vp_token,
                                presentation_submission,
                            };

                            let session_data = SessionData {
                                data: Some(Bstr(to_cbor(&response)?)),
                                status: Some(StatusCode::SessionTermination),
                            };

                            let enc_payload = peer
                                .encrypt(session_data)
                                .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

                            let chunks =
                                Chunks::from_bytes(&enc_payload[..], peer.device_info.mtu());

                            let payload_len = (chunks.len() as u16).to_be_bytes();
                            send(
                                CONTENT_SIZE_UUID,
                                &payload_len,
                                &peer,
                                &*central,
                                CharacteristicWriteType::WithResponse,
                            )
                            .await?;

                            for chunk in &chunks {
                                send(
                                    SUBMIT_VC_UUID,
                                    &chunk.to_bytes(),
                                    &peer,
                                    &*central,
                                    CharacteristicWriteType::WithoutResponse,
                                )
                                .await?;
                            }

                            // Wait to ensure the verifier has received and processed all chunks
                            tokio::time::sleep(Duration::from_millis(500)).await;

                            let missing_chunks = get_transfer_summary(&peer, &*central).await?;

                            if !missing_chunks.is_empty() {
                                return Err(ExchangeProtocolError::Failed(
                                    "did not send all chunks".to_string(),
                                ));
                            }

                            // Give some to the verifier to read everything
                            tokio::time::sleep(Duration::from_secs(1)).await;

                            let _ = central.disconnect(peer.device_info.address.clone()).await;

                            peripheral
                                .stop_server()
                                .await
                                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

                            Ok::<_, ExchangeProtocolError>(())
                        }
                    }
                },
                {
                    let peer = interaction.peer.clone();
                    move |central, peripheral| async move {
                        let _ = central.disconnect(peer.device_info.address.clone()).await;
                        let _ = peripheral.stop_server().await;
                    }
                },
                false,
            )
            .await
            .value_or(ExchangeProtocolError::Failed(
                "ble is busy with other flow".into(),
            ))
            .await
            .and_then(|(_, join_result)| {
                join_result.ok_or(ExchangeProtocolError::Failed("task aborted".into()))
            })
            .and_then(std::convert::identity)
    }
}

#[tracing::instrument(level = "debug", skip(ble_central), err(Debug))]
async fn send(
    id: &str,
    data: &[u8],
    verifier: &BLEPeer,
    ble_central: &dyn BleCentral,
    write_type: CharacteristicWriteType,
) -> Result<(), ExchangeProtocolError> {
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
        .map_err(ExchangeProtocolError::Transport)
}

#[tracing::instrument(level = "debug", skip(ble_central) err(Debug))]
async fn get_transfer_summary(
    connected_verifier: &BLEPeer,
    ble_central: &dyn BleCentral,
) -> Result<Vec<u16>, ExchangeProtocolError> {
    ble_central
        .subscribe_to_characteristic_notifications(
            connected_verifier.device_info.address.clone(),
            SERVICE_UUID.to_string(),
            TRANSFER_SUMMARY_REPORT_UUID.to_string(),
        )
        .await
        .context("subscribe_to_characteristic_notifications failed")
        .map_err(ExchangeProtocolError::Transport)?;

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
        .map_err(ExchangeProtocolError::Transport)?;

    let report: TransferSummaryReport = stream::iter(report)
        .map(Ok)
        .boxed()
        .parse()
        .map_err(ExchangeProtocolError::Transport)
        .await?;

    Ok(report)
}
