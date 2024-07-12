use crate::{
    model::proof::{self, ProofState},
    provider::{
        bluetooth_low_energy::low_level::{
            ble_peripheral::BlePeripheral,
            dto::{
                CharacteristicPermissions, CharacteristicProperties, ConnectionEvent,
                CreateCharacteristicOptions, DeviceInfo, ServiceDescription,
            },
        },
        exchange_protocol::{
            openid4vc::{
                dto::{ChunkExt, Chunks, OpenID4VPPresentationDefinition},
                openidvc_ble::BLEParse,
            },
            ExchangeProtocolError,
        },
    },
    repository::proof_repository::ProofRepository,
};
use anyhow::anyhow;
use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt, TryFutureExt};
use one_providers::crypto::imp::utilities;
use shared_types::ProofId;
use std::{sync::Arc, time::Duration};
use time::OffsetDateTime;

use super::{
    BLEPeer, BLEStream, IdentityRequest, KeyAgreementKey, TransferSummaryReport, CONTENT_SIZE_UUID,
    DISCONNECT_UUID, IDENTITY_UUID, PRESENTATION_REQUEST_UUID, REQUEST_SIZE_UUID, SERVICE_UUID,
    SUBMIT_VC_UUID, TRANSFER_SUMMARY_REPORT_UUID, TRANSFER_SUMMARY_REQUEST_UUID,
};

pub struct OpenID4VCBLEVerifier {
    pub(crate) ble_peripheral: Arc<dyn BlePeripheral>,
    pub proof_repository: Arc<dyn ProofRepository>,
    connected_wallet: Option<BLEPeer>,
}

impl OpenID4VCBLEVerifier {
    pub fn new(
        ble_peripheral: Arc<dyn BlePeripheral>,
        proof_repository: Arc<dyn ProofRepository>,
    ) -> Result<Self, ExchangeProtocolError> {
        Ok(Self {
            ble_peripheral,
            connected_wallet: None,
            proof_repository,
        })
    }

    // The native implementation is loaded lazily. It sometimes happens that
    // on the first call to this method, the native implementation is not loaded yet.
    // This causes the method to return false even though the adapter is enabled.
    // To work around this, we retry the call after a short delay.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn enabled(&self) -> Result<bool, ExchangeProtocolError> {
        let enabled = self
            .ble_peripheral
            .is_adapter_enabled()
            .await
            .unwrap_or(false);

        if enabled {
            return Ok(true);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
        return self
            .ble_peripheral
            .is_adapter_enabled()
            .await
            .map_err(|err| ExchangeProtocolError::Transport(err.into()));
    }

    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn share_proof(
        mut self,
        proof_request: OpenID4VPPresentationDefinition,
        proof_id: ProofId,
    ) -> Result<String, ExchangeProtocolError> {
        let keypair = KeyAgreementKey::new_random();
        let qr_url = self.start_advertisement(keypair.public_key_bytes()).await?;

        tokio::spawn(async move {
            // TODO
            // select between this future driving the main flow and a timeout future
            // select between this future driving the main flow and a disconnect event future
            let result: Result<(), ExchangeProtocolError> = async {
                let (wallet, identity_request) = self.wait_for_wallet_identify_request().await?;

                let (sender_key, receiver_key) = keypair
                    .derive_session_secrets(identity_request.key, identity_request.nonce)
                    .map_err(ExchangeProtocolError::Transport)?;

                self.connected_wallet = Some(BLEPeer::new(
                    wallet,
                    sender_key,
                    receiver_key,
                    identity_request.nonce,
                ));

                self.write_presentation_request(proof_request).await
            }
            .await;

            let _ = self.ble_peripheral.stop_server().await;
            if result.is_err() {
                let now = OffsetDateTime::now_utc();
                let _ = self
                    .proof_repository
                    .set_proof_state(
                        &proof_id,
                        ProofState {
                            state: proof::ProofStateEnum::Error,
                            created_date: now,
                            last_modified: now,
                        },
                    )
                    .await;
            };
        });

        Ok(qr_url)
    }

    #[tracing::instrument(level = "debug", skip(self))]
    async fn start_advertisement(
        &self,
        public_key: [u8; 32],
    ) -> Result<String, ExchangeProtocolError> {
        if self.ble_peripheral.is_advertising().await.map_err(|e| {
            ExchangeProtocolError::Transport(anyhow!("Failed to check BLE advertising status: {e}"))
        })? {
            self.ble_peripheral
                .stop_advertisement()
                .await
                .map_err(|e| {
                    ExchangeProtocolError::Transport(anyhow!("Failed to stop BLE advertising: {e}"))
                })?;
        };

        // https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#section-5.1.1
        // The verifier can advertise via BLE only or via BLE + QR.
        // Depending on the use case, the advertised name is different.
        let (verifier_name, adv_data) = {
            let random_name = utilities::generate_alphanumeric(11);
            let adv_data = [format!("OVP{}_", random_name).as_bytes(), &public_key[..5]].concat();

            (random_name, adv_data)
        };

        self.ble_peripheral
            .start_advertisement(
                Some(verifier_name.clone()),
                vec![get_advertise_data(adv_data)],
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        Ok(format!(
            "OPENID4VP://connect?name={}&key={}",
            verifier_name,
            hex::encode(public_key)
        ))
    }

    #[tracing::instrument(skip(self))]
    async fn wait_for_wallet_identify_request(
        &self,
    ) -> Result<(DeviceInfo, IdentityRequest), ExchangeProtocolError> {
        let mut identify_futures = FuturesUnordered::new();

        let holder_wallet = loop {
            tokio::select! {
               Some(wallet_info) = identify_futures.next() => {
                    break wallet_info;
                },
                connection_events = self.ble_peripheral.get_connection_change_events() => {
                    for event in connection_events.map_err(|e| {
                        ExchangeProtocolError::Transport(anyhow!(
                            "Failed to get BLE connection events: {e}"
                        ))
                    })? {
                        if let ConnectionEvent::Connected { device_info } = event {
                            identify_futures.push(async {
                                    let stream = self.read(IDENTITY_UUID, Some(device_info.address.clone()))?;
                                    let identity_request = stream.parse().map_err(ExchangeProtocolError::Transport).await?;
                                    Ok((device_info, identity_request))
                            });
                        } else {
                            continue;
                        }
                    }
                },
            };
        };
        self.ble_peripheral
            .stop_advertisement()
            .await
            .map_err(|e| {
                ExchangeProtocolError::Transport(anyhow!("Failed to stop advertisement: {e}"))
            })?;

        holder_wallet
    }
    async fn write_presentation_request(
        &self,
        proof_request: OpenID4VPPresentationDefinition,
    ) -> Result<(), ExchangeProtocolError> {
        let peer = self
            .connected_wallet
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "Wallet is not connected".to_string(),
            ))?;

        let encrypted = peer.encrypt(proof_request).map_err(|e| {
            ExchangeProtocolError::Transport(anyhow!("Failed to encrypt proof request: {e}"))
        })?;

        let chunks = Chunks::from_bytes(encrypted.as_slice(), peer.device_info.mtu);
        let len = (chunks.len() as u16).to_be_bytes();

        self.send(REQUEST_SIZE_UUID, &len).await?;
        self.write_chunks_with_report(chunks).await
    }

    async fn request_write_report(&self) -> Result<Vec<u16>, ExchangeProtocolError> {
        let device_address = self
            .connected_wallet
            .as_ref()
            .map(|peer| peer.device_info.address.clone())
            .ok_or(ExchangeProtocolError::Failed(
                "Wallet is not connected".to_string(),
            ))?;

        self.ble_peripheral
            .notify_characteristic_data(
                device_address,
                SERVICE_UUID.into(),
                TRANSFER_SUMMARY_REPORT_UUID.into(),
                &[],
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let report_bytes: TransferSummaryReport = self
            .read(TRANSFER_SUMMARY_REQUEST_UUID, None)?
            .parse()
            .map_err(ExchangeProtocolError::Transport)
            .await?;

        Ok(report_bytes)
    }

    fn write_chunks_with_report(
        &self,
        chunks: Chunks,
    ) -> BoxFuture<'_, Result<(), ExchangeProtocolError>> {
        return async move {
            for chunk in chunks.iter() {
                self.send(PRESENTATION_REQUEST_UUID, chunk.to_bytes().as_slice())
                    .await?
            }

            let missed_chunks = self.request_write_report().await?;
            let to_resend = chunks
                .into_iter()
                .filter(|chunk| missed_chunks.contains(&{ chunk.index }))
                .collect::<Vec<_>>();

            if to_resend.is_empty() {
                return Ok(());
            }

            self.write_chunks_with_report(to_resend).await?;

            Ok(())
        }
        .boxed();
    }
}

fn get_advertise_data(service_name: Vec<u8>) -> ServiceDescription {
    let read_characteristics = vec![REQUEST_SIZE_UUID, PRESENTATION_REQUEST_UUID];
    let write_characteristics = vec![
        IDENTITY_UUID,
        CONTENT_SIZE_UUID,
        SUBMIT_VC_UUID,
        TRANSFER_SUMMARY_REQUEST_UUID,
    ];

    let notify_characteristics = vec![TRANSFER_SUMMARY_REPORT_UUID, DISCONNECT_UUID];
    let characteristics = read_characteristics
        .into_iter()
        .map(|uuid| CreateCharacteristicOptions {
            uuid: uuid.to_string(),
            permissions: vec![CharacteristicPermissions::Read],
            properties: vec![CharacteristicProperties::Read],
            initial_value: None,
        })
        .chain(
            write_characteristics
                .into_iter()
                .map(|uuid| CreateCharacteristicOptions {
                    uuid: uuid.to_string(),
                    permissions: vec![CharacteristicPermissions::Write],
                    properties: vec![
                        CharacteristicProperties::Write,
                        CharacteristicProperties::WriteWithoutResponse,
                    ],
                    initial_value: None,
                }),
        )
        .chain(
            notify_characteristics
                .into_iter()
                .map(|uuid| CreateCharacteristicOptions {
                    uuid: uuid.to_string(),
                    permissions: vec![CharacteristicPermissions::Read],
                    properties: vec![
                        CharacteristicProperties::Read,
                        CharacteristicProperties::Notify,
                    ],
                    initial_value: None,
                }),
        )
        .collect();

    ServiceDescription {
        uuid: SERVICE_UUID.to_string(),
        advertise: true,
        advertised_service_data: Some(service_name),
        characteristics,
    }
}

impl OpenID4VCBLEVerifier {
    // The optional wallet address can be used to read before a device is connected
    pub fn read(
        &self,
        id: &str,
        wallet_address: Option<String>,
    ) -> Result<BLEStream, ExchangeProtocolError> {
        let address = self
            .connected_wallet
            .as_ref()
            .map(|wallet| wallet.device_info.address.clone())
            .or(wallet_address)
            .ok_or(ExchangeProtocolError::Failed(
                "Wallet is not connected".to_string(),
            ))?;

        Ok(Box::pin(futures::stream::unfold(
            (address, id.to_string(), self.ble_peripheral.clone()),
            move |(address, id, ble_peripheral)| async move {
                let data = ble_peripheral
                    .get_characteristic_writes(
                        address.clone(),
                        SERVICE_UUID.to_string(),
                        id.clone(),
                    )
                    .await
                    .map(|data| data.concat());

                Some((data, (address, id, ble_peripheral)))
            },
        )))
    }

    pub async fn send(&self, id: &str, data: &[u8]) -> Result<(), ExchangeProtocolError> {
        let wallet = self
            .connected_wallet
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "Wallet is not connected".to_string(),
            ))?;

        self.ble_peripheral
            .set_characteristic_data(SERVICE_UUID.to_string(), id.to_string(), data)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
            .await?;

        self.ble_peripheral
            .wait_for_characteristic_read(
                wallet.device_info.address.to_string(),
                SERVICE_UUID.to_string(),
                id.to_string(),
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
    }
}
