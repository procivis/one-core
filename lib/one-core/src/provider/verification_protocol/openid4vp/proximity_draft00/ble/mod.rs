//! OpenID4VP over BLE implementation
//! https://openid.net/specs/openid-4-verifiable-presentations-over-ble-1_0.html

use std::sync::LazyLock;

use anyhow::{Result, anyhow};
use futures::{Stream, TryStreamExt};
use secrecy::SecretSlice;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::dto::MessageSize;
use super::peer_encryption::PeerEncryption;
use crate::provider::bluetooth_low_energy::BleError;
use crate::provider::bluetooth_low_energy::low_level::dto::DeviceInfo;
pub mod dto;
pub mod mappers;
pub mod model;
pub mod oidc_ble_holder;
pub mod oidc_ble_verifier;

// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#section-10
pub const SERVICE_UUID: &str = "00000001-5026-444A-9E0E-D6F2450F3A77";
pub const REQUEST_SIZE_UUID: &str = "00000004-5026-444A-9E0E-D6F2450F3A77";
pub const PRESENTATION_REQUEST_UUID: &str = "00000005-5026-444A-9E0E-D6F2450F3A77";
pub const IDENTITY_UUID: &str = "00000006-5026-444A-9E0E-D6F2450F3A77";
pub const CONTENT_SIZE_UUID: &str = "00000007-5026-444A-9E0E-D6F2450F3A77";
pub const SUBMIT_VC_UUID: &str = "00000008-5026-444A-9E0E-D6F2450F3A77";
pub const TRANSFER_SUMMARY_REQUEST_UUID: &str = "00000009-5026-444A-9E0E-D6F2450F3A77";
pub const TRANSFER_SUMMARY_REPORT_UUID: &str = "0000000A-5026-444A-9E0E-D6F2450F3A77";
pub const DISCONNECT_UUID: &str = "0000000B-5026-444A-9E0E-D6F2450F3A77";

pub static OIDC_BLE_FLOW: LazyLock<Uuid> = LazyLock::new(Uuid::new_v4);

// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#name-transfer-summary-report
pub(crate) type TransferSummaryReport = Vec<u16>;

// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#section-5.3
#[derive(Clone, Debug)]
pub(crate) struct IdentityRequest {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

impl IdentityRequest {
    pub(crate) fn encode(self) -> Vec<u8> {
        self.key
            .iter()
            .chain(&self.nonce)
            .copied()
            .collect::<Vec<u8>>()
    }
}

#[async_trait::async_trait]
pub(crate) trait BLEParse<T, Error> {
    async fn parse(self) -> Result<T, Error>;
}

#[async_trait::async_trait]
impl<T> BLEParse<TransferSummaryReport, anyhow::Error> for T
where
    T: Stream<Item = Result<Vec<u8>, BleError>> + Send,
{
    async fn parse(self) -> Result<TransferSummaryReport> {
        tokio::pin!(self);
        let data = self
            .try_next()
            .await?
            .ok_or(anyhow!("Failed to read transfer summary report"))?;

        data.chunks(2)
            .map(|chunk| {
                Ok(u16::from_be_bytes(chunk.try_into().map_err(|_| {
                    anyhow!("Failed to convert chunk to [u8; 2]")
                })?))
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl<T> BLEParse<MessageSize, anyhow::Error> for T
where
    T: Stream<Item = Result<Vec<u8>, BleError>> + Send,
{
    async fn parse(self) -> Result<u16> {
        tokio::pin!(self);
        let data = self
            .try_next()
            .await?
            .ok_or(anyhow!("Failed to read message size"))?;

        let arr = data
            .try_into()
            .map_err(|_| anyhow!("cannot convert request to [u8; 2]"))?;

        Ok(u16::from_be_bytes(arr))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct BLEPeer {
    pub device_info: DeviceInfo,
    peer_encryption: PeerEncryption,
}

impl BLEPeer {
    pub(crate) fn new(
        device_info: DeviceInfo,
        sender_aes_key: SecretSlice<u8>,
        receiver_aes_key: SecretSlice<u8>,
        nonce: [u8; 12],
    ) -> Self {
        Self {
            device_info,
            peer_encryption: PeerEncryption::new(sender_aes_key, receiver_aes_key, nonce),
        }
    }

    pub(crate) fn encrypt<T>(&self, data: &T) -> anyhow::Result<Vec<u8>>
    where
        T: Serialize,
    {
        self.peer_encryption.encrypt(data)
    }

    pub(crate) fn decrypt<T>(&self, ciphertext: &[u8]) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
    {
        self.peer_encryption.decrypt(ciphertext)
    }
}
