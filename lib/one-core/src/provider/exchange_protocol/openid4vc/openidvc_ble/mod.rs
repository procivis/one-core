use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use futures::future::{BoxFuture, Shared};
use futures::{Stream, TryStreamExt};
use oidc_ble_holder::OpenID4VCBLEHolder;
use oidc_ble_verifier::OpenID4VCBLEVerifier;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use super::dto::OpenID4VPBleData;
use super::key_agreement_key::KeyAgreementKey;
use super::mapper::create_presentation_submission;
use super::model::BLEOpenID4VPInteractionData;
use super::openidvc_http::mappers::map_credential_formats_to_presentation_format;
use crate::config::core_config::{self, TransportType};
use crate::model::did::Did;
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::bluetooth_low_energy::low_level::dto::DeviceInfo;
use crate::provider::bluetooth_low_energy::BleError;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    OID4VPHandover, SessionTranscript,
};
use crate::provider::credential_formatter::model::FormatPresentationCtx;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::exchange_protocol::iso_mdl::common::to_cbor;
use crate::provider::exchange_protocol::mapper::proof_from_handle_invitation;
use crate::provider::exchange_protocol::openid4vc::mapper::create_open_id_for_vp_presentation_definition;
use crate::provider::exchange_protocol::openid4vc::model::{
    InvitationResponseDTO, PresentedCredential, UpdateResponse,
};
use crate::provider::exchange_protocol::openid4vc::peer_encryption::PeerEncryption;
use crate::provider::exchange_protocol::openid4vc::{FormatMapper, TypeToDescriptorMapper};
use crate::provider::exchange_protocol::{deserialize_interaction_data, ExchangeProtocolError};
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::util::ble_resource::{Abort, BleWaiter};
use crate::util::oidc::create_core_to_oicd_format_map;

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

pub type MessageSize = u16;

// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#name-transfer-summary-report
pub(crate) type TransferSummaryReport = Vec<u16>;

// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#section-5.3
#[derive(Clone, Debug)]
pub struct IdentityRequest {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

impl IdentityRequest {
    pub fn encode(self) -> Vec<u8> {
        self.key
            .iter()
            .chain(&self.nonce)
            .copied()
            .collect::<Vec<u8>>()
    }
}

#[async_trait::async_trait]
pub trait BLEParse<T, Error> {
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
pub struct BLEPeer {
    pub device_info: DeviceInfo,
    peer_encryption: PeerEncryption,
}

impl BLEPeer {
    pub fn new(
        device_info: DeviceInfo,
        sender_aes_key: [u8; 32],
        receiver_aes_key: [u8; 32],
        nonce: [u8; 12],
    ) -> Self {
        Self {
            device_info,
            peer_encryption: PeerEncryption::new(sender_aes_key, receiver_aes_key, nonce),
        }
    }

    pub fn encrypt<T>(&self, data: T) -> anyhow::Result<Vec<u8>>
    where
        T: Serialize,
    {
        self.peer_encryption.encrypt(&data)
    }

    pub fn decrypt<T>(&self, ciphertext: &[u8]) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
    {
        self.peer_encryption.decrypt(ciphertext)
    }
}

const PRESENTATION_DEFINITION_BLE_NAME: &str = "name";
const PRESENTATION_DEFINITION_BLE_KEY: &str = "key";

pub(crate) struct OpenID4VCBLE {
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    ble: Option<BleWaiter>,
    config: Arc<core_config::CoreConfig>,
}

impl OpenID4VCBLE {
    pub fn new(
        proof_repository: Arc<dyn ProofRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        ble: Option<BleWaiter>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            proof_repository,
            interaction_repository,
            formatter_provider,
            key_provider,
            ble,
            config,
        }
    }

    pub fn holder_can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        url.scheme() == "openid4vp"
            && query_has_key(PRESENTATION_DEFINITION_BLE_NAME)
            && query_has_key(PRESENTATION_DEFINITION_BLE_KEY)
    }

    pub async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        if !self.holder_can_handle(&url) {
            return Err(ExchangeProtocolError::Failed(
                "No OpenID4VC over BLE query params detected".to_string(),
            ));
        }

        if !self
            .config
            .transport
            .ble_enabled_for(TransportType::Ble.as_ref())
        {
            return Err(ExchangeProtocolError::Disabled(
                "BLE transport is disabled".to_string(),
            ));
        }

        let ble = self.ble.clone().ok_or_else(|| {
            ExchangeProtocolError::Failed("BLE central not available".to_string())
        })?;

        let query = url.query().ok_or(ExchangeProtocolError::InvalidRequest(
            "Query cannot be empty".to_string(),
        ))?;

        let OpenID4VPBleData { name, key } = serde_qs::from_str(query)
            .map_err(|e| ExchangeProtocolError::InvalidRequest(e.to_string()))?;

        let mut ble_holder = OpenID4VCBLEHolder::new(
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
            ble,
        );

        if !ble_holder.enabled().await? {
            return Err(ExchangeProtocolError::Disabled(
                "BLE adapter is disabled".into(),
            ));
        }

        let now = OffsetDateTime::now_utc();
        let interaction = Interaction {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            host: None,
            data: None,
            organisation: Some(organisation.clone()),
        };
        let interaction_id = self
            .interaction_repository
            .create_interaction(interaction.clone())
            .await
            .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

        let proof_id = Uuid::new_v4().into();
        let proof = proof_from_handle_invitation(
            &proof_id,
            "OPENID4VC",
            None,
            None,
            interaction,
            now,
            None,
            "BLE",
            ProofStateEnum::Requested,
        );

        ble_holder
            .handle_invitation(name, key, proof.id, interaction_id, organisation)
            .await?;

        Ok(InvitationResponseDTO::ProofRequest {
            interaction_id,
            proof: Box::new(proof),
        })
    }

    pub async fn holder_reject_proof(&self, _proof: &Proof) -> Result<(), ExchangeProtocolError> {
        let ble_holder = OpenID4VCBLEHolder::new(
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
            self.ble.clone().ok_or_else(|| {
                ExchangeProtocolError::Failed("Missing BLE central for reject proof".to_string())
            })?,
        );

        ble_holder.disconnect_from_verifier().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format_map: HashMap<String, String>,
        presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        let ble = self.ble.clone().ok_or_else(|| {
            ExchangeProtocolError::Failed("Missing BLE central for submit proof".to_string())
        })?;

        let interaction_data: BLEOpenID4VPInteractionData = deserialize_interaction_data(
            proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let ble_holder = OpenID4VCBLEHolder::new(
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
            ble,
        );

        if !ble_holder.enabled().await? {
            return Err(ExchangeProtocolError::Failed(
                "BLE adapter disabled".to_string(),
            ));
        }

        let tokens: Vec<String> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.presentation.to_owned())
            .collect();

        let token_formats: Vec<String> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.credential_schema.format.to_owned())
            .collect();

        let formats: HashMap<&str, &str> = credential_presentations
            .iter()
            .map(|presented_credential| {
                format_map
                    .get(presented_credential.credential_schema.format.as_str())
                    .map(|mapped| {
                        (
                            mapped.as_str(),
                            presented_credential.credential_schema.format.as_str(),
                        )
                    })
            })
            .collect::<Option<_>>()
            .ok_or_else(|| ExchangeProtocolError::Failed("missing format mapping".into()))?;

        let (_, format, oidc_format) =
            map_credential_formats_to_presentation_format(&formats, &format_map)?;

        let presentation_format =
            presentation_format_map
                .get(&oidc_format)
                .ok_or(ExchangeProtocolError::Failed(format!(
                    "Missing presentation format for `{oidc_format}`"
                )))?;

        let presentation_formatter = self
            .formatter_provider
            .get_formatter(presentation_format)
            .ok_or_else(|| ExchangeProtocolError::Failed("Formatter not found".to_string()))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(key, jwk_key_id)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let presentation_definition_id = interaction_data
            .presentation_definition
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "Missing presentation definition".into(),
            ))?
            .id;

        let presentation_submission = create_presentation_submission(
            presentation_definition_id,
            credential_presentations,
            &oidc_format,
            create_core_to_oicd_format_map(),
        )?;

        let mut ctx = FormatPresentationCtx {
            nonce: interaction_data.nonce.clone(),
            token_formats: Some(token_formats),
            vc_format_map: format_map,
            ..Default::default()
        };

        if format == "MDOC" {
            let mdoc_generated_nonce = interaction_data
                .identity_request_nonce
                .as_deref()
                .ok_or_else(|| {
                    ExchangeProtocolError::Failed(
                        "Cannot format MDOC - missing identity request nonce".to_string(),
                    )
                })?;
            let client_id = interaction_data.client_id.as_deref().ok_or_else(|| {
                ExchangeProtocolError::Failed("Cannot format MDOC - missing client_id".to_string())
            })?;
            let nonce = interaction_data.nonce.as_deref().ok_or_else(|| {
                ExchangeProtocolError::Failed("Cannot format MDOC - missing nonce".to_string())
            })?;

            ctx.mdoc_session_transcript = Some(
                to_cbor(&SessionTranscript {
                    handover: OID4VPHandover::compute(
                        client_id,
                        client_id,
                        nonce,
                        mdoc_generated_nonce,
                    )
                    .into(),
                    device_engagement_bytes: None,
                    e_reader_key_bytes: None,
                })
                .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?,
            );
        }

        let vp_token = presentation_formatter
            .format_presentation(&tokens, &holder_did.did, &key.key_type, auth_fn, ctx)
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        ble_holder
            .submit_presentation(vp_token, presentation_submission, &interaction_data)
            .await?;

        Ok(UpdateResponse {
            result: (),
            update_proof: None,
            create_did: None,
            update_credential: None,
            update_credential_schema: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        type_to_descriptor: TypeToDescriptorMapper,
        interaction_id: InteractionId,
        key_agreement: KeyAgreementKey,
        cancellation_token: CancellationToken,
        callback: Option<Shared<BoxFuture<'static, ()>>>,
    ) -> Result<String, ExchangeProtocolError> {
        // Pass the expected presentation content to interaction for verification
        let presentation_definition = create_open_id_for_vp_presentation_definition(
            interaction_id,
            proof,
            type_to_descriptor,
            format_to_type_mapper,
        )?;

        if !self
            .config
            .transport
            .ble_enabled_for(TransportType::Ble.as_ref())
        {
            return Err(ExchangeProtocolError::Disabled(
                "BLE transport is disabled".to_string(),
            ));
        }

        let ble = self.ble.clone().ok_or_else(|| {
            ExchangeProtocolError::Failed("BLE central not available".to_string())
        })?;

        let ble_verifier = OpenID4VCBLEVerifier::new(
            ble,
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
        )?;

        if !ble_verifier.enabled().await? {
            return Err(ExchangeProtocolError::Disabled(
                "BLE adapter is disabled".into(),
            ));
        }

        ble_verifier
            .share_proof(
                presentation_definition,
                proof.id,
                interaction_id,
                key_agreement,
                cancellation_token,
                callback,
            )
            .await
    }

    pub async fn verifier_retract_proof(&self) -> Result<(), ExchangeProtocolError> {
        self.ble
            .as_ref()
            .ok_or_else(|| ExchangeProtocolError::Failed("BLE is missing in service".to_string()))?
            .abort(Abort::Flow(*OIDC_BLE_FLOW))
            .await;

        Ok(())
    }
}
