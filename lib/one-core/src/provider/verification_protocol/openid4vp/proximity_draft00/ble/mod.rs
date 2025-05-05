//! OpenID4VP over BLE implementation
//! https://openid.net/specs/openid-4-verifiable-presentations-over-ble-1_0.html

use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use dto::OpenID4VPBleData;
use futures::future::{BoxFuture, Shared};
use futures::{Stream, TryStreamExt};
use model::BLEOpenID4VPInteractionData;
use oidc_ble_holder::OpenID4VCBLEHolder;
use oidc_ble_verifier::OpenID4VCBLEVerifier;
use secrecy::SecretSlice;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use shared_types::KeyId;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use super::dto::MessageSize;
use super::peer_encryption::PeerEncryption;
use super::{
    create_interaction_and_proof, create_presentation, prepare_proof_share,
    CreatePresentationParams, KeyAgreementKey, OpenID4VPProximityDraft00Params, ProofShareParams,
};
use crate::config::core_config::{self, TransportType, VerificationProtocolType};
use crate::model::did::{Did, KeyRole};
use crate::model::interaction::InteractionId;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::bluetooth_low_energy::low_level::dto::DeviceInfo;
use crate::provider::bluetooth_low_energy::BleError;
use crate::provider::credential_formatter::model::HolderBindingCtx;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::dto::{
    InvitationResponseDTO, PresentationDefinitionResponseDTO, PresentedCredential, UpdateResponse,
};
use crate::provider::verification_protocol::openid4vp::{
    get_presentation_definition_with_local_credentials, FormatMapper, TypeToDescriptorMapper,
};
use crate::provider::verification_protocol::{
    deserialize_interaction_data, VerificationProtocolError,
};
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::storage_proxy::StorageAccess;
use crate::util::ble_resource::{Abort, BleWaiter};
use crate::util::key_verification::KeyVerification;

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

const PRESENTATION_DEFINITION_BLE_NAME: &str = "name";
const PRESENTATION_DEFINITION_BLE_KEY: &str = "key";

pub(crate) struct OpenID4VCBLE {
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    did_repository: Arc<dyn DidRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    ble: Option<BleWaiter>,
    config: Arc<core_config::CoreConfig>,
    params: OpenID4VPProximityDraft00Params,
}

impl OpenID4VCBLE {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        proof_repository: Arc<dyn ProofRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        did_repository: Arc<dyn DidRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        ble: Option<BleWaiter>,
        config: Arc<core_config::CoreConfig>,
        params: OpenID4VPProximityDraft00Params,
    ) -> Self {
        Self {
            proof_repository,
            interaction_repository,
            did_repository,
            identifier_repository,
            formatter_provider,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            ble,
            config,
            params,
        }
    }

    pub(crate) fn holder_can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        self.params.url_scheme == url.scheme()
            && query_has_key(PRESENTATION_DEFINITION_BLE_NAME)
            && query_has_key(PRESENTATION_DEFINITION_BLE_KEY)
    }

    pub(crate) async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        context: serde_json::Value,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
        let interaction_data: BLEOpenID4VPInteractionData =
            serde_json::from_value(context).map_err(VerificationProtocolError::JsonError)?;

        let presentation_definition = interaction_data
            .openid_request
            .presentation_definition
            .ok_or(VerificationProtocolError::Failed(
                "Presentation definition not found".to_string(),
            ))?;

        get_presentation_definition_with_local_credentials(
            presentation_definition,
            proof,
            None,
            storage_access,
            &self.config,
        )
        .await
    }

    pub(crate) fn holder_get_holder_binding_context(
        &self,
        _proof: &Proof,
        context: serde_json::Value,
    ) -> Result<Option<HolderBindingCtx>, VerificationProtocolError> {
        let interaction_data: BLEOpenID4VPInteractionData =
            serde_json::from_value(context).map_err(VerificationProtocolError::JsonError)?;

        Ok(Some(HolderBindingCtx {
            nonce: interaction_data.nonce,
            audience: interaction_data.client_id,
        }))
    }

    pub(crate) async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        _storage_access: &StorageAccess,
        _transport: String,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        if !self.holder_can_handle(&url) {
            return Err(VerificationProtocolError::Failed(
                "No OpenID4VC over BLE query params detected".to_string(),
            ));
        }

        if !self
            .config
            .transport
            .ble_enabled_for(TransportType::Ble.as_ref())
        {
            return Err(VerificationProtocolError::Disabled(
                "BLE transport is disabled".to_string(),
            ));
        }

        let ble = self.ble.clone().ok_or_else(|| {
            VerificationProtocolError::Failed("BLE central not available".to_string())
        })?;

        let query = url
            .query()
            .ok_or(VerificationProtocolError::InvalidRequest(
                "Query cannot be empty".to_string(),
            ))?;

        let OpenID4VPBleData { name, key } = serde_qs::from_str(query)
            .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))?;

        let mut ble_holder = OpenID4VCBLEHolder::new(
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
            self.did_repository.clone(),
            self.identifier_repository.clone(),
            self.did_method_provider.clone(),
            ble,
        );

        if !ble_holder.enabled().await? {
            return Err(VerificationProtocolError::Disabled(
                "BLE adapter not enabled".into(),
            ));
        }

        let (interaction_id, mut proof) = create_interaction_and_proof(
            None,
            organisation.clone(),
            None,
            VerificationProtocolType::OpenId4VpProximityDraft00,
            TransportType::Ble,
            &*self.interaction_repository,
        )
        .await?;

        let verification_fn = Box::new(KeyVerification {
            did_method_provider: self.did_method_provider.clone(),
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });

        let verifier_did = ble_holder
            .handle_invitation(
                name,
                key,
                proof.id,
                verification_fn,
                interaction_id,
                organisation,
            )
            .await?;

        proof.verifier_did = Some(verifier_did);
        Ok(InvitationResponseDTO {
            interaction_id,
            proof,
        })
    }

    pub(crate) async fn holder_reject_proof(
        &self,
        _proof: &Proof,
    ) -> Result<(), VerificationProtocolError> {
        let ble_holder = OpenID4VCBLEHolder::new(
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
            self.did_repository.clone(),
            self.identifier_repository.clone(),
            self.did_method_provider.clone(),
            self.ble.clone().ok_or_else(|| {
                VerificationProtocolError::Failed(
                    "Missing BLE central for reject proof".to_string(),
                )
            })?,
        );

        ble_holder.disconnect_from_verifier().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        let ble = self.ble.clone().ok_or_else(|| {
            VerificationProtocolError::Failed("Missing BLE central for submit proof".to_string())
        })?;

        let interaction_data: BLEOpenID4VPInteractionData = deserialize_interaction_data(
            proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let BLEOpenID4VPInteractionData {
            openid_request,
            identity_request_nonce,
            ..
        } = &interaction_data;

        let ble_holder = OpenID4VCBLEHolder::new(
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
            self.did_repository.clone(),
            self.identifier_repository.clone(),
            self.did_method_provider.clone(),
            ble,
        );

        if !ble_holder.enabled().await? {
            return Err(VerificationProtocolError::Failed(
                "BLE adapter not enabled".to_string(),
            ));
        }

        let nonce = openid_request
            .nonce
            .as_deref()
            .ok_or_else(|| VerificationProtocolError::Failed("nonce missing".to_string()))?;

        let (vp_token, presentation_submission) = create_presentation(CreatePresentationParams {
            credential_presentations,
            presentation_definition: openid_request.presentation_definition.as_ref(),
            holder_did,
            key,
            jwk_key_id,
            client_id: &openid_request.client_id,
            identity_request_nonce: identity_request_nonce.as_deref(),
            nonce,
            formatter_provider: &*self.formatter_provider,
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            key_provider: &*self.key_provider,
        })
        .await?;

        ble_holder
            .submit_presentation(vp_token, presentation_submission, &interaction_data)
            .await?;

        Ok(UpdateResponse { update_proof: None })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        type_to_descriptor: TypeToDescriptorMapper,
        interaction_id: InteractionId,
        key_agreement: KeyAgreementKey,
        cancellation_token: CancellationToken,
        on_submission_callback: Option<Shared<BoxFuture<'static, ()>>>,
    ) -> Result<Url, VerificationProtocolError> {
        let (presentation_definition, verifier_did, auth_fn) =
            prepare_proof_share(ProofShareParams {
                interaction_id,
                proof,
                type_to_descriptor,
                format_to_type_mapper,
                key_id,
                did_method_provider: &*self.did_method_provider,
                formatter_provider: &*self.formatter_provider,
                key_provider: &*self.key_provider,
                key_algorithm_provider: self.key_algorithm_provider.clone(),
            })
            .await?;

        if !self
            .config
            .transport
            .ble_enabled_for(TransportType::Ble.as_ref())
        {
            return Err(VerificationProtocolError::Disabled(
                "BLE transport is disabled".to_string(),
            ));
        }

        let ble = self.ble.clone().ok_or_else(|| {
            VerificationProtocolError::Failed("BLE central not available".to_string())
        })?;

        let ble_verifier = OpenID4VCBLEVerifier::new(
            ble,
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
        )?;

        if !ble_verifier.enabled().await? {
            return Err(VerificationProtocolError::Disabled(
                "BLE adapter not enabled".into(),
            ));
        }

        let url = ble_verifier
            .share_proof(
                presentation_definition,
                proof.to_owned(),
                auth_fn,
                verifier_did.to_owned(),
                interaction_id,
                key_agreement,
                cancellation_token,
                on_submission_callback,
                &self.params.url_scheme,
            )
            .await?;

        Url::parse(&url).map_err(|e| VerificationProtocolError::Failed(e.to_string()))
    }

    pub(crate) async fn retract_proof(
        &self,
        _proof: &Proof,
    ) -> Result<(), VerificationProtocolError> {
        self.ble
            .as_ref()
            .ok_or_else(|| {
                VerificationProtocolError::Failed("BLE is missing in service".to_string())
            })?
            .abort(Abort::Flow(*OIDC_BLE_FLOW))
            .await;

        Ok(())
    }
}
