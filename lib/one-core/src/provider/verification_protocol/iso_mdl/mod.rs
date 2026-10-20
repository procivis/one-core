//! Implementation of ISO mDL (ISO/IEC 18013-5:2021).
//! https://www.iso.org/standard/69084.html

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use ble::holder::{MdocBleHolderInteractionData, send_device_response};
use common::{DeviceRequest, to_cbor};
use futures::future::BoxFuture;
use mapper::device_request_to_dcql_query;
use proc_macros::Provider;
use serde::{Deserialize, Serialize};
use url::Url;

use super::dto::{
    FormattedCredentialPresentation, InvitationResponseDTO, PresentationDefinitionV2ResponseDTO,
    PresentationDefinitionVersion, ShareResponse, VerificationProtocolCapabilities,
};
use super::openid4vp::dcql::get_presentation_definition_v2;
use super::openid4vp::mapper::format_to_type;
use super::{VerificationProtocol, VerificationProtocolError, deserialize_interaction_data};
use crate::config::core_config::{
    CoreConfig, DidType, IdentifierType, KeyAlgorithmType, TransportType, VerificationEngagement,
};
use crate::error::ContextWithErrorCode;
use crate::mapper::decode_cbor_base64url;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::relation::OptionalRelatedExt;
use crate::proto::bluetooth_low_energy::ble_resource::{Abort, BleWaiter};
use crate::proto::nfc::NfcError;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, FormatPresentationCtx, FormattedPresentation,
};
use crate::provider::presentation_formatter::mso_mdoc::model::{DeviceResponse, DocumentError};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::SessionTranscript;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::provider_directory::InitializationError;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::service::proof::dto::ShareProofRequestParamsDTO;

pub(crate) mod ble;
pub(crate) mod common;
pub(crate) mod device_engagement;
mod holder_trust;
mod mapper;
pub(crate) mod nfc;
mod session;
#[cfg(test)]
mod test;
mod verify_proof;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Params {
    pub holder: HolderParams,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderParams {
    pub session_encryption_algorithm: KeyAlgorithmType,
    pub ble_mode: BleMode,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum BleMode {
    Peripheral,
    Central,
    Both,
}

#[derive(Provider)]
pub(crate) struct IsoMdl {
    config_id: String,
    #[expect(unused)]
    params: Params,
    config: Arc<CoreConfig>,
    credential_repository: Arc<dyn CredentialRepository>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
    wrp_validator: Arc<dyn WRPValidator>,
    ble: Option<BleWaiter>,
    nfc_hce: Option<Arc<dyn NfcHce>>,
}

impl IsoMdl {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config_id: String,
        params: serde_json::Value,
        config: Arc<CoreConfig>,
        credential_repository: Arc<dyn CredentialRepository>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
        wrp_validator: Arc<dyn WRPValidator>,
        ble: Option<BleWaiter>,
        nfc_hce: Option<Arc<dyn NfcHce>>,
    ) -> Result<Self, InitializationError> {
        let params: Params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        if !key_algorithm_provider
            .key_algorithm_from_type(params.holder.session_encryption_algorithm)?
            .get_capabilities()
            .features
            .contains(&crate::provider::key_algorithm::model::Features::KeyAgreement)
        {
            return Err(InitializationError::UnsupportedConfiguration {
                key: config_id,
                detail: format!(
                    "Key algorithm `{}` does not support key agreement",
                    params.holder.session_encryption_algorithm
                ),
            });
        }

        Ok(Self {
            config_id,
            params,
            config,
            credential_repository,
            presentation_formatter_provider,
            key_provider,
            key_algorithm_provider,
            credential_schema_repository,
            credential_formatter_provider,
            ecosystem_provider,
            wrp_validator,
            ble,
            nfc_hce,
        })
    }
}

#[async_trait]
impl VerificationProtocol for IsoMdl {
    fn holder_can_handle(&self, _url: &Url) -> bool {
        false
    }

    async fn holder_handle_invitation<'a>(
        &self,
        _url: Url,
        _organisation: Organisation,
        _transport: String,
    ) -> Result<InvitationResponseDTO<'a>, VerificationProtocolError> {
        Err(VerificationProtocolError::OperationNotSupported)
    }

    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        let ble = self.ble.as_ref().ok_or(VerificationProtocolError::Failed(
            "Missing BLE waiter".to_string(),
        ))?;

        let interaction = if let Some(interaction) = proof.interaction.as_ref() {
            Some(interaction.as_ref().await?)
        } else {
            None
        };

        let interaction_data: MdocBleHolderInteractionData = deserialize_interaction_data(
            interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let device_request_bytes = &interaction_data
            .session
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "interaction_session_data missing".to_string(),
            ))?
            .device_request_bytes;

        let device_request: DeviceRequest = ciborium::from_reader(device_request_bytes.as_slice())
            .context("device request deserialization error")
            .map_err(VerificationProtocolError::Other)?;

        let mut document_error = DocumentError::new();
        for doc_request in device_request.doc_requests {
            let doc_type = doc_request.items_request.into_inner().doc_type;
            document_error.insert(doc_type, 0);
        }
        let device_response = DeviceResponse {
            version: Default::default(),
            documents: None,
            document_errors: Some(vec![document_error]),
            status: 0,
        };

        send_device_response(ble, device_response, interaction_data).await?;

        Ok(())
    }

    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<FormattedCredentialPresentation>,
    ) -> Result<(), VerificationProtocolError> {
        let ble = self.ble.clone().ok_or_else(|| {
            VerificationProtocolError::Failed("Missing BLE central for submit proof".to_string())
        })?;

        let interaction = if let Some(interaction) = proof.interaction.as_ref() {
            Some(interaction.as_ref().await?)
        } else {
            None
        };

        let interaction_data: MdocBleHolderInteractionData = deserialize_interaction_data(
            interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let session = interaction_data.session.as_ref().ok_or_else(|| {
            VerificationProtocolError::Failed("invalid interaction data".to_string())
        })?;

        let credential_presentation =
            credential_presentations
                .first()
                .ok_or(VerificationProtocolError::Failed(
                    "no credentials to format".into(),
                ))?;

        let auth_fn = self.key_provider.get_signature_provider(
            &credential_presentation.key,
            credential_presentation.jwk_key_id.to_owned(),
            self.key_algorithm_provider.clone(),
        )?;

        let presentation_schema_format = &credential_presentation.credential_format.format;
        let format_type = self
            .config
            .format
            .get_type(presentation_schema_format)
            .error_while("getting format type")?;
        let (_, presentation_formatter) = self
            .presentation_formatter_provider
            .get_presentation_formatter_by_type(format_type)
            .ok_or(VerificationProtocolError::Failed(format!(
                "unknown format: {presentation_schema_format}"
            )))?;
        let session_transcript_bytes: EmbeddedCbor<SessionTranscript> =
            ciborium::from_reader(session.session_transcript_bytes.as_slice())?;

        let ctx = FormatPresentationCtx {
            mdoc_session_transcript: Some(to_cbor(session_transcript_bytes.inner())?),
            ..Default::default()
        };

        let mut presentations = Vec::with_capacity(credential_presentations.len());
        for credential in credential_presentations {
            let credential_format = format_to_type(&credential, &self.config).await?;
            presentations.push(CredentialToPresent {
                credential_token: credential.presentation,
                credential_format,
            });
        }

        let FormattedPresentation { vp_token, .. } = presentation_formatter
            .format_presentation(presentations, auth_fn, ctx)
            .await
            .error_while("formatting presentation")?;

        let device_response = decode_cbor_base64url(&vp_token).error_while("decoding vp_token")?;

        send_device_response(&ble, device_response, interaction_data).await?;

        Ok(())
    }

    async fn retract_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        let ble = self.ble.as_ref().ok_or_else(|| {
            VerificationProtocolError::Failed("Missing BLE interface".to_string())
        })?;

        // There is one shared flowId for both holder and verifier logic.
        // So this call cancels either one, if running
        ble.abort(Abort::Flow(*ble::ISO_MDL_FLOW)).await;

        // explicitly stop NFC HCE if running
        if proof.role == ProofRole::Holder && proof.state == ProofStateEnum::Pending {
            let interaction = if let Some(interaction) = proof.interaction.as_ref() {
                Some(interaction.as_ref().await?)
            } else {
                None
            };

            let interaction_data: MdocBleHolderInteractionData = deserialize_interaction_data(
                interaction
                    .as_ref()
                    .and_then(|interaction| interaction.data.as_ref()),
            )?;

            if interaction_data
                .engagement
                .contains(&VerificationEngagement::NFC)
            {
                match self
                    .nfc_hce
                    .as_ref()
                    .ok_or_else(|| {
                        VerificationProtocolError::Failed("Missing NFC HCE interface".to_string())
                    })?
                    .stop_hosting(false)
                    .await
                {
                    Ok(_) | Err(NfcError::NotStarted) => {}
                    Err(err) => tracing::error!("Failed to stop NFC hosting: {err}"),
                }
            }
        }

        Ok(())
    }

    async fn verifier_share_proof(
        &self,
        _proof: &Proof,
        _callback: Option<BoxFuture<'static, ()>>,
        _params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse, VerificationProtocolError> {
        Err(VerificationProtocolError::OperationNotSupported)
    }

    async fn holder_get_presentation_definition_v2(
        &self,
        proof: &Proof,
        submitted_credential_ids: &[shared_types::CredentialId],
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
        let interaction = proof.interaction.as_required_ref().await?;
        let interaction_data: MdocBleHolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;

        let device_request_bytes = interaction_data
            .session
            .ok_or_else(|| VerificationProtocolError::Failed("Missing device_request".to_string()))?
            .device_request_bytes;

        let device_request = ciborium::from_reader(device_request_bytes.as_slice())
            .context("device request deserialization error")
            .map_err(VerificationProtocolError::Other)?;

        let dcql_query = device_request_to_dcql_query(&device_request);

        get_presentation_definition_v2(
            dcql_query,
            proof,
            &*self.credential_repository,
            &*self.credential_schema_repository,
            &*self.credential_formatter_provider,
            &*self.ecosystem_provider,
            &*self.wrp_validator,
            &self.config,
            None,
            &[],
            None,
            submitted_credential_ids,
        )
        .await
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        VerificationProtocolCapabilities {
            features: vec![],
            supported_transports: vec![TransportType::Ble],
            did_methods: vec![DidType::Key, DidType::Jwk, DidType::Web],
            verifier_identifier_types: vec![IdentifierType::Did],
            supported_presentation_definition: vec![PresentationDefinitionVersion::V2],
            supported_encryption_algorithms: vec![],
        }
    }

    fn config_name(&self) -> &str {
        &self.config_id
    }
}
