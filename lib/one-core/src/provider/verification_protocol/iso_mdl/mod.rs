//! Implementation of ISO mDL (ISO/IEC 18013-5:2021).
//! https://www.iso.org/standard/69084.html

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use ble::holder::{MdocBleHolderInteractionData, send_device_response};
use common::{DeviceRequest, to_cbor};
use dcapi::MdocDcApiHolderInteractionData;
use futures::future::BoxFuture;
use mapper::{device_request_to_dcql_query, holder_proof_for_dc_api, interaction_with_data};
use proc_macros::Provider;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::dto::{
    FormattedCredentialPresentation, InvitationRequest, InvitationResponseDTO,
    PresentationDefinitionV2ResponseDTO, PresentationDefinitionVersion, ShareResponse,
    VerificationProtocolCapabilities,
};
use super::openid4vp::dcql::get_presentation_definition_v2;
use super::openid4vp::mapper::format_to_type;
use super::{VerificationProtocol, VerificationProtocolError, deserialize_interaction_data};
use crate::config::core_config::{
    CoreConfig, DidType, IdentifierType, KeyAlgorithmType, TransportType, VerificationEngagement,
};
use crate::error::ContextWithErrorCode;
use crate::mapper::decode_cbor_base64url;
use crate::model::did::KeyRole;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::relation::OptionalRelatedExt;
use crate::proto::bluetooth_low_energy::ble_resource::{Abort, BleWaiter};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::key_verification::KeyVerification;
use crate::proto::nfc::NfcError;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;
use crate::provider::credential_formatter::model::VerificationFn;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, FormatPresentationCtx, FormattedPresentation,
};
use crate::provider::presentation_formatter::mso_mdoc::model::dcapi::EncryptionInfo;
use crate::provider::presentation_formatter::mso_mdoc::model::{DeviceResponse, DocumentError};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::dc_api::DcApiHandover;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
    Handover, SessionTranscript,
};
use crate::provider::presentation_formatter::mso_mdoc::try_build_dcapi_response;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::provider_directory::InitializationError;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::service::proof::dto::ShareProofRequestParamsDTO;

pub(crate) mod ble;
pub(crate) mod common;
mod dcapi;
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
    interaction_repository: Arc<dyn InteractionRepository>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
    did_method_provider: Arc<dyn DidMethodProvider>,
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
        interaction_repository: Arc<dyn InteractionRepository>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
        did_method_provider: Arc<dyn DidMethodProvider>,
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
            interaction_repository,
            presentation_formatter_provider,
            key_provider,
            key_algorithm_provider,
            certificate_validator,
            credential_schema_repository,
            credential_formatter_provider,
            ecosystem_provider,
            did_method_provider,
            wrp_validator,
            ble,
            nfc_hce,
        })
    }

    fn get_transport_type(
        &self,
        transport: &str,
    ) -> Result<TransportType, VerificationProtocolError> {
        Ok(self
            .config
            .transport
            .get_type(transport)
            .error_while("getting transport type")?)
    }

    fn verification_fn(&self) -> VerificationFn {
        Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        })
    }
}

#[async_trait]
impl VerificationProtocol for IsoMdl {
    fn holder_can_handle(&self, request: &InvitationRequest) -> bool {
        matches!(request, InvitationRequest::IsoDcApi { .. })
    }

    async fn holder_handle_invitation<'a>(
        &self,
        request: InvitationRequest,
        organisation: Organisation,
        transport: String,
    ) -> Result<InvitationResponseDTO<'a>, VerificationProtocolError> {
        let InvitationRequest::IsoDcApi {
            origin,
            encryption_info,
            device_request,
        } = request
        else {
            return Err(VerificationProtocolError::Failed(
                "Invalid request".to_string(),
            ));
        };

        if TransportType::DcApi != self.get_transport_type(&transport)? {
            return Err(VerificationProtocolError::Failed(
                "Invalid transport".to_string(),
            ));
        }

        let device_request: DeviceRequest =
            decode_cbor_base64url(&device_request).error_while("decoding device request")?;
        let device_request_bytes = to_cbor(&device_request)?;

        let session_transcript = SessionTranscript {
            device_engagement_bytes: None,
            e_reader_key_bytes: None,
            handover: Handover::DcApi(
                DcApiHandover::compute(&origin, &encryption_info)
                    .error_while("computing handover")?,
            ),
        };

        let proof_id = Uuid::new_v4().into();
        let ecosystem_artifact = holder_trust::holder_proof_artifact(
            &device_request,
            &session_transcript,
            proof_id,
            self.certificate_validator.as_ref(),
            &self.verification_fn(),
        )
        .await?;

        let session_transcript_bytes = EmbeddedCbor::new(session_transcript)?;
        let interaction_data = MdocDcApiHolderInteractionData {
            device_request_bytes,
            session_transcript_bytes: session_transcript_bytes.bytes().to_vec(),
            encryption_info,
        };
        let interaction = interaction_with_data(&interaction_data, organisation)?;
        let interaction_id = self
            .interaction_repository
            .create_interaction(interaction.clone())
            .await
            .error_while("creating interaction")?;

        let proof = holder_proof_for_dc_api(proof_id, self.config_name(), interaction, transport);
        Ok(InvitationResponseDTO {
            interaction_id,
            proof,
            ecosystem_artifact,
        })
    }

    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        let transport_type = self.get_transport_type(&proof.transport)?;
        match transport_type {
            TransportType::Ble => {
                let ble = self.ble.as_ref().ok_or(VerificationProtocolError::Failed(
                    "Missing BLE waiter".to_string(),
                ))?;

                let interaction = proof.interaction.as_required_ref().await?;
                let interaction_data: MdocBleHolderInteractionData =
                    deserialize_interaction_data(interaction.data.as_ref())?;

                let device_request_bytes = &interaction_data
                    .session
                    .as_ref()
                    .ok_or(VerificationProtocolError::Failed(
                        "interaction_session_data missing".to_string(),
                    ))?
                    .device_request_bytes;

                let device_request: DeviceRequest =
                    ciborium::from_reader(device_request_bytes.as_slice())
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
            }
            TransportType::DcApi => {
                // TODO (ONE-11712)
            }
            other => {
                return Err(VerificationProtocolError::Failed(format!(
                    "Invalid transport type: {other}"
                )));
            }
        }

        Ok(())
    }

    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<FormattedCredentialPresentation>,
    ) -> Result<(), VerificationProtocolError> {
        let interaction = proof.interaction.as_required_ref().await?;

        enum TransportContext {
            Ble {
                ble: BleWaiter,
                interaction_data: MdocBleHolderInteractionData,
            },
            DcApi {
                interaction_data: MdocDcApiHolderInteractionData,
            },
        }

        let transport_type = self.get_transport_type(&proof.transport)?;
        let (session_transcript_bytes, transport_context) = match transport_type {
            TransportType::Ble => {
                let ble = self.ble.clone().ok_or_else(|| {
                    VerificationProtocolError::Failed(
                        "Missing BLE central for submit proof".to_string(),
                    )
                })?;

                let interaction_data: MdocBleHolderInteractionData =
                    deserialize_interaction_data(interaction.data.as_ref())?;

                (
                    interaction_data
                        .session
                        .as_ref()
                        .ok_or_else(|| {
                            VerificationProtocolError::Failed("Missing BLE session".to_string())
                        })?
                        .session_transcript_bytes
                        .to_owned(),
                    TransportContext::Ble {
                        ble,
                        interaction_data,
                    },
                )
            }
            TransportType::DcApi => {
                let interaction_data: MdocDcApiHolderInteractionData =
                    deserialize_interaction_data(interaction.data.as_ref())?;

                (
                    interaction_data.session_transcript_bytes.to_owned(),
                    TransportContext::DcApi { interaction_data },
                )
            }
            other => {
                return Err(VerificationProtocolError::Failed(format!(
                    "Invalid transport type: {other}"
                )));
            }
        };

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
            ciborium::from_reader(session_transcript_bytes.as_slice())?;

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

        match transport_context {
            TransportContext::Ble {
                ble,
                interaction_data,
            } => {
                send_device_response(&ble, device_response, interaction_data).await?;
            }
            TransportContext::DcApi { interaction_data } => {
                let encryption_info: EncryptionInfo =
                    decode_cbor_base64url(&interaction_data.encryption_info)
                        .error_while("decoding EncryptionInfo")?;
                let _encrypted_response = try_build_dcapi_response(
                    device_response,
                    &encryption_info.parameters,
                    session_transcript_bytes.into_inner(),
                )
                .error_while("creating encrypted response")?;

                // TODO (ONE-11712)
            }
        };

        Ok(())
    }

    async fn retract_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        let transport_type = self.get_transport_type(&proof.transport)?;
        if transport_type != TransportType::Ble {
            return Ok(());
        }

        let ble = self.ble.as_ref().ok_or_else(|| {
            VerificationProtocolError::Failed("Missing BLE interface".to_string())
        })?;

        // There is one shared flowId for both holder and verifier logic.
        // So this call cancels either one, if running
        ble.abort(Abort::Flow(*ble::ISO_MDL_FLOW)).await;

        // explicitly stop NFC HCE if running
        if proof.role == ProofRole::Holder && proof.state == ProofStateEnum::Pending {
            let interaction = proof.interaction.as_required_ref().await?;
            let interaction_data: MdocBleHolderInteractionData =
                deserialize_interaction_data(interaction.data.as_ref())?;

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

        let transport_type = self.get_transport_type(&proof.transport)?;
        let device_request_bytes = match transport_type {
            TransportType::Ble => {
                let interaction_data: MdocBleHolderInteractionData =
                    deserialize_interaction_data(interaction.data.as_ref())?;

                interaction_data
                    .session
                    .ok_or_else(|| {
                        VerificationProtocolError::Failed("Missing device_request".to_string())
                    })?
                    .device_request_bytes
            }
            TransportType::DcApi => {
                let interaction_data: MdocDcApiHolderInteractionData =
                    deserialize_interaction_data(interaction.data.as_ref())?;

                interaction_data.device_request_bytes
            }
            other => {
                return Err(VerificationProtocolError::Failed(format!(
                    "Invalid transport type: {other}"
                )));
            }
        };

        let device_request = ciborium::from_reader(device_request_bytes.as_slice())?;
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
            supported_transports: vec![TransportType::Ble, TransportType::DcApi],
            did_methods: vec![DidType::Key, DidType::Jwk, DidType::Web],
            verifier_identifier_types: vec![IdentifierType::Did, IdentifierType::Certificate],
            supported_presentation_definition: vec![PresentationDefinitionVersion::V2],
            supported_encryption_algorithms: vec![],
        }
    }

    fn config_name(&self) -> &str {
        &self.config_id
    }
}
