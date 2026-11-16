//! Implementation of ISO mDL (ISO/IEC 18013-5:2021).
//! https://www.iso.org/standard/69084.html

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use ble::holder::{MdocBleHolderInteractionData, send_device_response};
use common::{DeviceRequest, to_cbor};
use dcapi::{MdocDcApiHolderInteractionData, MdocDcApiVerifierInteractionData};
use futures::future::BoxFuture;
use mapper::{device_request_to_dcql_query, holder_proof_for_dc_api, interaction_with_data};
use one_crypto::utilities::generate_random_bytes;
use proc_macros::Provider;
use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, serde_as};
use shared_types::{
    InteractionId, KeyId, KeyStorageId, ProofId, TransportId, VerificationProtocolId,
};
use standardized_types::openid4vp::dc_api::{DigitalCredentialGetRequest, IsoMdocRequest};
use time::Duration;
use tokio::sync::Mutex;

use super::dto::{
    FormattedCredentialPresentation, InvitationRequest, InvitationResponseDTO,
    PresentationDefinitionV2ResponseDTO, PresentationDefinitionVersion, ShareResponse,
    ShareResponseData, VerificationProtocolCapabilities,
};
use super::iso_mdl::common::EphemeralSessionKey;
use super::iso_mdl::verifier::{IsoMdlVerifier, create_device_request};
use super::openid4vp::dcql::get_presentation_definition_v2;
use super::openid4vp::mapper::format_to_type;
use super::{
    VerificationProtocol, VerificationProtocolError, deserialize_interaction_data,
    serialize_interaction_data,
};
use crate::clock::now_utc;
use crate::config::core_config::{
    CoreConfig, DidType, IdentifierType, KeyAlgorithmType, TransportType, VerificationEngagement,
};
use crate::error::ContextWithErrorCode;
use crate::mapper::{decode_cbor_base64url, encode_cbor_base64url};
use crate::model::did::KeyRole;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::relation::OptionalRelatedExt;
use crate::proto::bluetooth_low_energy::ble_resource::{Abort, BleWaiter};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::key_verification::KeyVerification;
use crate::proto::native_credential_manager::NativeDcApiResponseHandler;
use crate::proto::nfc::NfcError;
use crate::proto::nfc::hce::NfcHce;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::mdoc_formatter::util::{Bstr, EmbeddedCbor};
use crate::provider::credential_formatter::model::VerificationFn;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, FormatPresentationCtx, FormattedPresentation,
};
use crate::provider::presentation_formatter::mso_mdoc::model::dcapi::{
    EncryptionInfo, EncryptionParameters,
};
use crate::provider::presentation_formatter::mso_mdoc::model::{DeviceResponse, DocumentError};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::iso_18013_dc_api::Iso18013DcApiHandover;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
    Handover, SessionTranscript,
};
use crate::provider::presentation_formatter::mso_mdoc::try_build_dcapi_response;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::provider_directory::InitializationError;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::service::proof::dto::ShareProofRequestParamsDTO;

pub(crate) mod ble;
pub(crate) mod common;
pub(crate) mod dcapi;
pub(crate) mod device_engagement;
mod holder_trust;
mod mapper;
pub(crate) mod nfc;
mod session;
#[cfg(test)]
mod test;
pub(crate) mod verifier;
mod verify_proof;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Params {
    pub holder: Option<HolderParams>,
    pub dc_api_verifier: Option<DcApiVerifierParams>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderParams {
    pub session_encryption_algorithm: KeyAlgorithmType,
    pub ble_mode: BleMode,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DcApiVerifierParams {
    pub encryption_key_storage: KeyStorageId,
    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub interaction_expires_in_seconds: Option<Duration>,
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
    config_id: VerificationProtocolId,
    params: Params,
    config: Arc<CoreConfig>,
    credential_repository: Arc<dyn CredentialRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    key_repository: Arc<dyn KeyRepository>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    wrp_validator: Arc<dyn WRPValidator>,
    ble: Option<BleWaiter>,
    nfc_hce: Option<Arc<dyn NfcHce>>,

    /// active DC-API handlers (only available during DC-API flow)
    dc_api_response_handler: Mutex<HashMap<ProofId, Arc<dyn NativeDcApiResponseHandler>>>,
}

impl IsoMdl {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config_id: VerificationProtocolId,
        params: serde_json::Value,
        config: Arc<CoreConfig>,
        credential_repository: Arc<dyn CredentialRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        key_repository: Arc<dyn KeyRepository>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
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

        if let Some(holder_params) = &params.holder
            && !key_algorithm_provider
                .key_algorithm_from_type(holder_params.session_encryption_algorithm)?
                .get_capabilities()
                .features
                .contains(&crate::provider::key_algorithm::model::Features::KeyAgreement)
        {
            return Err(InitializationError::UnsupportedConfiguration {
                key: config_id.to_string(),
                detail: format!(
                    "Key algorithm `{}` does not support key agreement",
                    holder_params.session_encryption_algorithm
                ),
            });
        }

        if let Some(dc_api_verifier_params) = &params.dc_api_verifier {
            let capabilities = key_provider
                .get_key_storage(&dc_api_verifier_params.encryption_key_storage)?
                .get_capabilities();

            if !capabilities
                .features
                .contains(&crate::provider::key_storage::model::Features::KeyAgreement)
            {
                return Err(InitializationError::UnsupportedConfiguration {
                    key: config_id.to_string(),
                    detail: format!(
                        "Key storage `{}` does not support key agreement",
                        dc_api_verifier_params.encryption_key_storage
                    ),
                });
            }
            if !capabilities.algorithms.contains(&KeyAlgorithmType::Ecdsa) {
                return Err(InitializationError::UnsupportedConfiguration {
                    key: config_id.to_string(),
                    detail: format!(
                        "Key storage `{}` does not support ECDSA",
                        dc_api_verifier_params.encryption_key_storage
                    ),
                });
            }
        }

        Ok(Self {
            config_id,
            params,
            config,
            credential_repository,
            interaction_repository,
            key_repository,
            presentation_formatter_provider,
            key_provider,
            key_algorithm_provider,
            certificate_validator,
            credential_schema_repository,
            credential_formatter_provider,
            blob_storage_provider,
            ecosystem_provider,
            did_method_provider,
            wrp_validator,
            ble,
            nfc_hce,
            dc_api_response_handler: Default::default(),
        })
    }

    fn get_transport_type(
        &self,
        transport: &TransportId,
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
        transport: TransportId,
    ) -> Result<InvitationResponseDTO<'a>, VerificationProtocolError> {
        let InvitationRequest::IsoDcApi {
            origin,
            encryption_info,
            device_request,
            response_handler,
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
            handover: Handover::Iso18013DcApi(
                Iso18013DcApiHandover::compute(&origin, &encryption_info)
                    .error_while("computing handover")?,
            ),
        };

        let proof_id = ProofId::new();
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

        self.dc_api_response_handler
            .lock()
            .await
            .insert(proof_id, response_handler);

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
                let response_handler = self
                    .dc_api_response_handler
                    .lock()
                    .await
                    .remove(&proof.id)
                    .ok_or(VerificationProtocolError::Failed(
                        "missing DC-API response handler".to_string(),
                    ))?;
                response_handler
                    .on_reject()
                    .error_while("calling DC-API on_reject")?;
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

        enum TransportContext<'a> {
            Ble {
                ble: &'a BleWaiter,
                interaction_data: MdocBleHolderInteractionData,
            },
            DcApi {
                encryption_info: EncryptionInfo,
            },
        }

        let transport_type = self.get_transport_type(&proof.transport)?;
        let (session_transcript_bytes, transport_context) = match transport_type {
            TransportType::Ble => {
                let ble = self.ble.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("Missing BLE for submit proof".to_string())
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

                let encryption_info: EncryptionInfo =
                    decode_cbor_base64url(&interaction_data.encryption_info)
                        .error_while("decoding EncryptionInfo")?;

                (
                    interaction_data.session_transcript_bytes,
                    TransportContext::DcApi { encryption_info },
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
                send_device_response(ble, device_response, interaction_data).await?;
            }
            TransportContext::DcApi { encryption_info } => {
                let encrypted_response = try_build_dcapi_response(
                    device_response,
                    &encryption_info.parameters,
                    session_transcript_bytes.into_inner(),
                )
                .error_while("creating encrypted response")?;
                let response = encode_cbor_base64url(encrypted_response)
                    .error_while("encoding encrypted response")?;

                let response_handler = self
                    .dc_api_response_handler
                    .lock()
                    .await
                    .remove(&proof.id)
                    .ok_or(VerificationProtocolError::Failed(
                        "missing DC-API response handler".to_string(),
                    ))?;
                response_handler
                    .on_submit(response)
                    .error_while("calling DC-API on_submit")?;
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
        proof: &Proof,
        _callback: Option<BoxFuture<'static, ()>>,
        params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse, VerificationProtocolError> {
        if TransportType::DcApi != self.get_transport_type(&proof.transport)? {
            return Err(VerificationProtocolError::Failed(
                "Invalid transport".to_string(),
            ));
        }

        let Some(ShareProofRequestParamsDTO {
            dc_api_origin: Some(origin),
            ..
        }) = params
        else {
            return Err(VerificationProtocolError::InvalidRequest(
                "Missing origin".to_string(),
            ));
        };

        let Some(params) = &self.params.dc_api_verifier else {
            return Err(VerificationProtocolError::Failed(
                "Missing DC-API params".to_string(),
            ));
        };

        let proof_schema = proof.schema.as_required_ref().await?;

        if let Some(previous_interaction) = &proof.interaction
            && let Ok(interaction) = previous_interaction
                .as_ref()
                .await
                .inspect_err(|error| tracing::warn!(%error, "Failed to load previous interaction"))
            && let Ok(data) = deserialize_interaction_data::<MdocDcApiVerifierInteractionData>(
                interaction.data.as_ref(),
            )
            .inspect_err(|error| tracing::warn!(%error, "Failed to parse previous interaction"))
            && let Err(error) = self.key_repository.hard_delete(&data.encryption_key).await
        {
            tracing::warn!(%error, "Failed to remove previous encryption key");
        }

        let key_storage = self
            .key_provider
            .get_key_storage(&params.encryption_key_storage)?;
        let key_id = KeyId::new();
        let generated_key = key_storage
            .generate(key_id, KeyAlgorithmType::Ecdsa, Default::default())
            .await
            .error_while("generating encryption key")?;
        let key = Key {
            id: key_id,
            created_date: now_utc(),
            last_modified: now_utc(),
            public_key: generated_key.public_key,
            name: key_id.to_string(),
            key_reference: generated_key.key_reference,
            storage_type: key_storage.config_name(),
            key_type: KeyAlgorithmType::Ecdsa.to_string(),
            autogenerated: true,
            organisation: proof_schema.organisation.to_owned(),
        };
        let key_handle = key_storage
            .key_handle(&key)
            .error_while("getting key handle")?;

        self.key_repository
            .create_key(key)
            .await
            .error_while("creating key")?;

        let encryption_info = EncryptionInfo {
            parameters: EncryptionParameters {
                nonce: Bstr(generate_random_bytes::<16>().into()),
                recipient_public_key: EphemeralSessionKey::from_key(
                    key_handle
                        .key_agreement()
                        .ok_or(VerificationProtocolError::Failed(
                            "Invalid key handle".to_string(),
                        ))?
                        .public()
                        .as_ref(),
                )?,
            },
        };
        let encryption_info =
            encode_cbor_base64url(encryption_info).error_while("encoding EncryptionInfo")?;

        let session_transcript = SessionTranscript {
            device_engagement_bytes: None,
            e_reader_key_bytes: None,
            handover: Handover::Iso18013DcApi(
                Iso18013DcApiHandover::compute(&origin, &encryption_info)
                    .error_while("computing handover")?,
            ),
        };

        let verifier = match (
            &proof.verifier_identifier,
            &proof.verifier_certificate,
            &proof.verifier_key,
        ) {
            (Some(identifier), Some(certificate), Some(key)) => {
                let key = key.as_ref().await?;
                Some(IsoMdlVerifier {
                    identifier: identifier.as_ref().await?.to_owned(),
                    certificate: certificate.as_ref().await?.to_owned(),
                    key: key.to_owned(),
                    auth_fn: self.key_provider.get_signature_provider(
                        &key,
                        None,
                        self.key_algorithm_provider.clone(),
                    )?,
                })
            }
            _ => None,
        };

        let device_request = create_device_request(
            &proof_schema,
            verifier.as_ref(),
            &session_transcript,
            self.blob_storage_provider.as_ref(),
        )
        .await?;

        let request = IsoMdocRequest {
            device_request: encode_cbor_base64url(device_request)
                .error_while("encoding DeviceRequest")?,
            encryption_info,
        };

        let interaction_id = InteractionId::new();
        let session_transcript_bytes = EmbeddedCbor::new(session_transcript)?;
        let interaction_content = MdocDcApiVerifierInteractionData {
            encryption_key: key_id,
            session_transcript_bytes: session_transcript_bytes.bytes().to_vec(),
        };

        let expires_at = params
            .interaction_expires_in_seconds
            .map(|interaction_expires_in| crate::clock::now_utc() + interaction_expires_in);

        Ok(ShareResponse {
            data: ShareResponseData::DcApi(DigitalCredentialGetRequest::OrgIsoMdoc(request)),
            interaction_id,
            interaction_data: Some(serialize_interaction_data(&interaction_content)?),
            expires_at,
        })
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
        let mut supported_transports = HashSet::new();
        if self.params.holder.is_some() {
            supported_transports.extend([TransportType::Ble, TransportType::DcApi]);
        }
        if self.params.dc_api_verifier.is_some() {
            supported_transports.insert(TransportType::DcApi);
        }

        VerificationProtocolCapabilities {
            features: vec![],
            supported_transports: supported_transports.into_iter().collect(),
            did_methods: vec![DidType::Key, DidType::Jwk, DidType::Web],
            verifier_identifier_types: vec![IdentifierType::Did, IdentifierType::Certificate],
            supported_presentation_definition: vec![PresentationDefinitionVersion::V2],
            supported_encryption_algorithms: vec![],
        }
    }

    fn config_name(&self) -> &VerificationProtocolId {
        &self.config_id
    }
}
