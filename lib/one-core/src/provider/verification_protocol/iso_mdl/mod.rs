//! Implementation of ISO mDL (ISO/IEC 18013-5:2021).
//! https://www.iso.org/standard/69084.html

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use ble::ISO_MDL_FLOW;
use ble_holder::{MdocBleHolderInteractionData, send_mdl_response};
use common::{DeviceRequest, to_cbor};
use futures::future::BoxFuture;
use serde_json::Value;
use url::Url;

use super::dto::{
    FormattedCredentialPresentation, InvitationResponseDTO, PresentationDefinitionFieldDTO,
    PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
    PresentationDefinitionV2ResponseDTO, PresentationDefinitionVersion, ShareResponse,
    UpdateResponse, VerificationProtocolCapabilities,
};
use super::{
    FormatMapper, StorageAccess, TypeToDescriptorMapper, VerificationProtocol,
    VerificationProtocolError,
};
use crate::config::core_config::{
    CoreConfig, DidType, FormatType, IdentifierType, TransportType, VerificationEngagement,
};
use crate::mapper::{NESTED_CLAIM_MARKER, decode_cbor_base64};
use crate::model::credential::CredentialStateEnum;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::proto::bluetooth_low_energy::ble_resource::{Abort, BleWaiter};
use crate::proto::nfc::NfcError;
use crate::proto::nfc::hce::NfcHce;
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;
use crate::provider::credential_formatter::model::{DetailCredential, HolderBindingCtx};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, FormatPresentationCtx, FormattedPresentation,
};
use crate::provider::presentation_formatter::mso_mdoc::model::{
    DeviceResponse, DeviceResponseVersion, DocumentError,
};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::SessionTranscript;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::verification_protocol::deserialize_interaction_data;
use crate::provider::verification_protocol::openid4vp::mapper::key_and_did_from_formatted_creds;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::proof::dto::ShareProofRequestParamsDTO;

mod ble;
pub(crate) mod ble_holder;
pub(crate) mod ble_verifier;
pub(crate) mod common;
pub(crate) mod device_engagement;
pub(crate) mod nfc;
mod session;

#[cfg(test)]
mod test;
mod verify_proof;

pub(crate) struct IsoMdl {
    config: Arc<CoreConfig>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ble: Option<BleWaiter>,
    nfc_hce: Option<Arc<dyn NfcHce>>,
}

impl IsoMdl {
    pub(crate) fn new(
        config: Arc<CoreConfig>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        ble: Option<BleWaiter>,
        nfc_hce: Option<Arc<dyn NfcHce>>,
    ) -> Self {
        Self {
            config,
            presentation_formatter_provider,
            key_provider,
            key_algorithm_provider,
            ble,
            nfc_hce,
        }
    }
}

#[async_trait]
impl VerificationProtocol for IsoMdl {
    fn holder_can_handle(&self, _url: &Url) -> bool {
        false
    }

    fn holder_get_holder_binding_context(
        &self,
        _proof: &Proof,
        _context: serde_json::Value,
    ) -> Result<Option<HolderBindingCtx>, VerificationProtocolError> {
        Ok(None)
    }

    async fn holder_handle_invitation(
        &self,
        _url: Url,
        _organisation: Organisation,
        _storage_access: &StorageAccess,
        _transport: String,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        unimplemented!()
    }

    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        let ble = self.ble.as_ref().ok_or(VerificationProtocolError::Failed(
            "Missing BLE waiter".to_string(),
        ))?;

        let interaction_data: MdocBleHolderInteractionData = deserialize_interaction_data(
            proof
                .interaction
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
            version: DeviceResponseVersion::V1_0,
            documents: None,
            document_errors: Some(vec![document_error]),
            status: 0,
        };

        send_mdl_response(ble, device_response, interaction_data).await?;

        Ok(())
    }

    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<FormattedCredentialPresentation>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        let ble = self.ble.clone().ok_or_else(|| {
            VerificationProtocolError::Failed("Missing BLE central for submit proof".to_string())
        })?;

        let interaction_data: MdocBleHolderInteractionData = deserialize_interaction_data(
            proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let session = interaction_data.session.as_ref().ok_or_else(|| {
            VerificationProtocolError::Failed("invalid interaction data".to_string())
        })?;

        let (key, _, did) = key_and_did_from_formatted_creds(&credential_presentations)?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(&key, None, self.key_algorithm_provider.clone())
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let credential_presentation =
            credential_presentations
                .first()
                .ok_or(VerificationProtocolError::Failed(
                    "no credentials to format".into(),
                ))?;

        let presentation_formatter = self
            .presentation_formatter_provider
            .get_presentation_formatter(&credential_presentation.credential_schema.format)
            .ok_or(VerificationProtocolError::Failed(format!(
                "unknown format: {}",
                credential_presentation.credential_schema.format
            )))?;

        let session_transcript_bytes: EmbeddedCbor<SessionTranscript> =
            ciborium::from_reader(session.session_transcript_bytes.as_slice())
                .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;

        let ctx = FormatPresentationCtx {
            mdoc_session_transcript: Some(
                to_cbor(session_transcript_bytes.inner())
                    .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?,
            ),
            ..Default::default()
        };

        let presentations = credential_presentations
            .into_iter()
            .map(|credential| {
                let format = FormatType::from_str(&credential.credential_schema.format)
                    .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;
                Ok(CredentialToPresent {
                    raw_credential: credential.presentation,
                    credential_format: format,
                })
            })
            .collect::<Result<Vec<_>, VerificationProtocolError>>()?;

        let FormattedPresentation { vp_token, .. } = presentation_formatter
            .format_presentation(presentations, auth_fn, &did.did, ctx)
            .await
            .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;

        let device_response = decode_cbor_base64(&vp_token)
            .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;

        send_mdl_response(&ble, device_response, interaction_data).await?;

        Ok(UpdateResponse { update_proof: None })
    }

    async fn retract_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        let ble = self.ble.as_ref().ok_or_else(|| {
            VerificationProtocolError::Failed("Missing BLE interface".to_string())
        })?;

        // There is one shared flowId for both holder and verifier logic.
        // So this call cancels either one, if it is running
        ble.abort(Abort::Flow(*ISO_MDL_FLOW)).await;

        // explicitly stop NFC HCE if running
        if proof.role == ProofRole::Holder && proof.state == ProofStateEnum::Pending {
            let interaction_data: MdocBleHolderInteractionData = deserialize_interaction_data(
                proof
                    .interaction
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
        _format_to_type_mapper: FormatMapper,
        _type_to_descriptor: TypeToDescriptorMapper,
        _callback: Option<BoxFuture<'static, ()>>,
        _params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse<serde_json::Value>, VerificationProtocolError> {
        unimplemented!()
    }

    async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        interaction_data: serde_json::Value,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
        let interaction_data: MdocBleHolderInteractionData =
            serde_json::from_value(interaction_data)
                .map_err(VerificationProtocolError::JsonError)?;

        let device_request_bytes = interaction_data
            .session
            .ok_or_else(|| VerificationProtocolError::Failed("Missing device_request".to_string()))?
            .device_request_bytes;

        let device_request: DeviceRequest = ciborium::from_reader(device_request_bytes.as_slice())
            .context("device request deserialization error")
            .map_err(VerificationProtocolError::Other)?;

        let mut relevant_credentials = vec![];
        let mut requested_credentials = vec![];

        let organisation_id = interaction_data.organisation_id;

        for doc_request in device_request.doc_requests {
            let items_request = doc_request.items_request.into_inner();
            let schema_id = items_request.doc_type;
            let namespaces = items_request.name_spaces;

            let credentials: Vec<_> = storage_access
                .get_credentials_by_credential_schema_id(&schema_id, organisation_id)
                .await
                .map_err(|err| {
                    VerificationProtocolError::Failed(format!(
                        "Failed loading credentials for schema: {err}"
                    ))
                })?
                .into_iter()
                .filter(|credential| {
                    credential
                        .schema
                        .as_ref()
                        .and_then(|schema| schema.organisation.as_ref())
                        .filter(|organisation| organisation.id == organisation_id)
                        .is_some()
                })
                .collect();

            let mut fields: Vec<PresentationDefinitionFieldDTO> = namespaces
                .into_iter()
                .flat_map(|(namespace, data_elements)| {
                    data_elements.into_keys().map(move |element| {
                        let name = format!("{namespace}{NESTED_CLAIM_MARKER}{element}");

                        PresentationDefinitionFieldDTO {
                            id: name.clone(),
                            name: Some(name),
                            purpose: None,
                            required: Some(false),
                            key_map: HashMap::new(),
                        }
                    })
                })
                .collect();

            let mut applicable_credentials = vec![];

            for credential in credentials {
                let credential_state = credential.state;

                if !matches!(
                    credential_state,
                    CredentialStateEnum::Accepted
                        | CredentialStateEnum::Revoked
                        | CredentialStateEnum::Suspended
                ) {
                    continue;
                }

                let claims = credential.claims.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("Claims missing for credential".to_string())
                })?;

                let mut credential_claim_requested = false;
                for claim in claims {
                    let claim_schema = claim.schema.as_ref().ok_or_else(|| {
                        VerificationProtocolError::Failed(
                            "Claim is missing claim schema".to_string(),
                        )
                    })?;
                    let key = &claim_schema.key;

                    // iso-mdl only permits sharing of 2nd-level attributes
                    if let Some(field_description) = fields.iter_mut().find(|field| {
                        &field.id == key
                            || key.starts_with(&format!("{}{NESTED_CLAIM_MARKER}", field.id))
                    }) {
                        field_description
                            .key_map
                            .insert(credential.id, field_description.id.to_owned());

                        credential_claim_requested = true;
                    }
                }

                if credential_claim_requested {
                    applicable_credentials.push(credential.id);

                    let credential =
                        credential_detail_response_from_model(credential, &self.config, None, None)
                            .map_err(|err| {
                                VerificationProtocolError::Failed(format!(
                                    "Credential model mapping error: {err}"
                                ))
                            })?;
                    relevant_credentials.push(credential);
                }
            }

            let credential_response = PresentationDefinitionRequestedCredentialResponseDTO {
                id: schema_id,
                name: None,
                purpose: None,
                multiple: None,
                fields,
                applicable_credentials,
                inapplicable_credentials: vec![],
                validity_credential_nbf: None,
            };

            requested_credentials.push(credential_response);
        }

        let request_group = PresentationDefinitionRequestGroupResponseDTO {
            id: proof.id.to_string(),
            name: None,
            purpose: None,
            rule: PresentationDefinitionRuleDTO {
                r#type: PresentationDefinitionRuleTypeEnum::All,
                min: None,
                max: None,
                count: None,
            },
            requested_credentials,
        };

        Ok(PresentationDefinitionResponseDTO {
            request_groups: vec![request_group],
            credentials: relevant_credentials,
        })
    }

    async fn holder_get_presentation_definition_v2(
        &self,
        _proof: &Proof,
        _context: Value,
        _storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
        Err(VerificationProtocolError::OperationNotSupported)
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, VerificationProtocolError> {
        todo!()
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        VerificationProtocolCapabilities {
            supported_transports: vec![TransportType::Ble],
            did_methods: vec![DidType::Key, DidType::Jwk, DidType::Web],
            verifier_identifier_types: vec![IdentifierType::Did],
            supported_presentation_definition: vec![PresentationDefinitionVersion::V1],
        }
    }
}
