//! Implementation of ISO mDL (ISO/IEC 18013-5:2021).
//! https://www.iso.org/standard/69084.html

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use ble::ISO_MDL_FLOW;
use ble_holder::{send_mdl_response, MdocBleHolderInteractionData};
use common::{to_cbor, DeviceRequest};
use futures::future::BoxFuture;
use shared_types::KeyId;
use url::Url;

use super::dto::{
    InvitationResponseDTO, PresentationDefinitionFieldDTO,
    PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum, PresentedCredential,
    ShareResponse, UpdateResponse, VerificationProtocolCapabilities,
};
use super::{
    FormatMapper, StorageAccess, TypeToDescriptorMapper, VerificationProtocol,
    VerificationProtocolError,
};
use crate::common_mapper::{decode_cbor_base64, NESTED_CLAIM_MARKER};
use crate::config::core_config::{CoreConfig, DidType};
use crate::model::credential::CredentialStateEnum;
use crate::model::did::Did;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    DeviceResponse, DeviceResponseVersion, DocumentError, EmbeddedCbor, SessionTranscript,
};
use crate::provider::credential_formatter::model::{
    DetailCredential, FormatPresentationCtx, HolderBindingCtx,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::deserialize_interaction_data;
use crate::provider::verification_protocol::openid4vp::model::OpenID4VpPresentationFormat;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::proof::dto::ShareProofRequestParamsDTO;
use crate::util::ble_resource::{Abort, BleWaiter};

mod ble;
pub(crate) mod ble_holder;
pub(crate) mod ble_verifier;
pub(crate) mod common;
pub(crate) mod device_engagement;
mod session;

#[cfg(test)]
mod test;
mod verify_proof;

pub(crate) struct IsoMdl {
    config: Arc<CoreConfig>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ble: Option<BleWaiter>,
}

impl IsoMdl {
    pub(crate) fn new(
        config: Arc<CoreConfig>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        ble: Option<BleWaiter>,
    ) -> Self {
        Self {
            config,
            formatter_provider,
            key_provider,
            key_algorithm_provider,
            ble,
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
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        _jwk_key_id: Option<String>,
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

        let auth_fn = self
            .key_provider
            .get_signature_provider(key, None, self.key_algorithm_provider.clone())
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let credential_presentation =
            credential_presentations
                .first()
                .ok_or(VerificationProtocolError::Failed(
                    "no credentials to format".into(),
                ))?;

        let formatter = self
            .formatter_provider
            .get_formatter(&credential_presentation.credential_schema.format)
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

        let presentaitons = credential_presentations
            .into_iter()
            .map(|credential| credential.presentation)
            .collect::<Vec<_>>();

        let device_response = formatter
            .format_presentation(&presentaitons, &holder_did.did, &key.key_type, auth_fn, ctx)
            .await
            .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;

        let device_response = decode_cbor_base64(&device_response)
            .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;

        send_mdl_response(&ble, device_response, interaction_data).await?;

        Ok(UpdateResponse { update_proof: None })
    }

    async fn retract_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        let ble = self.ble.as_ref().ok_or_else(|| {
            VerificationProtocolError::Failed("Missing BLE interface".to_string())
        })?;

        // There is one shared flowId for both holder and verifier logic.
        // So this call cancels either one, if it is running
        ble.abort(Abort::Flow(*ISO_MDL_FLOW)).await;
        Ok(())
    }

    async fn verifier_share_proof(
        &self,
        _proof: &Proof,
        _format_to_type_mapper: FormatMapper,
        _key_id: KeyId,
        _encryption_key_jwk: PublicKeyJwkDTO,
        _vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
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
                            .insert(credential.id.to_string(), field_description.id.to_owned());

                        credential_claim_requested = true;
                    }
                }

                if credential_claim_requested {
                    applicable_credentials.push(credential.id.to_string());

                    let credential =
                        credential_detail_response_from_model(credential, &self.config, None)
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

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, VerificationProtocolError> {
        todo!()
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        VerificationProtocolCapabilities {
            supported_transports: vec!["BLE".to_owned()],
            did_methods: vec![DidType::Key, DidType::Jwk, DidType::Web, DidType::MDL],
        }
    }
}
