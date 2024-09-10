use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use ble_holder::{send_mdl_response, MdocBleHolderInteractionData};
use common::DeviceRequest;
use one_providers::common_dto::PublicKeyJwkDTO;
use one_providers::common_models::credential::{OpenCredential, OpenCredentialStateEnum};
use one_providers::common_models::did::OpenDid;
use one_providers::common_models::key::{KeyId, OpenKey};
use one_providers::common_models::organisation::OpenOrganisation;
use one_providers::common_models::proof::{OpenProof, OpenProofStateEnum};
use one_providers::credential_formatter::model::DetailCredential;
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::exchange_protocol::openid4vc::model::{
    DatatypeType, InvitationResponseDTO, OpenID4VPFormat, PresentationDefinitionFieldDTO,
    PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum, PresentedCredential,
    ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use one_providers::exchange_protocol::openid4vc::service::FnMapExternalFormatToExternalDetailed;
use one_providers::exchange_protocol::openid4vc::validator::throw_if_latest_proof_state_not_eq;
use one_providers::exchange_protocol::openid4vc::{
    ExchangeProtocolError, ExchangeProtocolImpl, FormatMapper, HandleInvitationOperationsAccess,
    StorageAccess, TypeToDescriptorMapper,
};
use one_providers::key_storage::provider::KeyProvider;
use url::Url;

use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::CoreConfig;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    DeviceResponse, DeviceResponseVersion, DocumentError,
};
use crate::provider::exchange_protocol::deserialize_interaction_data;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::util::ble_resource::{Abort, BleWaiter};

mod ble;
pub(crate) mod ble_holder;
pub(crate) mod ble_verifier;
pub(crate) mod common;
pub(crate) mod device_engagement;
mod session;

#[cfg(test)]
mod test;

#[allow(dead_code)]
pub(crate) struct IsoMdl {
    config: Arc<CoreConfig>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    ble: Option<BleWaiter>,
}

impl IsoMdl {
    pub fn new(
        config: Arc<CoreConfig>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        ble: Option<BleWaiter>,
    ) -> Self {
        Self {
            config,
            formatter_provider,
            key_provider,
            ble,
        }
    }
}

#[async_trait]
impl ExchangeProtocolImpl for IsoMdl {
    type VCInteractionContext = ();
    type VPInteractionContext = serde_json::Value;

    fn can_handle(&self, _url: &Url) -> bool {
        false
    }

    async fn handle_invitation(
        &self,
        _url: Url,
        _organisation: OpenOrganisation,
        _storage_access: &StorageAccess,
        _handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn reject_proof(&self, proof: &OpenProof) -> Result<(), ExchangeProtocolError> {
        let ble = self.ble.as_ref().ok_or(ExchangeProtocolError::Failed(
            "Missing BLE waiter".to_string(),
        ))?;

        let mut doc_types = DocumentError::new();
        let input_schemas = proof
            .schema
            .clone()
            .ok_or(ExchangeProtocolError::Failed(
                "Proof schema missing".to_string(),
            ))?
            .input_schemas
            .ok_or(ExchangeProtocolError::Failed(
                "Input schemas missing".to_string(),
            ))?;

        for input_schema in input_schemas {
            let schema_id = input_schema
                .credential_schema
                .ok_or(ExchangeProtocolError::Failed(
                    "Credential schema missing".to_string(),
                ))?
                .schema_id;
            doc_types.insert(schema_id, 0);
        }
        let device_response = DeviceResponse {
            version: DeviceResponseVersion::V1_0,
            documents: None,
            document_errors: vec![doc_types].into(),
            status: 0,
        };

        send_mdl_response(ble, device_response, proof).await?;

        Ok(())
    }

    async fn submit_proof(
        &self,
        proof: &OpenProof,
        _credential_presentations: Vec<PresentedCredential>,
        _holder_did: &OpenDid,
        _key: &OpenKey,
        _jwk_key_id: Option<String>,
        _format_map: HashMap<String, String>,
        _presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        let _ble = self.ble.clone().ok_or_else(|| {
            ExchangeProtocolError::Failed("Missing BLE central for submit proof".to_string())
        })?;

        let _interaction_data: MdocBleHolderInteractionData = deserialize_interaction_data(
            proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        // TODO:
        // submit proof logic

        Ok(UpdateResponse {
            result: (),
            update_proof: None,
            create_did: None,
            update_credential: None,
            update_credential_schema: None,
        })
    }

    async fn accept_credential(
        &self,
        _credential: &OpenCredential,
        _holder_did: &OpenDid,
        _key: &OpenKey,
        _jwk_key_id: Option<String>,
        _format: &str,
        _storage_access: &StorageAccess,
        _map_oidc_format_to_external: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn reject_credential(
        &self,
        _credential: &OpenCredential,
    ) -> Result<(), ExchangeProtocolError> {
        unimplemented!()
    }

    async fn validate_proof_for_submission(
        &self,
        proof: &OpenProof,
    ) -> Result<(), ExchangeProtocolError> {
        throw_if_latest_proof_state_not_eq(proof, OpenProofStateEnum::Requested)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
    }

    async fn share_credential(
        &self,
        _credential: &OpenCredential,
        _credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn retract_proof(&self, proof: &OpenProof) -> Result<(), ExchangeProtocolError> {
        // TODO: implement retract proof on verifier

        let interaction_data: MdocBleHolderInteractionData = deserialize_interaction_data(
            proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let ble = self.ble.clone().ok_or_else(|| {
            ExchangeProtocolError::Failed("Missing BLE central for submit proof".to_string())
        })?;

        ble.abort(Abort::Task(interaction_data.continuation_task_id))
            .await;
        Ok(())
    }

    async fn share_proof(
        &self,
        _proof: &OpenProof,
        _format_to_type_mapper: FormatMapper,
        _key_id: KeyId,
        _encryption_key_jwk: PublicKeyJwkDTO,
        _vp_formats: HashMap<String, OpenID4VPFormat>,
        _type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn get_presentation_definition(
        &self,
        proof: &OpenProof,
        interaction_data: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        _format_map: HashMap<String, String>,
        _types: HashMap<String, DatatypeType>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        let interaction_data: MdocBleHolderInteractionData =
            serde_json::from_value(interaction_data).map_err(ExchangeProtocolError::JsonError)?;

        let device_request_bytes = interaction_data
            .session
            .ok_or_else(|| ExchangeProtocolError::Failed("Missing device_request".to_string()))?
            .device_request_bytes;

        let device_request: DeviceRequest = ciborium::from_reader(device_request_bytes.as_slice())
            .context("device request deserialization error")
            .map_err(ExchangeProtocolError::Other)?;

        let mut relevant_credentials = vec![];
        let mut requested_credentials = vec![];

        let organisation_id = interaction_data.organisation_id;

        for doc_request in device_request.doc_requests {
            let items_request = doc_request.items_request.into_inner();
            let schema_id = items_request.doc_type;
            let namespaces = items_request.name_spaces;

            let credentials: Vec<_> = storage_access
                .get_credentials_by_credential_schema_id(&schema_id)
                .await
                .map_err(|err| {
                    ExchangeProtocolError::Failed(format!(
                        "Failed loading credentials for schema: {err}"
                    ))
                })?
                .into_iter()
                .filter(|credential| {
                    credential
                        .schema
                        .as_ref()
                        .and_then(|schema| schema.organisation.as_ref())
                        .filter(|organisation| organisation.id == organisation_id.into())
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
                let credential_state = credential
                    .state
                    .as_ref()
                    .and_then(|states| states.first())
                    .ok_or_else(|| {
                        ExchangeProtocolError::Failed("State missing for credential".to_string())
                    })?;

                if !matches!(
                    credential_state.state,
                    OpenCredentialStateEnum::Accepted
                        | OpenCredentialStateEnum::Revoked
                        | OpenCredentialStateEnum::Suspended
                ) {
                    continue;
                }

                let claims = credential.claims.as_ref().ok_or_else(|| {
                    ExchangeProtocolError::Failed("Claims missing for credential".to_string())
                })?;

                let mut credential_claim_requested = false;
                for claim in claims {
                    let claim_schema = claim.schema.as_ref().ok_or_else(|| {
                        ExchangeProtocolError::Failed("Claim is missing claim schema".to_string())
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
                        credential_detail_response_from_model(credential.into(), &self.config)
                            .map_err(|err| {
                                ExchangeProtocolError::Failed(format!(
                                    "Credential model mapping error: {err}"
                                ))
                            })?;
                    relevant_credentials.push(credential.into());
                }
            }

            let credential_response = PresentationDefinitionRequestedCredentialResponseDTO {
                id: schema_id,
                name: None,
                purpose: None,
                fields,
                applicable_credentials,
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
        _proof: &OpenProof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        todo!()
    }
}
