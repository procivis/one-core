use anyhow::Context;
use std::collections::{HashMap, HashSet};
use std::iter;
use std::sync::Arc;

use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    Bstr, DeviceResponse, DeviceResponseVersion, DocumentError,
};
use crate::provider::exchange_protocol::iso_mdl::ble::SERVER_2_CLIENT;
use crate::provider::exchange_protocol::iso_mdl::session::SessionData;
use crate::provider::exchange_protocol::iso_mdl::session::StatusCode;
use async_trait::async_trait;
use url::Url;

use one_providers::common_dto::PublicKeyJwkDTO;
use one_providers::common_models::credential::{OpenCredential, OpenCredentialStateEnum};
use one_providers::common_models::did::OpenDid;
use one_providers::common_models::key::{KeyId, OpenKey};
use one_providers::common_models::organisation::OpenOrganisation;
use one_providers::common_models::proof::{OpenProof, OpenProofStateEnum};
use one_providers::credential_formatter::model::{DetailCredential, FormatPresentationCtx};
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::exchange_protocol::openid4vc::imp::create_presentation_submission;
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

use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::CoreConfig;
use crate::provider::exchange_protocol::deserialize_interaction_data;
use crate::provider::exchange_protocol::iso_mdl::ble_holder::IsoMdlBleHolder;
use crate::provider::exchange_protocol::openid4vc::model::BLEOpenID4VPInteractionData;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::proof::dto::MdocBleInteractionData;
use crate::util::ble_resource::BleWaiter;

pub(crate) mod ble;
mod ble_holder;
pub(crate) mod common;

use common::Chunk;
pub(crate) mod device_engagement;
mod session;
#[cfg(test)]
mod test;

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
        let mut bytes = vec![];
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
        let response = DeviceResponse {
            version: DeviceResponseVersion::V1_0,
            documents: None,
            document_errors: vec![doc_types].into(),
            status: 0,
        };
        ciborium::ser::into_writer(&response, &mut bytes).map_err(|_err| {
            ExchangeProtocolError::Failed("CBOR serialization error".to_string())
        })?;

        let session_data = SessionData {
            data: Some(Bstr(bytes)),
            status: Some(StatusCode::SessionTermination),
        };

        let mut writer = vec![];
        ciborium::into_writer(&session_data, &mut writer).unwrap();

        let interaction_data: MdocBleInteractionData = deserialize_interaction_data(
            proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let device_address =
            interaction_data
                .device_address
                .ok_or(ExchangeProtocolError::Failed(
                    "Device address missing".to_string(),
                ))?;

        let mtu = interaction_data
            .mtu
            .ok_or(ExchangeProtocolError::Failed("Mtu missing".to_string()))?;

        let mut chunks = writer.chunks(mtu.into());

        let last = Chunk::Last(
            chunks
                .next_back()
                .context("no chunks")
                .map_err(|_| ExchangeProtocolError::Failed("No chunks available".to_string()))?
                .to_vec(),
        );

        let chunks: Vec<Vec<u8>> = chunks
            .map(|slice| Chunk::Next(slice.to_vec()))
            .chain(iter::once(last))
            .map(Into::into)
            .collect();

        let ble_peripheral = self
            .ble
            .clone()
            .ok_or(ExchangeProtocolError::Failed(
                "Missing BLE waiter".to_string(),
            ))?
            .get_peripheral();

        for chunk in chunks {
            ble_peripheral
                .notify_characteristic_data(
                    device_address.clone(),
                    interaction_data.service_id.to_string(),
                    SERVER_2_CLIENT.into(),
                    &chunk,
                )
                .await
                .map_err(|_err| {
                    ExchangeProtocolError::Failed("Unable to send end event to central".to_string())
                })?;
        }

        ble_peripheral.stop_server().await.map_err(|_err| {
            ExchangeProtocolError::Failed("Server could not be stopped".to_string())
        })?;

        Ok(())
    }

    async fn submit_proof(
        &self,
        proof: &OpenProof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &OpenDid,
        key: &OpenKey,
        jwk_key_id: Option<String>,
        _format_map: HashMap<String, String>,
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

        let ble_holder = IsoMdlBleHolder::new(ble.clone());

        if !ble_holder.enabled().await? {
            return Err(ExchangeProtocolError::Failed(
                "BLE adapter disabled".to_string(),
            ));
        }

        let tokens: Vec<String> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.presentation.to_owned())
            .collect();

        let formats: HashSet<&str> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.credential_schema.format.as_str())
            .collect();

        let (format, oidc_format) = match () {
            _ if formats.contains("MDOC") => {
                if formats.len() > 1 {
                    return Err(ExchangeProtocolError::Failed(
                        "Currently for a proof MDOC cannot be used with other formats".to_string(),
                    ));
                };

                ("MDOC", "mso_mdoc")
            }
            _ if formats.contains("JSON_LD_CLASSIC")
                || formats.contains("JSON_LD_BBSPLUS")
                // Workaround for missing cryptosuite information in openid4vc
                || formats.contains("JSON_LD") =>
            {
                ("JSON_LD_CLASSIC", "ldp_vp")
            }
            _ => ("JWT", "jwt_vp_json"),
        };

        let presentation_formatter = self
            .formatter_provider
            .get_formatter(format)
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
            oidc_format,
            presentation_format_map,
        )?;

        if format == "MDOC" {
            return Err(ExchangeProtocolError::Failed(
                "Mdoc over BLE not available".to_string(),
            ));
        }

        let nonce = interaction_data.nonce.to_owned();
        let ctx = FormatPresentationCtx {
            nonce,
            ..Default::default()
        };

        let vp_token = presentation_formatter
            .format_presentation(
                &tokens,
                &holder_did.did.to_string().into(),
                &key.key_type,
                auth_fn,
                ctx,
            )
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
        let interaction_data: MdocBleInteractionData =
            serde_json::from_value(interaction_data).map_err(ExchangeProtocolError::JsonError)?;

        let mut relevant_credentials = vec![];
        let mut requested_credentials = vec![];

        let organisation_id = interaction_data.organisation_id;

        for doc_request in interaction_data.device_request.doc_request {
            let items_request = doc_request.items_request;
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
