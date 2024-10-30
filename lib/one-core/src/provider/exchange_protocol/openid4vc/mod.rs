use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use key_agreement_key::KeyAgreementKey;
use openidvc_ble::OpenID4VCBLE;
use openidvc_http::OpenID4VCHTTP;
use openidvc_mqtt::OpenId4VcMqtt;
use serde_json::json;
use shared_types::KeyId;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use super::dto::{ExchangeProtocolCapabilities, PresentationDefinitionResponseDTO};
use super::{
    ExchangeProtocol, ExchangeProtocolError, ExchangeProtocolImpl, FormatMapper,
    HandleInvitationOperationsAccess, StorageAccess, TypeToDescriptorMapper,
};
use crate::common_validator::throw_if_latest_proof_state_not_eq;
use crate::config::core_config::{CoreConfig, TransportType};
use crate::model::credential::Credential;
use crate::model::did::Did;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::exchange_protocol::openid4vc::mapper::holder_ble_mqtt_get_presentation_definition;
use crate::provider::exchange_protocol::openid4vc::model::{
    BLEOpenID4VPInteractionData, DatatypeType, InvitationResponseDTO, MQTTOpenID4VPInteractionData,
    OpenID4VPFormat, PresentedCredential, ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::exchange_protocol::openid4vc::service::FnMapExternalFormatToExternalDetailed;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::proof::dto::CreateProofInteractionData;

pub mod dto;
pub mod error;
pub mod handle_invitation_operations;
mod key_agreement_key;
pub(crate) mod mapper;
pub mod model;
pub(crate) mod openidvc_ble;
pub mod openidvc_http;
pub(crate) mod openidvc_mqtt;
mod peer_encryption;
pub mod proof_formatter;
pub mod service;
pub mod validator;

pub(crate) struct OpenID4VC {
    config: Arc<CoreConfig>,
    openid_http: OpenID4VCHTTP,
    openid_ble: OpenID4VCBLE,
    openid_mqtt: Option<OpenId4VcMqtt>,
}

impl OpenID4VC {
    pub fn new(
        config: Arc<CoreConfig>,
        openid_http: OpenID4VCHTTP,
        openid_ble: OpenID4VCBLE,
        mqtt: Option<OpenId4VcMqtt>,
    ) -> Self {
        Self {
            config,
            openid_http,
            openid_ble,
            openid_mqtt: mqtt,
        }
    }
}

#[async_trait]
impl ExchangeProtocolImpl for OpenID4VC {
    type VCInteractionContext = serde_json::Value;
    type VPInteractionContext = serde_json::Value;

    fn can_handle(&self, url: &Url) -> bool {
        self.openid_http.can_handle(url)
            || self.openid_ble.can_handle(url)
            || self
                .openid_mqtt
                .as_ref()
                .is_some_and(|mqtt| mqtt.can_handle(url))
    }

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
        transport: String,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        let transport = TransportType::try_from(transport.as_str()).map_err(|err| {
            ExchangeProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        match transport {
            TransportType::Ble => {
                if self.openid_ble.can_handle(&url) {
                    return self.openid_ble.handle_invitation(url, organisation).await;
                }
            }
            TransportType::Http => {
                if self.openid_http.can_handle(&url) {
                    return self
                        .openid_http
                        .handle_invitation(
                            url,
                            organisation,
                            storage_access,
                            handle_invitation_operations,
                        )
                        .await;
                }
            }
            TransportType::Mqtt => {
                let client = self.openid_mqtt.as_ref().ok_or_else(|| {
                    ExchangeProtocolError::Failed("MQTT client not configured".to_string())
                })?;

                if client.can_handle(&url) {
                    return client.handle_invitation(url, organisation).await;
                }
            }
        }

        Err(ExchangeProtocolError::Failed(
            "No OpenID4VC query params detected".to_string(),
        ))
    }

    async fn reject_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            ExchangeProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        match transport {
            TransportType::Ble => self.openid_ble.reject_proof(proof).await,
            TransportType::Http => self.openid_http.reject_proof(proof).await,
            TransportType::Mqtt => {
                let client = self.openid_mqtt.as_ref().ok_or_else(|| {
                    ExchangeProtocolError::Failed("MQTT client not configured".to_string())
                })?;
                client.reject_proof(proof).await
            }
        }
    }

    async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format_map: HashMap<String, String>,
        presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            ExchangeProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        match transport {
            TransportType::Ble => {
                self.openid_ble
                    .submit_proof(
                        proof,
                        credential_presentations,
                        holder_did,
                        key,
                        jwk_key_id,
                        format_map,
                        presentation_format_map,
                    )
                    .await
            }
            TransportType::Http => {
                self.openid_http
                    .submit_proof(
                        proof,
                        credential_presentations,
                        holder_did,
                        key,
                        jwk_key_id,
                        format_map,
                        presentation_format_map,
                    )
                    .await
            }
            TransportType::Mqtt => {
                let client = self.openid_mqtt.as_ref().ok_or_else(|| {
                    ExchangeProtocolError::Failed("MQTT client not configured".to_string())
                })?;
                client
                    .submit_proof(
                        proof,
                        credential_presentations,
                        holder_did,
                        key,
                        jwk_key_id,
                        format_map,
                        presentation_format_map,
                    )
                    .await
            }
        }
    }

    async fn accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format: &str,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
        map_oidc_format_to_external: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        self.openid_http
            .accept_credential(
                credential,
                holder_did,
                key,
                jwk_key_id,
                format,
                storage_access,
                tx_code,
                map_oidc_format_to_external,
            )
            .await
    }

    async fn reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        self.openid_http.reject_credential(credential).await
    }

    async fn validate_proof_for_submission(
        &self,
        proof: &Proof,
    ) -> Result<(), ExchangeProtocolError> {
        throw_if_latest_proof_state_not_eq(proof, ProofStateEnum::Pending)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
    }

    async fn share_credential(
        &self,
        credential: &Credential,
        credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        self.openid_http
            .share_credential(credential, credential_format)
            .await
            .map(|context| ShareResponse {
                url: context.url,
                interaction_id: context.interaction_id,
                context: json!(context.context),
            })
    }

    async fn share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        let transport = get_transport(proof)?;

        match transport.as_slice() {
            [TransportType::Ble] => {
                let interaction_id = Uuid::new_v4();
                let key_agreement = KeyAgreementKey::new_random();

                self.openid_ble
                    .share_proof(
                        proof,
                        format_to_type_mapper,
                        type_to_descriptor,
                        interaction_id,
                        key_agreement,
                        CancellationToken::new(),
                    )
                    .await
                    .map(|url| ShareResponse {
                        url,
                        interaction_id,
                        context: json!({}),
                    })
            }
            [TransportType::Http] => self
                .openid_http
                .share_proof(
                    proof,
                    format_to_type_mapper,
                    key_id,
                    encryption_key_jwk,
                    vp_formats,
                    type_to_descriptor,
                )
                .await
                .map(|context| ShareResponse {
                    url: context.url,
                    interaction_id: context.interaction_id,
                    context: json!(context.context),
                }),
            [TransportType::Mqtt] => {
                let mqtt = self.openid_mqtt.as_ref().ok_or_else(|| {
                    ExchangeProtocolError::Failed("MQTT client not configured".to_string())
                })?;
                let interaction_id = Uuid::new_v4();
                let key_agreement = KeyAgreementKey::new_random();

                mqtt.share_proof(
                    proof,
                    format_to_type_mapper,
                    type_to_descriptor,
                    interaction_id,
                    key_agreement,
                    CancellationToken::new(),
                )
                .await
                .map(|url| ShareResponse {
                    url: url.to_string(),
                    interaction_id,
                    context: json!({}),
                })
            }

            [TransportType::Ble, TransportType::Mqtt]
            | [TransportType::Mqtt, TransportType::Ble] => {
                let mqtt = self.openid_mqtt.as_ref().ok_or_else(|| {
                    ExchangeProtocolError::Failed("MQTT client not configured".to_string())
                })?;

                let interaction_id = Uuid::new_v4();
                let key_agreement = KeyAgreementKey::new_random();

                // notification to cancel the other flow when one is selected
                let cancellation_token = CancellationToken::new();

                let mqtt_url = mqtt
                    .share_proof(
                        proof,
                        format_to_type_mapper.clone(),
                        type_to_descriptor.clone(),
                        interaction_id,
                        key_agreement.clone(),
                        cancellation_token.clone(),
                    )
                    .await?;

                tracing::debug!("Got mqtt url: {mqtt_url}");

                let ble_response = self
                    .openid_ble
                    .share_proof(
                        proof,
                        format_to_type_mapper,
                        type_to_descriptor,
                        interaction_id,
                        key_agreement,
                        cancellation_token,
                    )
                    .await?;

                tracing::debug!("Got ble url: {ble_response}");

                let ble_url: Url = ble_response
                    .parse()
                    .map_err(|err| ExchangeProtocolError::Failed(format!("Invalid URL: {err}")))?;

                let url = merge_query_params(mqtt_url, ble_url);

                Ok(ShareResponse {
                    url: format!("{url}"),
                    interaction_id,
                    context: serde_json::to_value(CreateProofInteractionData {
                        transport: transport.iter().map(ToString::to_string).collect(),
                    })
                    .unwrap(),
                })
            }
            other => Err(ExchangeProtocolError::Failed(format!(
                "Invalid transport selection: {other:?}",
            ))),
        }
    }

    async fn get_presentation_definition(
        &self,
        proof: &Proof,
        interaction_data: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        format_map: HashMap<String, String>,
        types: HashMap<String, DatatypeType>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            ExchangeProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        match transport {
            TransportType::Ble => {
                let interaction_data: BLEOpenID4VPInteractionData =
                    serde_json::from_value(interaction_data)
                        .map_err(ExchangeProtocolError::JsonError)?;

                holder_ble_mqtt_get_presentation_definition(
                    &self.config,
                    proof,
                    interaction_data.presentation_definition.ok_or(
                        ExchangeProtocolError::Failed(
                            "presentation_definition is None".to_string(),
                        ),
                    )?,
                    storage_access,
                )
                .await
            }
            TransportType::Http => {
                self.openid_http
                    .get_presentation_definition(proof, storage_access, format_map, types)
                    .await
            }
            TransportType::Mqtt => {
                tracing::debug!("Getting presentation definition");

                let interaction_data: MQTTOpenID4VPInteractionData =
                    serde_json::from_value(interaction_data)
                        .map_err(ExchangeProtocolError::JsonError)?;

                holder_ble_mqtt_get_presentation_definition(
                    &self.config,
                    proof,
                    interaction_data.presentation_definition.ok_or(
                        ExchangeProtocolError::Failed(
                            "presentation_definition is None".to_string(),
                        ),
                    )?,
                    storage_access,
                )
                .await
            }
        }
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn retract_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError> {
        for transport in get_transport(proof)? {
            match transport {
                TransportType::Http => {}
                TransportType::Ble => self.openid_ble.retract_proof().await?,
                TransportType::Mqtt => {
                    self.openid_mqtt
                        .as_ref()
                        .ok_or_else(|| {
                            ExchangeProtocolError::Failed(
                                "MQTT not configured for retract proof".to_string(),
                            )
                        })?
                        .retract_proof()
                        .await;
                }
            }
        }

        Ok(())
    }

    fn get_capabilities(&self) -> ExchangeProtocolCapabilities {
        ExchangeProtocolCapabilities {
            supported_transports: vec!["HTTP".to_owned(), "BLE".to_owned(), "MQTT".to_owned()],
        }
    }
}

impl ExchangeProtocol for OpenID4VC {}

fn get_transport(proof: &Proof) -> Result<Vec<TransportType>, ExchangeProtocolError> {
    let transport = if proof.transport.is_empty() {
        let data: CreateProofInteractionData = proof
            .interaction
            .as_ref()
            .context("Missing interaction data for proof transport selection")
            .and_then(|interaction| {
                let interaction_data = interaction
                    .data
                    .as_ref()
                    .context("Missing interaction data")?;

                serde_json::from_slice(interaction_data).context("Interaction deserialization")
            })
            .map_err(ExchangeProtocolError::Other)?;

        data.transport
    } else {
        vec![proof.transport.clone()]
    };

    transport
        .into_iter()
        .map(|t| TransportType::try_from(t.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| ExchangeProtocolError::Failed(format!("Invalid transport type: {err}")))
}

fn merge_query_params(mut first: Url, second: Url) -> Url {
    let mut query_params: HashMap<_, _> = second.query_pairs().into_owned().collect();

    query_params.extend(first.query_pairs().into_owned());

    first.query_pairs_mut().clear();

    first.query_pairs_mut().extend_pairs(query_params);

    first
}
