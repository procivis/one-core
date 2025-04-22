use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use ble::OpenID4VCBLE;
use futures::future::BoxFuture;
use futures::FutureExt;
use key_agreement_key::KeyAgreementKey;
use mqtt::OpenId4VcMqtt;
use serde::Deserialize;
use serde_json::json;
use shared_types::KeyId;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use super::model::{
    default_presentation_url_scheme, InvitationResponseDTO, OpenID4VpPresentationFormat,
    PresentedCredential, ShareResponse, UpdateResponse,
};
use crate::config::core_config::{CoreConfig, DidType, TransportType};
use crate::model::did::Did;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::model::{DetailCredential, HolderBindingCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::mqtt_client::MqttClient;
use crate::provider::verification_protocol::dto::{
    PresentationDefinitionResponseDTO, VerificationProtocolCapabilities,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::{
    FormatMapper, TypeToDescriptorMapper, VerificationProtocol,
};
use crate::repository::did_repository::DidRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::proof::dto::{CreateProofInteractionData, ShareProofRequestParamsDTO};
use crate::service::storage_proxy::StorageAccess;

pub mod ble;
mod dto;
mod key_agreement_key;
pub mod mqtt;
mod peer_encryption;

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct OpenID4VPProximityDraft00Params {
    #[serde(default = "default_presentation_url_scheme")]
    pub url_scheme: String,
}
pub struct OpenID4VPProximityDraft00 {
    openid_ble: OpenID4VCBLE,
    openid_mqtt: Option<OpenId4VcMqtt>,
}

impl OpenID4VPProximityDraft00 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        mqtt_client: Option<Arc<dyn MqttClient>>,
        config: Arc<CoreConfig>,
        params: OpenID4VPProximityDraft00Params,
        interaction_repository: Arc<dyn InteractionRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        did_repository: Arc<dyn DidRepository>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
    ) -> Self {
        let openid_ble = OpenID4VCBLE::new(
            proof_repository.clone(),
            interaction_repository.clone(),
            did_repository.clone(),
            did_method_provider.clone(),
            formatter_provider.clone(),
            key_algorithm_provider.clone(),
            key_provider.clone(),
            None,
            config.clone(),
            params.clone(),
        );
        let openid_mqtt = if let Some(mqtt_client) = mqtt_client {
            if let Ok(transport_params) = config.transport.get(TransportType::Mqtt.as_ref()) {
                Some(OpenId4VcMqtt::new(
                    mqtt_client,
                    config,
                    transport_params,
                    params,
                    interaction_repository,
                    proof_repository,
                    did_repository,
                    key_algorithm_provider,
                    formatter_provider,
                    did_method_provider,
                    key_provider,
                ))
            } else {
                None
            }
        } else {
            None
        };

        Self {
            openid_ble,
            openid_mqtt,
        }
    }
}

#[async_trait::async_trait]
impl VerificationProtocol for OpenID4VPProximityDraft00 {
    fn holder_can_handle(&self, url: &Url) -> bool {
        self.openid_ble.holder_can_handle(url)
            || self
                .openid_mqtt
                .as_ref()
                .is_some_and(|mqtt| mqtt.holder_can_handle(url))
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        transport: String,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        let transport = TransportType::try_from(transport.as_str()).map_err(|err| {
            VerificationProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        match transport {
            TransportType::Ble => {
                if self.openid_ble.holder_can_handle(&url) {
                    return self
                        .openid_ble
                        .holder_handle_invitation(
                            url,
                            organisation,
                            storage_access,
                            transport.to_string(),
                        )
                        .await;
                }
            }
            TransportType::Mqtt => {
                let client = self.openid_mqtt.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("MQTT client not configured".to_string())
                })?;

                if client.holder_can_handle(&url) {
                    return client
                        .holder_handle_invitation(
                            url,
                            organisation,
                            storage_access,
                            transport.to_string(),
                        )
                        .await;
                }
            }
            _ => {
                return Err(VerificationProtocolError::Failed(
                    "Unsupported transport type".to_string(),
                ));
            }
        }

        Err(VerificationProtocolError::Failed(
            "No OpenID4VC query params detected".to_string(),
        ))
    }

    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            VerificationProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        match transport {
            TransportType::Ble => self.openid_ble.holder_reject_proof(proof).await,
            TransportType::Mqtt => {
                let client = self.openid_mqtt.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("MQTT client not configured".to_string())
                })?;
                client.holder_reject_proof(proof).await
            }
            _ => {
                return Err(VerificationProtocolError::Failed(
                    "Unsupported transport type".to_string(),
                ));
            }
        }
    }

    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            VerificationProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        match transport {
            TransportType::Ble => {
                self.openid_ble
                    .holder_submit_proof(
                        proof,
                        credential_presentations,
                        holder_did,
                        key,
                        jwk_key_id,
                    )
                    .await
            }
            TransportType::Mqtt => {
                let client = self.openid_mqtt.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("MQTT client not configured".to_string())
                })?;
                client
                    .holder_submit_proof(
                        proof,
                        credential_presentations,
                        holder_did,
                        key,
                        jwk_key_id,
                    )
                    .await
            }
            _ => {
                return Err(VerificationProtocolError::Failed(
                    "Unsupported transport type".to_string(),
                ));
            }
        }
    }
    async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        context: serde_json::Value,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            VerificationProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        match transport {
            TransportType::Ble => {
                self.openid_ble
                    .holder_get_presentation_definition(proof, context, storage_access)
                    .await
            }
            TransportType::Mqtt => {
                let client = self.openid_mqtt.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("MQTT client not configured".to_string())
                })?;
                client
                    .holder_get_presentation_definition(proof, context, storage_access)
                    .await
            }
            _ => {
                return Err(VerificationProtocolError::Failed(
                    "Unsupported transport type".to_string(),
                ));
            }
        }
    }

    fn holder_get_holder_binding_context(
        &self,
        proof: &Proof,
        context: serde_json::Value,
    ) -> Result<Option<HolderBindingCtx>, VerificationProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            VerificationProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        match transport {
            TransportType::Ble => self
                .openid_ble
                .holder_get_holder_binding_context(proof, context),
            TransportType::Http => Err(VerificationProtocolError::Failed(
                "HTTP transport not supported".to_string(),
            )),
            TransportType::Mqtt => self
                .openid_mqtt
                .as_ref()
                .ok_or_else(|| {
                    VerificationProtocolError::Failed("MQTT client not configured".to_string())
                })?
                .holder_get_holder_binding_context(proof, context),
        }
    }

    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        _encryption_key_jwk: PublicKeyJwkDTO,
        _vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
        callback: Option<BoxFuture<'static, ()>>,
        _params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse<serde_json::Value>, VerificationProtocolError> {
        let transport = get_transport(proof)?;
        let callback = callback.map(|fut| fut.shared());

        match transport.as_slice() {
            [TransportType::Ble] => {
                let interaction_id = Uuid::new_v4();
                let key_agreement = KeyAgreementKey::new_random();

                self.openid_ble
                    .verifier_share_proof(
                        proof,
                        format_to_type_mapper,
                        key_id,
                        type_to_descriptor,
                        interaction_id,
                        key_agreement,
                        CancellationToken::new(),
                        callback,
                    )
                    .await
                    .map(|url| ShareResponse {
                        url: url.to_string(),
                        interaction_id,
                        context: json!({}),
                    })
            }
            [TransportType::Http] => {
                return Err(VerificationProtocolError::Failed(
                    "HTTP transport not supported".to_string(),
                ));
            }
            [TransportType::Mqtt] => {
                let mqtt = self.openid_mqtt.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("MQTT client not configured".to_string())
                })?;
                let interaction_id = Uuid::new_v4();
                let key_agreement = KeyAgreementKey::new_random();

                mqtt.verifier_share_proof(
                    proof,
                    format_to_type_mapper,
                    key_id,
                    type_to_descriptor,
                    interaction_id,
                    key_agreement,
                    CancellationToken::new(),
                    callback,
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
                    VerificationProtocolError::Failed("MQTT client not configured".to_string())
                })?;
                let interaction_id = Uuid::new_v4();
                let key_agreement = KeyAgreementKey::new_random();

                // notification to cancel the other flow when one is selected
                let cancellation_token = CancellationToken::new();

                let mqtt_url = mqtt
                    .verifier_share_proof(
                        proof,
                        format_to_type_mapper.clone(),
                        key_id,
                        type_to_descriptor.clone(),
                        interaction_id,
                        key_agreement.clone(),
                        cancellation_token.clone(),
                        callback.clone(),
                    )
                    .await?;

                let ble_url = self
                    .openid_ble
                    .verifier_share_proof(
                        proof,
                        format_to_type_mapper,
                        key_id,
                        type_to_descriptor,
                        interaction_id,
                        key_agreement,
                        cancellation_token,
                        callback,
                    )
                    .await?;

                let url = merge_query_params(mqtt_url, ble_url);

                Ok(ShareResponse {
                    url: format!("{url}"),
                    interaction_id,
                    context: serde_json::to_value(CreateProofInteractionData {
                        transport: transport.iter().map(ToString::to_string).collect(),
                    })
                    .map_err(|e| {
                        VerificationProtocolError::Failed(format!(
                            "Failed to serialize create proof interaction data: {e}"
                        ))
                    })?,
                })
            }
            other => Err(VerificationProtocolError::Failed(format!(
                "Invalid transport selection: {other:?}",
            ))),
        }
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, VerificationProtocolError> {
        unimplemented!()
    }

    async fn retract_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        for transport in get_transport(proof)? {
            match transport {
                TransportType::Http => {}
                TransportType::Ble => self.openid_ble.retract_proof(proof).await?,
                TransportType::Mqtt => {
                    self.openid_mqtt
                        .as_ref()
                        .ok_or_else(|| {
                            VerificationProtocolError::Failed(
                                "MQTT not configured for retract proof".to_string(),
                            )
                        })?
                        .retract_proof(proof)
                        .await?;
                }
            }
        }

        Ok(())
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        let did_methods = vec![
            DidType::Key,
            DidType::Jwk,
            DidType::Web,
            DidType::MDL,
            DidType::WebVh,
        ];

        VerificationProtocolCapabilities {
            supported_transports: vec!["BLE".to_owned(), "MQTT".to_owned()],
            did_methods,
        }
    }
}

fn get_transport(proof: &Proof) -> Result<Vec<TransportType>, VerificationProtocolError> {
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
            .map_err(VerificationProtocolError::Other)?;

        data.transport
    } else {
        vec![proof.transport.clone()]
    };

    transport
        .into_iter()
        .map(|t| TransportType::try_from(t.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| VerificationProtocolError::Failed(format!("Invalid transport type: {err}")))
}

fn merge_query_params(mut first: Url, second: Url) -> Url {
    let mut query_params: HashMap<_, _> = second.query_pairs().into_owned().collect();

    query_params.extend(first.query_pairs().into_owned());

    first.query_pairs_mut().clear();

    first.query_pairs_mut().extend_pairs(query_params);

    first
}
