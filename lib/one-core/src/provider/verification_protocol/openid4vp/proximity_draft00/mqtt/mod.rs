use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use dto::OpenID4VPMqttQueryParams;
use futures::future::{BoxFuture, Shared};
use model::{MQTTOpenID4VPInteractionDataHolder, MQTTOpenId4VpResponse, MQTTSessionKeys};
use oidc_mqtt_verifier::{mqtt_verifier_flow, Topics};
use one_crypto::utilities::generate_random_bytes;
use serde::Deserialize;
use shared_types::{DidValue, KeyId, ProofId};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use url::Url;

use super::key_agreement_key::KeyAgreementKey;
use super::{
    create_interaction_and_proof, create_presentation, prepare_proof_share,
    CreatePresentationParams, OpenID4VPProximityDraft00Params, ProofShareParams,
};
use crate::common_mapper::{get_or_create_did, DidRole};
use crate::config::core_config::{CoreConfig, TransportType, VerificationProtocolType};
use crate::model::did::{Did, KeyRole};
use crate::model::interaction::InteractionId;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, HolderBindingCtx, TokenVerifier,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::mqtt_client::{MqttClient, MqttTopic};
use crate::provider::verification_protocol::dto::PresentationDefinitionResponseDTO;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft20::model::OpenID4VP20AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::IdentityRequest;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::peer_encryption::PeerEncryption;
use crate::provider::verification_protocol::openid4vp::{
    get_presentation_definition_with_local_credentials, InvitationResponseDTO,
    OpenID4VPPresentationDefinition, PresentedCredential, UpdateResponse,
};
use crate::provider::verification_protocol::{
    deserialize_interaction_data, FormatMapper, TypeToDescriptorMapper,
};
use crate::repository::did_repository::DidRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::storage_proxy::StorageAccess;
use crate::util::key_verification::KeyVerification;

pub mod dto;
pub mod model;
mod oidc_mqtt_verifier;

#[cfg(test)]
mod test;

pub(crate) struct OpenId4VcMqtt {
    mqtt_client: Arc<dyn MqttClient>,
    config: Arc<CoreConfig>,
    params: ConfigParams,
    openid_params: OpenID4VPProximityDraft00Params,
    handle: Mutex<HashMap<ProofId, SubscriptionHandle>>,

    interaction_repository: Arc<dyn InteractionRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    did_repository: Arc<dyn DidRepository>,

    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigParams {
    broker_url: Url,
}

struct SubscriptionHandle {
    task_handle: tokio::task::JoinHandle<Result<(), VerificationProtocolError>>,
}

impl OpenId4VcMqtt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        mqtt_client: Arc<dyn MqttClient>,
        config: Arc<CoreConfig>,
        params: ConfigParams,
        openid_params: OpenID4VPProximityDraft00Params,
        interaction_repository: Arc<dyn InteractionRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        did_repository: Arc<dyn DidRepository>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
    ) -> OpenId4VcMqtt {
        OpenId4VcMqtt {
            mqtt_client,
            config,
            params,
            openid_params,
            handle: Mutex::new(HashMap::new()),
            interaction_repository,
            did_repository,
            key_algorithm_provider,
            proof_repository,
            formatter_provider,
            did_method_provider,
            key_provider,
        }
    }

    async fn subscribe_to_topic(
        &self,
        topic: String,
    ) -> Result<Box<dyn MqttTopic>, VerificationProtocolError> {
        let (host, port) = extract_host_and_port(&self.params.broker_url)?;

        self
            .mqtt_client
            .subscribe(
                host,
                port,
                topic.clone(),
            )
            .await
            .map_err(move |error| {
                tracing::error!(%error, "Failed to subscribe to `{topic}` topic during proof sharing");
                VerificationProtocolError::Failed(format!("Failed to subscribe to `{topic}` topic"))
            })
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    pub(crate) async fn start_detached_subscriber(
        &self,
        topic_prefix: String,
        keypair: KeyAgreementKey,
        proof: Proof,
        presentation_definition: OpenID4VPPresentationDefinition,
        verifier_did: Did,
        auth_fn: AuthenticationFn,
        interaction_id: InteractionId,
        cancellation_token: CancellationToken,
        on_submission_callback: Option<Shared<BoxFuture<'static, ()>>>,
    ) -> Result<(), VerificationProtocolError> {
        let (identify, presentation_definition_topic, accept, reject) = tokio::try_join!(
            self.subscribe_to_topic(topic_prefix.clone() + "/presentation-submission/identify"),
            self.subscribe_to_topic(topic_prefix.clone() + "/presentation-definition"),
            self.subscribe_to_topic(topic_prefix.clone() + "/presentation-submission/accept"),
            self.subscribe_to_topic(topic_prefix + "/presentation-submission/reject"),
        )?;

        let topics = Topics {
            identify: Mutex::from(identify),
            presentation_definition: Mutex::from(presentation_definition_topic),
            accept: Mutex::from(accept),
            reject: Mutex::from(reject),
        };

        let proof_id = proof.id;
        let handle = tokio::spawn(
            mqtt_verifier_flow(
                topics,
                keypair,
                proof,
                presentation_definition,
                auth_fn,
                verifier_did,
                self.proof_repository.clone(),
                self.interaction_repository.clone(),
                interaction_id,
                cancellation_token,
                on_submission_callback,
            )
            .in_current_span(),
        );

        let old = self.handle.lock().await.insert(
            proof_id,
            SubscriptionHandle {
                task_handle: handle,
            },
        );

        if let Some(old) = old {
            old.task_handle.abort()
        };

        Ok(())
    }

    pub(crate) fn holder_get_holder_binding_context(
        &self,
        _proof: &Proof,
        context: serde_json::Value,
    ) -> Result<Option<HolderBindingCtx>, VerificationProtocolError> {
        let interaction_data: MQTTOpenID4VPInteractionDataHolder =
            serde_json::from_value(context).map_err(VerificationProtocolError::JsonError)?;

        Ok(Some(HolderBindingCtx {
            nonce: interaction_data.nonce,
            audience: interaction_data.client_id,
        }))
    }

    pub(crate) async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        context: serde_json::Value,
        storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
        let interaction_data: MQTTOpenID4VPInteractionDataHolder =
            serde_json::from_value(context).map_err(VerificationProtocolError::JsonError)?;

        let presentation_definition =
            interaction_data
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

    pub(crate) fn holder_can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        self.openid_params.url_scheme == url.scheme()
            && query_has_key("brokerUrl")
            && query_has_key("key")
            && query_has_key("topicId")
    }

    pub(crate) async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        _storage_access: &StorageAccess,
        _transport: String,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        tracing::debug!("MQTT Handle invitation: {url}");

        if !self.holder_can_handle(&url) {
            return Err(VerificationProtocolError::Failed(
                "No OpenID4VC over MQTT query params detected".to_string(),
            ));
        }

        let query = url
            .query()
            .ok_or(VerificationProtocolError::InvalidRequest(
                "Query cannot be empty".to_string(),
            ))?;

        let OpenID4VPMqttQueryParams {
            broker_url,
            key,
            topic_id,
        } = serde_qs::from_str(query)
            .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))?;

        let (host, port) = extract_host_and_port(&broker_url)?;

        let verifier_public_key = hex::decode(&key)
            .context("Failed to decode verifier public key")
            .map_err(VerificationProtocolError::Transport)?
            .as_slice()
            .try_into()
            .context("Invalid verifier public key length")
            .map_err(VerificationProtocolError::Transport)?;

        let session_keys = generate_session_keys(verifier_public_key)?;
        let encryption = PeerEncryption::new(
            session_keys.sender_key.clone(),
            session_keys.receiver_key.clone(),
            session_keys.nonce,
        );

        let identity_request = IdentityRequest {
            key: session_keys.public_key.to_owned(),
            nonce: session_keys.nonce.to_owned(),
        };
        let identity_request_nonce = hex::encode(identity_request.nonce);

        tracing::debug!("Identity request");

        let identify_topic = self
            .mqtt_client
            .subscribe(
                host.to_string(),
                port,
                format!("/proof/{topic_id}/presentation-submission/identify"),
            )
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        identify_topic
            .send(identity_request.encode())
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        tracing::debug!("Presentation request");

        let mut presentation_definition_topic = self
            .mqtt_client
            .subscribe(
                host.to_string(),
                port,
                format!("/proof/{topic_id}/presentation-definition"),
            )
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let presentation_request_bytes = presentation_definition_topic
            .recv()
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        tracing::debug!("Presentation request received");

        let verification_fn = Box::new(KeyVerification {
            did_method_provider: self.did_method_provider.clone(),
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });

        let presentation_request: String = encryption
            .decrypt(&presentation_request_bytes)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let verification_fn: Box<dyn TokenVerifier> = verification_fn;
        let presentation_request = Jwt::<OpenID4VP20AuthorizationRequest>::build_from_token(
            &presentation_request,
            Some(&verification_fn),
            None,
        )
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let organisation_as_option = Some(organisation.clone());
        let verifier_did = {
            let did_value =
                DidValue::from_did_url(presentation_request.payload.custom.client_id.as_str())
                    .map_err(|_| {
                        VerificationProtocolError::InvalidRequest(format!(
                            "invalid client_id: {}",
                            presentation_request.payload.custom.client_id
                        ))
                    })?;

            get_or_create_did(
                &*self.did_method_provider,
                &*self.did_repository,
                &organisation_as_option,
                &did_value,
                DidRole::Verifier,
            )
            .await
            .map_err(|_| {
                VerificationProtocolError::Failed(format!(
                    "failed to resolve or create did: {}",
                    presentation_request.payload.custom.client_id
                ))
            })?
        };

        let mqtt_interaction_data = MQTTOpenID4VPInteractionDataHolder {
            broker_url: host.to_string(),
            broker_port: port,
            client_id: presentation_request.payload.custom.client_id,
            nonce: presentation_request.payload.custom.nonce.ok_or(
                VerificationProtocolError::Failed("missing nonce".to_string()),
            )?,
            session_keys,
            presentation_definition: presentation_request.payload.custom.presentation_definition,
            identity_request_nonce,
            topic_id,
        };

        let interaction_data = Some(serde_json::to_vec(&mqtt_interaction_data).map_err(|err| {
            VerificationProtocolError::Failed(format!("Interaction data: {err}"))
        })?);

        let (interaction_id, proof) = create_interaction_and_proof(
            interaction_data,
            organisation,
            Some(verifier_did),
            VerificationProtocolType::OpenId4VpDraft20,
            TransportType::Mqtt,
            &*self.interaction_repository,
        )
        .await?;

        Ok(InvitationResponseDTO {
            interaction_id,
            proof,
        })
    }

    pub(crate) async fn holder_reject_proof(
        &self,
        proof: &Proof,
    ) -> Result<(), VerificationProtocolError> {
        let interaction_data: MQTTOpenID4VPInteractionDataHolder = deserialize_interaction_data(
            proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let encryption = PeerEncryption::new(
            interaction_data.session_keys.sender_key,
            interaction_data.session_keys.receiver_key,
            interaction_data.session_keys.nonce,
        );

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let encrypted = encryption
            .encrypt(&now)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let reject_topic_name = format!(
            "/proof/{}/presentation-submission/reject",
            interaction_data.topic_id
        );

        let reject_topic = self
            .mqtt_client
            .subscribe(
                interaction_data.broker_url,
                interaction_data.broker_port,
                reject_topic_name,
            )
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        reject_topic
            .send(encrypted)
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

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
        tracing::debug!("Called submit proof");

        let interaction_data: MQTTOpenID4VPInteractionDataHolder = deserialize_interaction_data(
            proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let (vp_token, presentation_submission) = create_presentation(CreatePresentationParams {
            credential_presentations,
            presentation_definition: interaction_data.presentation_definition.as_ref(),
            holder_did,
            key,
            jwk_key_id,
            client_id: &interaction_data.client_id,
            identity_request_nonce: Some(&interaction_data.identity_request_nonce),
            nonce: &interaction_data.nonce,
            formatter_provider: &*self.formatter_provider,
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            key_provider: &*self.key_provider,
        })
        .await?;

        let response = MQTTOpenId4VpResponse {
            vp_token,
            presentation_submission,
        };

        let encryption = PeerEncryption::new(
            interaction_data.session_keys.sender_key,
            interaction_data.session_keys.receiver_key,
            interaction_data.session_keys.nonce,
        );

        let encrypted = encryption
            .encrypt(&response)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let presentation_submission_topic = self
            .mqtt_client
            .subscribe(
                interaction_data.broker_url.to_string(),
                interaction_data.broker_port,
                format!(
                    "/proof/{}/presentation-submission/accept",
                    interaction_data.topic_id
                ),
            )
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        presentation_submission_topic
            .send(encrypted)
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        Ok(UpdateResponse { update_proof: None })
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    pub(crate) async fn verifier_share_proof(
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

        let url = {
            let mut url: Url = format!("{}://connect", self.openid_params.url_scheme)
                .parse()
                .map_err(|e| {
                    VerificationProtocolError::Failed(format!("Failed to parse url: `{e}`"))
                })?;
            url.query_pairs_mut()
                .append_pair("key", &hex::encode(key_agreement.public_key_bytes()))
                .append_pair(
                    "brokerUrl",
                    self.params.broker_url.as_str().trim_end_matches('/'),
                )
                .append_pair("topicId", &interaction_id.to_string());

            url
        };

        if !self
            .config
            .transport
            .mqtt_enabled_for(TransportType::Mqtt.as_ref())
        {
            return Err(VerificationProtocolError::Disabled(
                "MQTT transport is disabled".to_string(),
            ));
        }

        let topic_prefix = format!("/proof/{}", interaction_id);
        self.start_detached_subscriber(
            topic_prefix,
            key_agreement,
            proof.clone(),
            presentation_definition,
            verifier_did.clone(),
            auth_fn,
            interaction_id,
            cancellation_token,
            on_submission_callback,
        )
        .await?;

        Ok(url)
    }

    pub(crate) async fn retract_proof(
        &self,
        proof: &Proof,
    ) -> Result<(), VerificationProtocolError> {
        if let Some(old) = self.handle.lock().await.remove(&proof.id) {
            old.task_handle.abort()
        };

        Ok(())
    }
}

fn generate_session_keys(
    verifier_public_key: [u8; 32],
) -> Result<MQTTSessionKeys, VerificationProtocolError> {
    let key_agreement_key = KeyAgreementKey::new_random();
    let public_key = key_agreement_key.public_key_bytes();
    let nonce = generate_random_bytes::<12>();

    let (receiver_key, sender_key) = key_agreement_key
        .derive_session_secrets(verifier_public_key, nonce)
        .map_err(VerificationProtocolError::Transport)?;

    Ok(MQTTSessionKeys {
        public_key,
        receiver_key,
        sender_key,
        nonce,
    })
}

fn extract_host_and_port(url: &Url) -> Result<(String, u16), VerificationProtocolError> {
    url.host_str()
        .map(ToString::to_string)
        .zip(url.port())
        .ok_or_else(|| {
            VerificationProtocolError::Failed(format!("Invalid URL `{url}`. Missing host or port"))
        })
}
