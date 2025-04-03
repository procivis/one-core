use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use futures::future::{BoxFuture, Shared};
use model::{MQTTOpenID4VPInteractionDataHolder, MQTTOpenId4VpResponse, MQTTSessionKeys};
use oidc_mqtt_verifier::{mqtt_verifier_flow, Topics};
use rand::rngs::OsRng;
use rand::Rng;
use serde::Deserialize;
use shared_types::{DidValue, KeyId, ProofId};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use url::Url;
use uuid::Uuid;

use super::mapper::{
    create_open_id_for_vp_presentation_definition, create_presentation_submission,
};
use super::model::{
    InvitationResponseDTO, OpenID4VPPresentationDefinition, OpenID4VpParams, PresentedCredential,
    UpdateResponse,
};
use crate::common_mapper::{get_or_create_did, DidRole};
use crate::config::core_config::{CoreConfig, TransportType, VerificationProtocolType};
use crate::model::did::{Did, KeyRole};
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    OID4VPHandover, SessionTranscript,
};
use crate::provider::credential_formatter::model::{
    AuthenticationFn, FormatPresentationCtx, TokenVerifier,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::mqtt_client::{MqttClient, MqttTopic};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::common::to_cbor;
use crate::provider::verification_protocol::mapper::proof_from_handle_invitation;
use crate::provider::verification_protocol::openid4vc::dto::OpenID4VPMqttQueryParams;
use crate::provider::verification_protocol::openid4vc::key_agreement_key::KeyAgreementKey;
use crate::provider::verification_protocol::openid4vc::model::OpenID4VPAuthorizationRequestParams;
use crate::provider::verification_protocol::openid4vc::openidvc_ble::IdentityRequest;
use crate::provider::verification_protocol::openid4vc::openidvc_http::mappers::map_credential_formats_to_presentation_format;
use crate::provider::verification_protocol::openid4vc::peer_encryption::PeerEncryption;
use crate::provider::verification_protocol::{
    deserialize_interaction_data, FormatMapper, TypeToDescriptorMapper,
};
use crate::repository::did_repository::DidRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::util::key_verification::KeyVerification;

pub mod model;
mod oidc_mqtt_verifier;

#[cfg(test)]
mod test;

pub struct OpenId4VcMqtt {
    mqtt_client: Arc<dyn MqttClient>,
    config: Arc<CoreConfig>,
    params: ConfigParams,
    openid_params: OpenID4VpParams,
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
pub struct ConfigParams {
    broker_url: Url,
}

struct SubscriptionHandle {
    task_handle: tokio::task::JoinHandle<Result<(), VerificationProtocolError>>,
}

impl OpenId4VcMqtt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mqtt_client: Arc<dyn MqttClient>,
        config: Arc<CoreConfig>,
        params: ConfigParams,
        openid_params: OpenID4VpParams,
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

    pub fn holder_can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        self.openid_params.url_scheme == url.scheme()
            && query_has_key("brokerUrl")
            && query_has_key("key")
            && query_has_key("topicId")
    }

    pub async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
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
        let presentation_request = Jwt::<OpenID4VPAuthorizationRequestParams>::build_from_token(
            &presentation_request,
            Some(&verification_fn),
            None,
        )
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let organisation = Some(organisation);
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
                &organisation,
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

        let interaction_data = MQTTOpenID4VPInteractionDataHolder {
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

        let now = OffsetDateTime::now_utc();
        let interaction = Interaction {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            host: None,
            data: Some(serde_json::to_vec(&interaction_data).map_err(|err| {
                VerificationProtocolError::Failed(format!("Interaction data: {err}"))
            })?),
            organisation,
        };

        let interaction_id = self
            .interaction_repository
            .create_interaction(interaction.clone())
            .await
            .map_err(|error| VerificationProtocolError::Failed(error.to_string()))?;

        let proof_id: ProofId = Uuid::new_v4().into();
        let proof = proof_from_handle_invitation(
            &proof_id,
            VerificationProtocolType::OpenId4VpDraft20.as_ref(),
            None,
            Some(verifier_did),
            interaction,
            OffsetDateTime::now_utc(),
            None,
            TransportType::Mqtt.as_ref(),
            ProofStateEnum::Requested,
        );

        Ok(InvitationResponseDTO {
            interaction_id,
            proof,
        })
    }

    pub async fn holder_reject_proof(
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
    pub async fn holder_submit_proof(
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

        let tokens: Vec<String> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.presentation.to_owned())
            .collect();

        let token_formats: Vec<String> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.credential_schema.format.to_owned())
            .collect();

        let (format, oidc_format) =
            map_credential_formats_to_presentation_format(&credential_presentations)?;

        let presentation_formatter = self.formatter_provider.get_formatter(&format).ok_or(
            VerificationProtocolError::Failed("Formatter not found".to_string()),
        )?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(key, jwk_key_id, self.key_algorithm_provider.clone())
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let presentation_definition_id = interaction_data
            .presentation_definition
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "Missing presentation definition".into(),
            ))?
            .id
            .to_owned();

        let presentation_submission = create_presentation_submission(
            presentation_definition_id,
            credential_presentations,
            &oidc_format,
        )?;

        let mut ctx = FormatPresentationCtx {
            nonce: Some(interaction_data.nonce.clone()),
            token_formats: Some(token_formats),
            ..Default::default()
        };

        if format == "MDOC" {
            ctx.mdoc_session_transcript = Some(
                to_cbor(&SessionTranscript {
                    handover: OID4VPHandover::compute(
                        &interaction_data.client_id,
                        &interaction_data.client_id,
                        &interaction_data.nonce,
                        &interaction_data.identity_request_nonce,
                    )
                    .into(),
                    device_engagement_bytes: None,
                    e_reader_key_bytes: None,
                })
                .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?,
            );
        }

        let vp_token = presentation_formatter
            .format_presentation(&tokens, &holder_did.did, &key.key_type, auth_fn, ctx)
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

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
    pub async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        type_to_descriptor: TypeToDescriptorMapper,
        interaction_id: InteractionId,
        key_agreement: KeyAgreementKey,
        cancellation_token: CancellationToken,
        callback: Option<Shared<BoxFuture<'static, ()>>>,
    ) -> Result<Url, VerificationProtocolError> {
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

        let presentation_definition = create_open_id_for_vp_presentation_definition(
            interaction_id,
            proof,
            type_to_descriptor,
            format_to_type_mapper,
            &*self.formatter_provider,
        )?;

        if !self
            .config
            .transport
            .mqtt_enabled_for(TransportType::Mqtt.as_ref())
        {
            return Err(VerificationProtocolError::Disabled(
                "MQTT transport is disabled".to_string(),
            ));
        }

        let Some(verifier_did) = proof.verifier_did.as_ref() else {
            return Err(VerificationProtocolError::InvalidRequest(format!(
                "Verifier DID missing for proof {}",
                { proof.id }
            )));
        };

        let Ok(verifier_key) = verifier_did.find_key(&key_id, KeyRole::Authentication) else {
            return Err(VerificationProtocolError::InvalidRequest(format!(
                "Verifier key {} not found for proof {}",
                key_id,
                { proof.id }
            )));
        };

        let verifier_jwk_key_id = self
            .did_method_provider
            .get_verification_method_id_from_did_and_key(verifier_did, verifier_key)
            .await
            .map_err(|err| {
                VerificationProtocolError::Failed(format!("Failed resolving did {err}"))
            })?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(
                verifier_key,
                Some(verifier_jwk_key_id),
                self.key_algorithm_provider.clone(),
            )
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
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
            callback,
        )
        .await?;

        Ok(url)
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
    async fn start_detached_subscriber(
        &self,
        topic_prefix: String,
        keypair: KeyAgreementKey,
        proof: Proof,
        presentation_definition: OpenID4VPPresentationDefinition,
        verifier_did: Did,
        auth_fn: AuthenticationFn,
        interaction_id: InteractionId,
        cancellation_token: CancellationToken,
        callback: Option<Shared<BoxFuture<'static, ()>>>,
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
                callback,
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

    pub async fn retract_proof(&self, proof_id: &ProofId) {
        if let Some(old) = self.handle.lock().await.remove(proof_id) {
            old.task_handle.abort()
        };
    }
}

fn generate_session_keys(
    verifier_public_key: [u8; 32],
) -> Result<MQTTSessionKeys, VerificationProtocolError> {
    let key_agreement_key = KeyAgreementKey::new_random();
    let public_key = key_agreement_key.public_key_bytes();
    let nonce: [u8; 12] = OsRng.gen();

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
