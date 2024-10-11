use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use futures::TryFutureExt;
use oidc_mqtt_verifier::{mqtt_verifier_flow, Topics};
use one_crypto::utilities;
use rand::rngs::OsRng;
use rand::Rng;
use serde::Deserialize;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::Instrument;
use url::Url;
use uuid::Uuid;

use super::mapper::{
    create_open_id_for_vp_presentation_definition, create_presentation_submission,
};
use super::model::{
    InvitationResponseDTO, MQTTOpenId4VpResponse, MqttOpenId4VpRequest, PresentedCredential,
    UpdateResponse,
};
use crate::config::core_config::CoreConfig;
use crate::model::did::Did;
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofState, ProofStateEnum, UpdateProofRequest};
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    OID4VPHandover, SessionTranscript,
};
use crate::provider::credential_formatter::model::FormatPresentationCtx;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::provider::exchange_protocol::iso_mdl::common::to_cbor;
use crate::provider::exchange_protocol::mapper::proof_from_handle_invitation;
use crate::provider::exchange_protocol::openid4vc::dto::OpenID4VPMqttQueryParams;
use crate::provider::exchange_protocol::openid4vc::key_agreement_key::KeyAgreementKey;
use crate::provider::exchange_protocol::openid4vc::model::{
    MQTTOpenID4VPInteractionData, MQTTSessionKeys,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_ble::IdentityRequest;
use crate::provider::exchange_protocol::openid4vc::openidvc_http::mappers::map_credential_formats_to_presentation_format;
use crate::provider::exchange_protocol::openid4vc::peer_encryption::PeerEncryption;
use crate::provider::exchange_protocol::{
    deserialize_interaction_data, FormatMapper, TypeToDescriptorMapper,
};
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::mqtt_client::{MqttClient, MqttTopic};
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::util::oidc::create_core_to_oicd_format_map;

mod oidc_mqtt_verifier;

#[cfg(test)]
mod test;

pub struct OpenId4VcMqtt {
    mqtt_client: Arc<dyn MqttClient>,
    config: Arc<CoreConfig>,
    params: ConfigParams,
    handle: Mutex<Option<SubscriptionHandle>>,

    interaction_repository: Arc<dyn InteractionRepository>,
    proof_repository: Arc<dyn ProofRepository>,

    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigParams {
    broker_url: Url,
}

struct SubscriptionHandle {
    task_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl OpenId4VcMqtt {
    pub fn new(
        mqtt_client: Arc<dyn MqttClient>,
        config: Arc<CoreConfig>,
        params: ConfigParams,
        interaction_repository: Arc<dyn InteractionRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
    ) -> OpenId4VcMqtt {
        OpenId4VcMqtt {
            mqtt_client,
            config,
            params,
            handle: Mutex::new(None),
            interaction_repository,
            proof_repository,
            formatter_provider,
            key_provider,
        }
    }

    pub fn can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        url.scheme() == "openid4vp"
            && query_has_key("brokerUrl")
            && query_has_key("key")
            && query_has_key("proofId")
    }

    pub async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        if !self.can_handle(&url) {
            return Err(ExchangeProtocolError::Failed(
                "No OpenID4VC over MQTT query params detected".to_string(),
            ));
        }

        let query = url.query().ok_or(ExchangeProtocolError::InvalidRequest(
            "Query cannot be empty".to_string(),
        ))?;

        let OpenID4VPMqttQueryParams {
            broker_url,
            key,
            proof_id,
        } = serde_qs::from_str(query)
            .map_err(|e| ExchangeProtocolError::InvalidRequest(e.to_string()))?;

        let (host, port) = extract_host_and_port(&broker_url)?;

        let verifier_public_key = hex::decode(&key)
            .context("Failed to decode verifier public key")
            .map_err(ExchangeProtocolError::Transport)?
            .as_slice()
            .try_into()
            .context("Invalid verifier public key length")
            .map_err(ExchangeProtocolError::Transport)?;

        let now = OffsetDateTime::now_utc();
        let interaction = Interaction {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            host: None,
            data: None,
            organisation: Some(organisation.clone()),
        };
        let interaction_id = self
            .interaction_repository
            .create_interaction(interaction.clone())
            .await
            .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

        let now = OffsetDateTime::now_utc();
        let proof = proof_from_handle_invitation(
            &proof_id,
            "OPENID4VC",
            None,
            None,
            interaction,
            now,
            None,
            "MQTT",
            ProofStateEnum::Created,
        );

        let mqtt_client = self.mqtt_client.clone();
        let interaction_repository = self.interaction_repository.clone();
        let proof_repository = self.proof_repository.clone();

        tokio::spawn(
            async move {
                let mut presentation_definition_topic = mqtt_client
                    .subscribe(
                        host.to_string(),
                        port,
                        format!("/proof/{}/presentation-definition", proof_id),
                    )
                    .await
                    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

                let session_keys = generate_session_keys(verifier_public_key)?;
                let encryption = PeerEncryption::new(
                    session_keys.sender_key,
                    session_keys.receiver_key,
                    session_keys.nonce,
                );

                let identity_request = IdentityRequest {
                    key: session_keys.public_key.to_owned(),
                    nonce: session_keys.nonce.to_owned(),
                };
                let identity_request_nonce = hex::encode(identity_request.nonce);

                {
                    let identify_topic = mqtt_client
                        .subscribe(
                            host.to_string(),
                            port,
                            format!("/proof/{}/presentation-submission/identify", proof_id),
                        )
                        .await
                        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

                    identify_topic
                        .send(identity_request.encode())
                        .await
                        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
                }
                let presentation_request_bytes = presentation_definition_topic
                    .recv()
                    .await
                    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

                let presentation_request: MqttOpenId4VpRequest = encryption
                    .decrypt(&presentation_request_bytes)
                    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

                let interaction_data = MQTTOpenID4VPInteractionData {
                    broker_url: host.to_string(),
                    broker_port: port,
                    client_id: presentation_request.client_id,
                    nonce: presentation_request.nonce,
                    session_keys: session_keys.to_owned(),
                    presentation_definition: Some(presentation_request.presentation_definition),
                    identity_request_nonce,
                    proof_id,
                };

                let now = OffsetDateTime::now_utc();
                interaction_repository
                    .update_interaction(Interaction {
                        id: interaction_id,
                        created_date: now,
                        last_modified: now,
                        host: None,
                        data: Some(
                            serde_json::to_vec(&interaction_data)
                                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?,
                        ),
                        organisation: Some(organisation),
                    })
                    .await
                    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

                let now = OffsetDateTime::now_utc();
                proof_repository
                    .update_proof(
                        &proof_id,
                        UpdateProofRequest {
                            state: Some(ProofState {
                                created_date: now,
                                last_modified: now,
                                state: ProofStateEnum::Pending,
                            }),
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

                Ok::<_, ExchangeProtocolError>(())
            }
            .inspect_err(|error| tracing::error!(%error, "handle_invitation detached task failed")),
        );

        Ok(InvitationResponseDTO::ProofRequest {
            interaction_id,
            proof: Box::new(proof),
        })
    }

    pub async fn reject_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError> {
        let interaction_data: MQTTOpenID4VPInteractionData = deserialize_interaction_data(
            proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let encryption = PeerEncryption::new(
            interaction_data.session_keys.sender_key,
            interaction_data.session_keys.receiver_key,
            interaction_data.session_keys.nonce,
        );

        let encrypted = encryption
            .encrypt(now)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let reject_topic_name = format!("/proof/{}/presentation-submission/reject", proof.id);
        let reject_topic = self
            .mqtt_client
            .subscribe(
                interaction_data.broker_url,
                interaction_data.broker_port,
                reject_topic_name,
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
        reject_topic
            .send(encrypted)
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        format_map: HashMap<String, String>,
        presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        let interaction_data: MQTTOpenID4VPInteractionData = deserialize_interaction_data(
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

        let formats: HashMap<&str, &str> = credential_presentations
            .iter()
            .map(|presented_credential| {
                format_map
                    .get(presented_credential.credential_schema.format.as_str())
                    .map(|mapped| {
                        (
                            mapped.as_str(),
                            presented_credential.credential_schema.format.as_str(),
                        )
                    })
            })
            .collect::<Option<_>>()
            .ok_or_else(|| ExchangeProtocolError::Failed("missing format mapping".into()))?;

        let (_, format, oidc_format) =
            map_credential_formats_to_presentation_format(&formats, &format_map)?;

        let presentation_format =
            presentation_format_map
                .get(&oidc_format)
                .ok_or(ExchangeProtocolError::Failed(format!(
                    "Missing presentation format for `{oidc_format}`"
                )))?;

        let presentation_formatter = self
            .formatter_provider
            .get_formatter(presentation_format)
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
            &oidc_format,
            create_core_to_oicd_format_map(),
        )?;

        let mut ctx = FormatPresentationCtx {
            nonce: Some(interaction_data.nonce.clone()),
            token_formats: Some(token_formats),
            vc_format_map: format_map,
            ..Default::default()
        };

        if format == "MDOC" {
            let mdoc_generated_nonce = utilities::generate_nonce();

            ctx.mdoc_session_transcript = Some(
                to_cbor(&SessionTranscript {
                    handover: OID4VPHandover::compute(
                        &interaction_data.client_id,
                        &interaction_data.client_id,
                        &interaction_data.nonce,
                        &mdoc_generated_nonce,
                    )
                    .into(),
                    device_engagement_bytes: None,
                    e_reader_key_bytes: None,
                })
                .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?,
            );
        }

        let vp_token = presentation_formatter
            .format_presentation(&tokens, &holder_did.did, &key.key_type, auth_fn, ctx)
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

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
            .encrypt(response)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let presentation_submission_topic = self
            .mqtt_client
            .subscribe(
                interaction_data.broker_url.to_string(),
                interaction_data.broker_port,
                format!("/proof/{}/presentation-submission/accept", proof.id),
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        presentation_submission_topic
            .send(encrypted)
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let now = OffsetDateTime::now_utc();
        self.proof_repository
            .update_proof(
                &proof.id,
                UpdateProofRequest {
                    state: Some(ProofState {
                        created_date: now,
                        last_modified: now,
                        state: ProofStateEnum::Accepted,
                    }),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        Ok(UpdateResponse {
            result: (),
            update_proof: None,
            create_did: None,
            update_credential: None,
            update_credential_schema: None,
        })
    }

    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    pub async fn share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        type_to_descriptor: TypeToDescriptorMapper,
        interaction_id: InteractionId,
        key_agreement: KeyAgreementKey,
    ) -> Result<Url, ExchangeProtocolError> {
        let url = {
            let mut url: Url = "openid4vp://".parse().unwrap();
            url.query_pairs_mut()
                .append_pair("key", &hex::encode(key_agreement.public_key_bytes()))
                .append_pair(
                    "brokerUrl",
                    self.params.broker_url.as_str().trim_end_matches('/'),
                )
                .append_pair("proofId", &proof.id.to_string());

            url
        };

        let presentation_definition = create_open_id_for_vp_presentation_definition(
            interaction_id,
            proof,
            type_to_descriptor,
            format_to_type_mapper,
        )?;
        let presentation_request = MqttOpenId4VpRequest {
            client_id: utilities::generate_alphanumeric(32),
            nonce: utilities::generate_nonce(),
            presentation_definition,
        };

        if !self.config.transport.mqtt_enabled_for(&proof.transport) {
            return Err(ExchangeProtocolError::Disabled(
                "MQTT transport is disabled".to_string(),
            ));
        }

        let topic_prefix = format!("/proof/{}", proof.id);
        self.start_detached_subscriber(
            topic_prefix,
            key_agreement,
            proof.clone(),
            presentation_request,
            interaction_id,
        )
        .await?;

        Ok(url)
    }

    async fn subscribe_to_topic(
        &self,
        topic: String,
    ) -> Result<Box<dyn MqttTopic>, ExchangeProtocolError> {
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
                ExchangeProtocolError::Failed(format!("Failed to subscribe to `{topic}` topic"))
            })
    }

    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    async fn start_detached_subscriber(
        &self,
        topic_prefix: String,
        keypair: KeyAgreementKey,
        proof: Proof,
        presentation_request: MqttOpenId4VpRequest,
        interaction_id: InteractionId,
    ) -> Result<(), ExchangeProtocolError> {
        let (identify, presentation_definition_topic, accept, reject) = tokio::try_join!(
            self.subscribe_to_topic(topic_prefix.clone() + "/presentation-submission/identify"),
            self.subscribe_to_topic(topic_prefix.clone() + "/presentation-definition"),
            self.subscribe_to_topic(topic_prefix.clone() + "/presentation-submission/accept"),
            self.subscribe_to_topic(topic_prefix + "/presentation-submission/reject"),
        )?;

        let topics = Topics {
            identify,
            presentation_definition: presentation_definition_topic,
            accept,
            reject,
        };

        let handle = tokio::spawn(
            mqtt_verifier_flow(
                topics,
                keypair,
                proof,
                presentation_request,
                self.proof_repository.clone(),
                self.interaction_repository.clone(),
                interaction_id,
            )
            .in_current_span(),
        );

        let old = self.handle.lock().await.replace(SubscriptionHandle {
            task_handle: handle,
        });

        if let Some(old) = old {
            old.task_handle.abort()
        };

        Ok(())
    }

    pub async fn retract_proof(&self) {
        if let Some(old) = self.handle.lock().await.take() {
            old.task_handle.abort()
        };
    }
}

fn generate_session_keys(
    verifier_public_key: [u8; 32],
) -> Result<MQTTSessionKeys, ExchangeProtocolError> {
    let key_agreement_key = KeyAgreementKey::new_random();
    let public_key = key_agreement_key.public_key_bytes();
    let nonce: [u8; 12] = OsRng.gen();

    let (receiver_key, sender_key) = key_agreement_key
        .derive_session_secrets(verifier_public_key, nonce)
        .map_err(ExchangeProtocolError::Transport)?;

    Ok(MQTTSessionKeys {
        public_key,
        receiver_key,
        sender_key,
        nonce,
    })
}

fn extract_host_and_port(url: &Url) -> Result<(String, u16), ExchangeProtocolError> {
    url.host_str()
        .map(ToString::to_string)
        .zip(url.port())
        .ok_or_else(|| {
            ExchangeProtocolError::Failed(format!("Invalid URL `{url}`. Missing host or port"))
        })
}
