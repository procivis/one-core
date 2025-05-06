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
use shared_types::{KeyId, ProofId};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use super::model::{
    default_presentation_url_scheme, OpenID4VPPresentationDefinition, OpenID4VpPresentationFormat,
    PresentationSubmissionMappingDTO,
};
use crate::config::core_config::{CoreConfig, DidType, TransportType, VerificationProtocolType};
use crate::model::did::{Did, KeyRole};
use crate::model::identifier::Identifier;
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    OID4VPHandover, SessionTranscript,
};
use crate::provider::credential_formatter::model::{
    AuthenticationFn, DetailCredential, FormatPresentationCtx, HolderBindingCtx,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::mqtt_client::MqttClient;
use crate::provider::verification_protocol::dto::{
    InvitationResponseDTO, PresentationDefinitionResponseDTO, PresentedCredential, ShareResponse,
    UpdateResponse, VerificationProtocolCapabilities,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::common::to_cbor;
use crate::provider::verification_protocol::mapper::proof_from_handle_invitation;
use crate::provider::verification_protocol::openid4vp::mapper::{
    create_open_id_for_vp_presentation_definition, create_presentation_submission,
    map_credential_formats_to_presentation_format,
};
use crate::provider::verification_protocol::{
    FormatMapper, TypeToDescriptorMapper, VerificationProtocol,
};
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::proof::dto::{CreateProofInteractionData, ShareProofRequestParamsDTO};
use crate::service::storage_proxy::StorageAccess;
use crate::util::ble_resource::BleWaiter;

mod async_verifier_flow;
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
        identifier_repository: Arc<dyn IdentifierRepository>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        ble: Option<BleWaiter>,
    ) -> Self {
        let openid_ble = OpenID4VCBLE::new(
            proof_repository.clone(),
            interaction_repository.clone(),
            did_repository.clone(),
            identifier_repository.clone(),
            did_method_provider.clone(),
            formatter_provider.clone(),
            key_algorithm_provider.clone(),
            key_provider.clone(),
            ble,
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
                    identifier_repository,
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
        on_submission_callback: Option<BoxFuture<'static, ()>>,
        _params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse<serde_json::Value>, VerificationProtocolError> {
        let transport = get_transport(proof)?;
        let on_submission_callback = on_submission_callback.map(|fut| fut.shared());

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
                        on_submission_callback,
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
                    on_submission_callback,
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
                        on_submission_callback.clone(),
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
                        on_submission_callback,
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
            supported_transports: vec![TransportType::Ble, TransportType::Mqtt],
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

pub(super) async fn create_interaction_and_proof(
    interaction_data: Option<Vec<u8>>,
    organisation: Organisation,
    verifier_did: Option<Did>,
    verifier_identifier: Option<Identifier>,
    verification_protocol_type: VerificationProtocolType,
    transport_type: TransportType,
    interaction_repository: &dyn InteractionRepository,
) -> Result<(InteractionId, Proof), VerificationProtocolError> {
    let now = OffsetDateTime::now_utc();
    let interaction = Interaction {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        host: None,
        data: interaction_data,
        organisation: Some(organisation),
    };

    let interaction_id = interaction_repository
        .create_interaction(interaction.clone())
        .await
        .map_err(|error| VerificationProtocolError::Failed(error.to_string()))?;

    let proof_id: ProofId = Uuid::new_v4().into();
    Ok((
        interaction_id,
        proof_from_handle_invitation(
            &proof_id,
            verification_protocol_type.as_ref(),
            None,
            verifier_did,
            verifier_identifier,
            interaction,
            now,
            None,
            transport_type.as_ref(),
            ProofStateEnum::Requested,
        ),
    ))
}

pub(super) struct CreatePresentationParams<'a> {
    credential_presentations: Vec<PresentedCredential>,
    presentation_definition: Option<&'a OpenID4VPPresentationDefinition>,
    holder_did: &'a Did,
    key: &'a Key,
    jwk_key_id: Option<String>,

    client_id: &'a str,
    identity_request_nonce: Option<&'a str>,
    nonce: &'a str,

    formatter_provider: &'a dyn CredentialFormatterProvider,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: &'a dyn KeyProvider,
}

pub(super) async fn create_presentation(
    params: CreatePresentationParams<'_>,
) -> Result<(String, PresentationSubmissionMappingDTO), VerificationProtocolError> {
    let tokens: Vec<String> = params
        .credential_presentations
        .iter()
        .map(|presented_credential| presented_credential.presentation.to_owned())
        .collect();

    let token_formats: Vec<String> = params
        .credential_presentations
        .iter()
        .map(|presented_credential| presented_credential.credential_schema.format.to_owned())
        .collect();

    let (format, oidc_format) =
        map_credential_formats_to_presentation_format(&params.credential_presentations)?;

    let presentation_formatter = params.formatter_provider.get_formatter(&format).ok_or(
        VerificationProtocolError::Failed("Formatter not found".to_string()),
    )?;

    let auth_fn = params
        .key_provider
        .get_signature_provider(params.key, params.jwk_key_id, params.key_algorithm_provider)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let presentation_definition_id = params
        .presentation_definition
        .ok_or(VerificationProtocolError::Failed(
            "Missing presentation definition".into(),
        ))?
        .id
        .to_owned();

    let presentation_submission = create_presentation_submission(
        presentation_definition_id,
        params.credential_presentations,
        &oidc_format,
    )?;

    let mut ctx = FormatPresentationCtx {
        nonce: Some(params.nonce.to_string()),
        token_formats: Some(token_formats),
        ..Default::default()
    };

    if format == "MDOC" {
        let mdoc_generated_nonce = params.identity_request_nonce.ok_or_else(|| {
            VerificationProtocolError::Failed(
                "Cannot format MDOC - missing identity request nonce".to_string(),
            )
        })?;

        ctx.mdoc_session_transcript = Some(
            to_cbor(&SessionTranscript {
                handover: OID4VPHandover::compute(
                    params.client_id,
                    params.client_id,
                    params.nonce,
                    mdoc_generated_nonce,
                )
                .into(),
                device_engagement_bytes: None,
                e_reader_key_bytes: None,
            })
            .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?,
        );
    }

    let vp_token = presentation_formatter
        .format_presentation(
            &tokens,
            &params.holder_did.did,
            &params.key.key_type,
            auth_fn,
            ctx,
        )
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    Ok((vp_token, presentation_submission))
}

pub(super) struct ProofShareParams<'a> {
    interaction_id: InteractionId,
    proof: &'a Proof,
    type_to_descriptor: TypeToDescriptorMapper,
    format_to_type_mapper: FormatMapper,
    key_id: KeyId,

    did_method_provider: &'a dyn DidMethodProvider,
    formatter_provider: &'a dyn CredentialFormatterProvider,
    key_provider: &'a dyn KeyProvider,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

pub(super) async fn prepare_proof_share(
    params: ProofShareParams<'_>,
) -> Result<(OpenID4VPPresentationDefinition, Did, AuthenticationFn), VerificationProtocolError> {
    let presentation_definition = create_open_id_for_vp_presentation_definition(
        params.interaction_id,
        params.proof,
        params.type_to_descriptor,
        params.format_to_type_mapper,
        params.formatter_provider,
    )?;

    let Some(verifier_did) = params.proof.verifier_did.as_ref() else {
        return Err(VerificationProtocolError::InvalidRequest(format!(
            "Verifier DID missing for proof {}",
            { params.proof.id }
        )));
    };

    let Ok(verifier_key) = verifier_did.find_key(&params.key_id, KeyRole::Authentication) else {
        return Err(VerificationProtocolError::InvalidRequest(format!(
            "Verifier key {} not found for proof {}",
            params.key_id,
            { params.proof.id }
        )));
    };

    let verifier_jwk_key_id = params
        .did_method_provider
        .get_verification_method_id_from_did_and_key(verifier_did, verifier_key)
        .await
        .map_err(|err| VerificationProtocolError::Failed(format!("Failed resolving did {err}")))?;

    let auth_fn = params
        .key_provider
        .get_signature_provider(
            verifier_key,
            Some(verifier_jwk_key_id),
            params.key_algorithm_provider,
        )
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    Ok((presentation_definition, verifier_did.clone(), auth_fn))
}
