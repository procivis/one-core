use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use futures::FutureExt;
use futures::future::BoxFuture;
use key_agreement_key::KeyAgreementKey;
use mqtt::oidc_mqtt_verifier::MqttVerifier;
use serde::Deserialize;
use serde_json::{Value, json};
use shared_types::{KeyId, ProofId};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::model::{
    OpenID4VPPresentationDefinition, PresentationSubmissionMappingDTO,
    default_presentation_url_scheme,
};
use crate::config::core_config::{
    CoreConfig, DidType, FormatType, IdentifierType, TransportType, VerificationProtocolType,
};
use crate::model::did::{Did, KeyFilter, KeyRole};
use crate::model::identifier::Identifier;
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::credential_formatter::model::{
    AuthenticationFn, DetailCredential, HolderBindingCtx
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::mqtt_client::MqttClient;
use crate::provider::presentation_formatter::model::{FormatPresentationCtx, FormattedPresentation,CredentialToPresent};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::iso_18013_7::OID4VPDraftHandover;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{Handover, SessionTranscript};
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::verification_protocol::dto::{InvitationResponseDTO, PresentationDefinitionResponseDTO, PresentationDefinitionV2ResponseDTO, FormattedCredentialPresentation, ShareResponse, UpdateResponse, VerificationProtocolCapabilities, PresentationDefinitionVersion};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::common::to_cbor;
use crate::provider::verification_protocol::mapper::proof_from_handle_invitation;
use crate::provider::verification_protocol::openid4vp::get_presentation_definition_with_local_credentials;
use crate::provider::verification_protocol::openid4vp::mapper::{create_open_id_for_vp_presentation_definition, create_presentation_submission, explode_validity_credentials, key_and_did_from_formatted_creds, map_presented_credentials_to_presentation_format_type};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::async_verifier_flow::{verifier_flow, AsyncVerifierFlowParams};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::oidc_ble_holder::BleHolderTransport;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::oidc_ble_verifier::{retract_proof_ble, schedule_ble_verifier_flow};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::holder_flow::{
    handle_invitation_with_transport, submit_proof_with_transport, HolderCommonVPInteractionData,
    ProximityHolderTransport,
};
use crate::provider::verification_protocol::openid4vp::proximity_draft00::mqtt::MqttHolderTransport;
use crate::provider::verification_protocol::{
    FormatMapper, TypeToDescriptorMapper, VerificationProtocol,
};
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::proof::dto::{CreateProofInteractionData, ShareProofRequestParamsDTO};
use crate::service::storage_proxy::StorageAccess;
use crate::util::ble_resource::BleWaiter;
use crate::util::key_verification::KeyVerification;

mod async_verifier_flow;
pub mod ble;
mod dto;
mod holder_flow;
mod key_agreement_key;
pub mod mqtt;
mod peer_encryption;

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct OpenID4VPProximityDraft00Params {
    #[serde(default = "default_presentation_url_scheme")]
    pub url_scheme: String,
}
pub struct OpenID4VPProximityDraft00 {
    ble: Option<BleWaiter>,
    ble_holder_transport: Option<BleHolderTransport>,
    mqtt_holder_transport: Option<MqttHolderTransport>,
    mqtt_verifier: Option<MqttVerifier>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    interaction_repository: Arc<dyn InteractionRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    config: Arc<CoreConfig>,
    params: OpenID4VPProximityDraft00Params,
}

impl OpenID4VPProximityDraft00 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        mqtt_client: Option<Arc<dyn MqttClient>>,
        config: Arc<CoreConfig>,
        params: OpenID4VPProximityDraft00Params,
        interaction_repository: Arc<dyn InteractionRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        ble: Option<BleWaiter>,
    ) -> Self {
        let url_scheme = params.url_scheme.clone();
        let ble_holder_transport = ble
            .clone()
            .map(|ble| BleHolderTransport::new(url_scheme.clone(), ble));
        let (openid_mqtt, mqtt_holder_transport) = if let Some(mqtt_client) = mqtt_client {
            if let Ok(transport_params) = config.transport.get(TransportType::Mqtt.as_ref()) {
                (
                    Some(MqttVerifier::new(mqtt_client.clone(), transport_params)),
                    Some(MqttHolderTransport::new(url_scheme, mqtt_client)),
                )
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        Self {
            ble,
            mqtt_verifier: openid_mqtt,
            mqtt_holder_transport,
            ble_holder_transport,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            credential_formatter_provider,
            presentation_formatter_provider,
            interaction_repository,
            proof_repository,
            certificate_validator,
            config,
            params,
        }
    }

    async fn holder_handle_invitation_inner<T: Send + Sync + 'static>(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        holder_transport: &dyn ProximityHolderTransport<Context = T>,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        if !holder_transport.can_handle(&url) {
            return Err(VerificationProtocolError::Failed(
                "No OpenID4VC query params detected".to_string(),
            ));
        };
        let verification_fn = Box::new(KeyVerification {
            did_method_provider: self.did_method_provider.clone(),
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        });
        handle_invitation_with_transport(
            url,
            organisation,
            storage_access,
            holder_transport,
            verification_fn,
        )
        .await
    }

    fn parse_interaction_data(
        &self,
        context: Value,
        transport: TransportType,
    ) -> Result<HolderCommonVPInteractionData, VerificationProtocolError> {
        match transport {
            TransportType::Ble => self
                .ble_holder_transport
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(
                    "BLE transport not configured".to_string(),
                ))?
                .parse_interaction_data(context),
            TransportType::Mqtt => self
                .mqtt_holder_transport
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(
                    "MQTT transport not configured".to_string(),
                ))?
                .parse_interaction_data(context),
            _ => Err(VerificationProtocolError::Failed(
                "Unsupported transport type".to_string(),
            )),
        }
    }
}

#[async_trait::async_trait]
impl VerificationProtocol for OpenID4VPProximityDraft00 {
    fn holder_can_handle(&self, url: &Url) -> bool {
        self.ble_holder_transport
            .as_ref()
            .is_some_and(|transport| transport.can_handle(url))
            || self
                .mqtt_holder_transport
                .as_ref()
                .is_some_and(|mqtt| mqtt.can_handle(url))
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
                if !self
                    .config
                    .transport
                    .ble_enabled_for(TransportType::Ble.as_ref())
                {
                    return Err(VerificationProtocolError::Disabled(
                        "BLE transport is disabled".to_string(),
                    ));
                }

                let holder_transport = self.ble_holder_transport.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("BLE not available".to_string())
                })?;
                self.holder_handle_invitation_inner(
                    url,
                    organisation,
                    storage_access,
                    holder_transport,
                )
                .await
            }
            TransportType::Mqtt => {
                if !self
                    .config
                    .transport
                    .mqtt_enabled_for(TransportType::Mqtt.as_ref())
                {
                    return Err(VerificationProtocolError::Disabled(
                        "MQTT transport is disabled".to_string(),
                    ));
                }
                let holder_transport = self.mqtt_holder_transport.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("MQTT client not configured".to_string())
                })?;
                self.holder_handle_invitation_inner(
                    url,
                    organisation,
                    storage_access,
                    holder_transport,
                )
                .await
            }
            _ => Err(VerificationProtocolError::Failed(
                "Unsupported transport type".to_string(),
            )),
        }
    }

    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            VerificationProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        let interaction_data = interaction_data_from_proof(proof)?;
        match transport {
            TransportType::Ble => {
                let ble = self.ble_holder_transport.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("BLE transport not configured".to_string())
                })?;
                ble.reject_proof(interaction_data).await
            }
            TransportType::Mqtt => {
                let mqtt_transport = self.mqtt_holder_transport.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("MQTT transport not configured".to_string())
                })?;
                mqtt_transport.reject_proof(interaction_data).await
            }
            _ => Err(VerificationProtocolError::Failed(
                "Unsupported transport type".to_string(),
            )),
        }
    }

    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<FormattedCredentialPresentation>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            VerificationProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;
        let credential_presentations = explode_validity_credentials(credential_presentations);

        let interaction_data = interaction_data_from_proof(proof)?;
        let (key, jwk_key_id, holder_did) =
            key_and_did_from_formatted_creds(&credential_presentations)?;

        let params = CreatePresentationParams {
            credential_presentations,
            holder_did: &holder_did,
            key: &key,
            jwk_key_id,
            presentation_formatter_provider: &*self.presentation_formatter_provider,
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            key_provider: &*self.key_provider,
            config: self.config.clone(),
            // Will be filled in later using holder transport
            presentation_definition: None,
            client_id: "",
            identity_request_nonce: None,
            nonce: "",
        };

        match transport {
            TransportType::Ble => {
                let ble_transport = self.ble_holder_transport.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("BLE transport not configured".to_string())
                })?;
                submit_proof_with_transport(ble_transport, interaction_data, params).await
            }
            TransportType::Mqtt => {
                let mqtt_transport = self.mqtt_holder_transport.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("MQTT transport not configured".to_string())
                })?;
                submit_proof_with_transport(mqtt_transport, interaction_data, params).await
            }
            _ => Err(VerificationProtocolError::Failed(
                "Unsupported transport type".to_string(),
            )),
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

        let interaction_data = self.parse_interaction_data(context, transport)?;
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

    fn holder_get_holder_binding_context(
        &self,
        proof: &Proof,
        context: serde_json::Value,
    ) -> Result<Option<HolderBindingCtx>, VerificationProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            VerificationProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        let interaction_data = self.parse_interaction_data(context, transport)?;
        let holder_binding_context = HolderBindingCtx {
            nonce: interaction_data.nonce,
            audience: interaction_data.client_id,
        };
        Ok(Some(holder_binding_context))
    }

    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        type_to_descriptor: TypeToDescriptorMapper,
        on_submission_callback: Option<BoxFuture<'static, ()>>,
        _params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse<Value>, VerificationProtocolError> {
        let transport = get_transport(proof)?;
        let on_submission_callback = on_submission_callback.map(|fut| fut.shared());

        let key_id = proof.verifier_key.as_ref().map(|key| key.id).ok_or(
            VerificationProtocolError::Failed("Missing verifier key".to_string()),
        )?;

        let interaction_id = Uuid::new_v4();
        let key_agreement = KeyAgreementKey::new_random();

        let (presentation_definition, verifier_did, auth_fn_ble, auth_fn_mqtt) =
            prepare_proof_share(ProofShareParams {
                interaction_id,
                proof,
                type_to_descriptor,
                format_to_type_mapper,
                key_id,
                formatter_provider: &*self.credential_formatter_provider,
                key_provider: &*self.key_provider,
                key_algorithm_provider: self.key_algorithm_provider.clone(),
            })
            .await?;

        let params = AsyncVerifierFlowParams {
            proof_id: proof.id,
            presentation_definition,
            did: verifier_did.did,
            interaction_id,
            proof_repository: self.proof_repository.clone(),
            interaction_repository: self.interaction_repository.clone(),
            key_agreement: key_agreement.clone(),
            // notification to cancel the other flow (if any) when one is selected
            cancellation_token: Default::default(),
        };

        match transport.as_slice() {
            [TransportType::Ble] => {
                let ble = self.ble.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("BLE transport not configured".to_string())
                })?;
                schedule_ble_verifier_flow(
                    ble,
                    &key_agreement,
                    &self.params.url_scheme,
                    interaction_id,
                    self.interaction_repository.clone(),
                    |verifier_transport| {
                        verifier_flow(
                            params,
                            auth_fn_ble,
                            on_submission_callback,
                            verifier_transport,
                        )
                        .boxed()
                    },
                )
                .await
                .map(|url| ShareResponse {
                    url: url.to_string(),
                    interaction_id,
                    context: json!({}),
                })
            }
            [TransportType::Http] => Err(VerificationProtocolError::Failed(
                "HTTP transport not supported".to_string(),
            )),
            [TransportType::Mqtt] => {
                let mqtt = self.mqtt_verifier.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("MQTT client not configured".to_string())
                })?;
                mqtt.schedule_verifier_flow(
                    &key_agreement,
                    &self.params.url_scheme,
                    interaction_id,
                    proof.id,
                    |verifier_transport| {
                        verifier_flow(
                            params,
                            auth_fn_mqtt,
                            on_submission_callback,
                            verifier_transport,
                        )
                        .boxed()
                    },
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
                let mqtt = self.mqtt_verifier.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("MQTT client not configured".to_string())
                })?;
                let ble = self.ble.as_ref().ok_or_else(|| {
                    VerificationProtocolError::Failed("BLE transport not configured".to_string())
                })?;

                let ble_params = params.clone();
                let ble_callback = on_submission_callback.clone();
                let ble_url = schedule_ble_verifier_flow(
                    ble,
                    &key_agreement,
                    &self.params.url_scheme,
                    interaction_id,
                    self.interaction_repository.clone(),
                    |verifier_transport| {
                        verifier_flow(ble_params, auth_fn_ble, ble_callback, verifier_transport)
                            .boxed()
                    },
                )
                .await?;
                let mqtt_url = mqtt
                    .schedule_verifier_flow(
                        &key_agreement,
                        &self.params.url_scheme,
                        interaction_id,
                        proof.id,
                        |verifier_transport| {
                            verifier_flow(
                                params,
                                auth_fn_mqtt,
                                on_submission_callback,
                                verifier_transport,
                            )
                            .boxed()
                        },
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
                TransportType::Ble => {
                    let ble = self.ble.as_ref().ok_or_else(|| {
                        VerificationProtocolError::Failed(
                            "BLE not configured for retract proof".to_string(),
                        )
                    })?;
                    retract_proof_ble(ble).await;
                }
                TransportType::Mqtt => {
                    self.mqtt_verifier
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
        let did_methods = vec![DidType::Key, DidType::Jwk, DidType::Web, DidType::WebVh];

        VerificationProtocolCapabilities {
            supported_transports: vec![TransportType::Ble, TransportType::Mqtt],
            did_methods,
            verifier_identifier_types: vec![IdentifierType::Did],
            supported_presentation_definition: vec![PresentationDefinitionVersion::V1],
        }
    }

    async fn holder_get_presentation_definition_v2(
        &self,
        _proof: &Proof,
        _context: Value,
        _storage_access: &StorageAccess,
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
        Err(VerificationProtocolError::OperationNotSupported)
    }
}

fn interaction_data_from_proof(proof: &Proof) -> Result<Value, VerificationProtocolError> {
    let interaction_data_bytes = proof
        .interaction
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "missing interaction".to_string(),
        ))?
        .data
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "missing interaction data".to_string(),
        ))?;
    let interaction_data = serde_json::from_slice(interaction_data_bytes).map_err(|err| {
        VerificationProtocolError::Failed(format!("failed to parse interaction data: {err}"))
    })?;
    Ok(interaction_data)
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
    verifier_identifier: Option<Identifier>,
    verification_protocol_type: VerificationProtocolType,
    transport_type: TransportType,
    storage_access: &StorageAccess,
) -> Result<(InteractionId, Proof), VerificationProtocolError> {
    let now = OffsetDateTime::now_utc();
    let interaction = Interaction {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        host: None,
        data: interaction_data,
        organisation: Some(organisation),
        nonce_id: None,
    };

    let interaction_id = storage_access
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
            verifier_identifier,
            interaction,
            now,
            transport_type.as_ref(),
            ProofStateEnum::Requested,
        ),
    ))
}

pub(super) struct CreatePresentationParams<'a> {
    credential_presentations: Vec<FormattedCredentialPresentation>,
    presentation_definition: Option<&'a OpenID4VPPresentationDefinition>,
    holder_did: &'a Did,
    key: &'a Key,
    jwk_key_id: Option<String>,

    client_id: &'a str,
    identity_request_nonce: Option<&'a str>,
    nonce: &'a str,

    presentation_formatter_provider: &'a dyn PresentationFormatterProvider,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: &'a dyn KeyProvider,

    config: Arc<CoreConfig>,
}

pub(super) async fn create_presentation(
    params: CreatePresentationParams<'_>,
) -> Result<(String, PresentationSubmissionMappingDTO), VerificationProtocolError> {
    let format = map_presented_credentials_to_presentation_format_type(
        &params.credential_presentations,
        &params.config,
    )?;

    let presentation_formatter = params
        .presentation_formatter_provider
        .get_presentation_formatter(&format.to_string())
        .ok_or(VerificationProtocolError::Failed(
            "Formatter not found".to_string(),
        ))?;

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

    let mut ctx = FormatPresentationCtx {
        nonce: Some(params.nonce.to_string()),
        ..Default::default()
    };

    if format == FormatType::Mdoc {
        let mdoc_generated_nonce = params.identity_request_nonce.ok_or_else(|| {
            VerificationProtocolError::Failed(
                "Cannot format MDOC - missing identity request nonce".to_string(),
            )
        })?;

        ctx.mdoc_session_transcript = Some(
            to_cbor(&SessionTranscript {
                handover: Some(Handover::Iso18013_7AnnexB(
                    OID4VPDraftHandover::compute(
                        params.client_id,
                        params.client_id,
                        params.nonce,
                        mdoc_generated_nonce,
                    )
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
                )),
                device_engagement_bytes: None,
                e_reader_key_bytes: None,
            })
            .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?,
        );
    }

    let credentials = params
        .credential_presentations
        .iter()
        .map(|presented_credential| {
            let credential_format =
                FormatType::from_str(&presented_credential.credential_schema.format)
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
            Ok(CredentialToPresent {
                raw_credential: presented_credential.presentation.to_owned(),
                credential_format,
            })
        })
        .collect::<Result<Vec<_>, VerificationProtocolError>>()?;

    let FormattedPresentation {
        vp_token,
        oidc_format,
    } = presentation_formatter
        .format_presentation(credentials, auth_fn, &params.holder_did.did, ctx)
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let presentation_submission = create_presentation_submission(
        presentation_definition_id,
        params.credential_presentations,
        &oidc_format,
        &params.config,
    )?;

    Ok((vp_token, presentation_submission))
}

pub(super) struct ProofShareParams<'a> {
    interaction_id: InteractionId,
    proof: &'a Proof,
    type_to_descriptor: TypeToDescriptorMapper,
    format_to_type_mapper: FormatMapper,
    key_id: KeyId,

    formatter_provider: &'a dyn CredentialFormatterProvider,
    key_provider: &'a dyn KeyProvider,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

pub(super) async fn prepare_proof_share(
    params: ProofShareParams<'_>,
) -> Result<
    (
        OpenID4VPPresentationDefinition,
        Did,
        AuthenticationFn,
        AuthenticationFn,
    ),
    VerificationProtocolError,
> {
    let proof_schema = params
        .proof
        .schema
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "missing proof schema".to_string(),
        ))?;

    let presentation_definition = create_open_id_for_vp_presentation_definition(
        params.interaction_id,
        proof_schema,
        params.type_to_descriptor,
        params.format_to_type_mapper,
        params.formatter_provider,
    )?;

    let Some(verifier_did) = params
        .proof
        .verifier_identifier
        .as_ref()
        .and_then(|identifier| identifier.did.as_ref())
    else {
        return Err(VerificationProtocolError::InvalidRequest(format!(
            "Verifier DID missing for proof {}",
            { params.proof.id }
        )));
    };

    let Ok(Some(verifier_key)) = verifier_did.find_key(
        &params.key_id,
        &KeyFilter::role_filter(KeyRole::Authentication),
    ) else {
        return Err(VerificationProtocolError::InvalidRequest(format!(
            "Verifier key {} not found for proof {}",
            params.key_id,
            { params.proof.id }
        )));
    };

    let verifier_jwk_key_id = verifier_did.verification_method_id(verifier_key);

    let auth_fn_ble = params
        .key_provider
        .get_signature_provider(
            &verifier_key.key,
            Some(verifier_jwk_key_id.clone()),
            params.key_algorithm_provider.clone(),
        )
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
    let auth_fn_mqtt = params
        .key_provider
        .get_signature_provider(
            &verifier_key.key,
            Some(verifier_jwk_key_id),
            params.key_algorithm_provider,
        )
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    Ok((
        presentation_definition,
        verifier_did.clone(),
        auth_fn_ble,
        auth_fn_mqtt,
    ))
}
