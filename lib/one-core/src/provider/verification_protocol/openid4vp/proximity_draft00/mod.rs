use std::collections::HashMap;
use std::sync::Arc;

use futures::FutureExt;
use futures::future::BoxFuture;
use key_agreement_key::KeyAgreementKey;
use mqtt::oidc_mqtt_verifier::MqttVerifier;
use proc_macros::Provider;
use serde::Deserialize;
use serde_json::Value;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{InteractionId, KeyId, ProofId};
use standardized_types::openid4vp::VpTokenResponse;
use standardized_types::openid4vp::dcql::DcqlQuery;
use time::Duration;
use url::Url;
use uuid::Uuid;

use super::dcql::get_presentation_definition_v2;
use super::final1_0::dcql::create_dcql_query;
use super::mapper::format_to_type;
use super::mdoc::mdoc_presentation_context;
use super::model::default_presentation_url_scheme;
use super::proximity_draft00::async_verifier_flow::{AsyncVerifierFlowParams, verifier_flow};
use super::proximity_draft00::ble::oidc_ble_holder::BleHolderTransport;
use super::proximity_draft00::ble::oidc_ble_verifier::{
    retract_proof_ble, schedule_ble_verifier_flow,
};
use super::proximity_draft00::holder_flow::{
    HolderCommonVPInteractionData, ProximityHolderTransport, handle_invitation_with_transport,
    submit_proof_with_transport,
};
use super::proximity_draft00::mqtt::MqttHolderTransport;
use crate::config::core_config::{
    CoreConfig, DidType, FormatType, IdentifierType, TransportType, VerificationProtocolType,
};
use crate::error::ContextWithErrorCode;
use crate::model::did::{Did, KeyRole};
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::proto::bluetooth_low_energy::ble_resource::BleWaiter;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::key_verification::KeyVerification;
use crate::proto::mqtt_client::MqttClient;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::{CredentialToPresent, FormatPresentationCtx};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::Handover;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::openid4vp_final1_0::OID4VPFinal1_0Handover;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::provider_directory::InitializationError;
use crate::provider::verification_protocol::dto::{
    Feature, FormattedCredentialPresentation, InvitationResponseDTO,
    PresentationDefinitionV2ResponseDTO, PresentationDefinitionVersion, ShareResponse,
    UpdateResponse, VerificationProtocolCapabilities,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::mapper::proof_from_handle_invitation;
use crate::provider::verification_protocol::model::CommonParams;
use crate::provider::verification_protocol::openid4vp::mapper::create_open_id_for_vp_presentation_definition;
use crate::provider::verification_protocol::openid4vp::model::OpenID4VPPresentationDefinition;
use crate::provider::verification_protocol::{
    FormatMapper, VerificationProtocol, serialize_interaction_data,
};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::proof::dto::{CreateProofInteractionData, ShareProofRequestParamsDTO};
use crate::util::key_selection::KeyFilter;

mod async_verifier_flow;
pub mod ble;
pub(crate) mod draft20_request;
mod dto;
mod holder_flow;
mod key_agreement_key;
pub mod mqtt;
mod peer_encryption;

#[derive(Debug, Deserialize, Clone)]
struct OpenID4VPProximityDraft00Params {
    #[serde(default = "default_presentation_url_scheme")]
    pub url_scheme: String,
    #[serde(default)]
    pub verifier: Option<OpenID4VPProximityDraft00PresentationVerifierParams>,

    #[serde(flatten)]
    pub common: CommonParams,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VPProximityDraft00PresentationVerifierParams {
    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub interaction_expires_in_seconds: Option<Duration>,
}

#[derive(Provider)]
pub struct OpenID4VPProximityDraft00 {
    config_id: String,
    ble: Option<BleWaiter>,
    ble_holder_transport: Option<BleHolderTransport>,
    mqtt_holder_transport: Option<MqttHolderTransport>,
    mqtt_verifier: Option<MqttVerifier>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    wrp_validator: Arc<dyn WRPValidator>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
    config: Arc<CoreConfig>,
    params: OpenID4VPProximityDraft00Params,
}

impl OpenID4VPProximityDraft00 {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config_id: String,
        mqtt_client: Option<Arc<dyn MqttClient>>,
        config: Arc<CoreConfig>,
        params: serde_json::Value,
        credential_repository: Arc<dyn CredentialRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        wrp_validator: Arc<dyn WRPValidator>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
        ble: Option<BleWaiter>,
    ) -> Result<Self, InitializationError> {
        let params: OpenID4VPProximityDraft00Params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

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

        Ok(Self {
            config_id,
            ble,
            mqtt_verifier: openid_mqtt,
            mqtt_holder_transport,
            ble_holder_transport,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            credential_formatter_provider,
            presentation_formatter_provider,
            credential_repository,
            credential_schema_repository,
            interaction_repository,
            proof_repository,
            certificate_validator,
            wrp_validator,
            identifier_creator,
            ecosystem_provider,
            config,
            params,
        })
    }

    async fn holder_handle_invitation_inner<'a, T: Send + Sync + 'static>(
        &self,
        url: Url,
        organisation: Organisation,
        holder_transport: &dyn ProximityHolderTransport<Context = T>,
    ) -> Result<InvitationResponseDTO<'a>, VerificationProtocolError> {
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
            self.interaction_repository.as_ref(),
            self.identifier_creator.as_ref(),
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

    async fn holder_handle_invitation<'a>(
        &self,
        url: Url,
        organisation: Organisation,
        transport: String,
    ) -> Result<InvitationResponseDTO<'a>, VerificationProtocolError> {
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
                self.holder_handle_invitation_inner(url, organisation, holder_transport)
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
                self.holder_handle_invitation_inner(url, organisation, holder_transport)
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

        let interaction_data = interaction_data_from_proof(proof).await?;
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

        let interaction_data = interaction_data_from_proof(proof).await?;

        let params = CreatePresentationParams {
            credential_presentations,
            presentation_formatter_provider: &*self.presentation_formatter_provider,
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            key_provider: &*self.key_provider,
            config: self.config.clone(),
            // Will be filled in later using holder transport
            client_id: "",
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

    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        on_submission_callback: Option<BoxFuture<'static, ()>>,
        _params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse, VerificationProtocolError> {
        let transport = get_transport(proof).await?;
        let on_submission_callback = on_submission_callback.map(|fut| fut.shared());

        let key_id = proof.verifier_key.as_ref().map(|key| key.id()).ok_or(
            VerificationProtocolError::Failed("Missing verifier key".to_string()),
        )?;

        let interaction_id = Uuid::new_v4().into();
        let key_agreement = KeyAgreementKey::new_random();

        let (presentation_definition, dcql_query, verifier_did, auth_fn_ble, auth_fn_mqtt) =
            prepare_proof_share(ProofShareParams {
                proof,
                interaction_id,
                key_id,
                format_to_type_mapper,
                formatter_provider: &*self.credential_formatter_provider,
                key_provider: &*self.key_provider,
                key_algorithm_provider: self.key_algorithm_provider.clone(),
            })
            .await?;

        let params = AsyncVerifierFlowParams {
            proof_id: proof.id,
            dcql_query,
            presentation_definition,
            did: verifier_did.did,
            interaction_id,
            proof_repository: self.proof_repository.clone(),
            interaction_repository: self.interaction_repository.clone(),
            key_agreement: key_agreement.clone(),
            // notification to cancel the other flow (if any) when one is selected
            cancellation_token: Default::default(),
        };

        let expires_at = self.params.verifier.as_ref().and_then(|verifier| {
            verifier
                .interaction_expires_in_seconds
                .map(|interaction_expires_in| crate::clock::now_utc() + interaction_expires_in)
        });

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
                    interaction_data: None,
                    expires_at,
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
                    interaction_data: None,
                    expires_at,
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
                    interaction_data: Some(serialize_interaction_data(
                        &CreateProofInteractionData {
                            transport: transport.iter().map(ToString::to_string).collect(),
                            common: Default::default(),
                        },
                    )?),
                    expires_at,
                })
            }
            other => Err(VerificationProtocolError::Failed(format!(
                "Invalid transport selection: {other:?}",
            ))),
        }
    }

    async fn retract_proof(&self, proof: &Proof) -> Result<(), VerificationProtocolError> {
        for transport in get_transport(proof).await? {
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
        let mut features = vec![];

        if self.params.common.webhook_task.is_some() {
            features.push(Feature::SupportsWebhooks);
        }

        VerificationProtocolCapabilities {
            features,
            supported_transports: vec![TransportType::Ble, TransportType::Mqtt],
            did_methods,
            verifier_identifier_types: vec![IdentifierType::Did],
            supported_presentation_definition: vec![PresentationDefinitionVersion::V2],
        }
    }

    async fn holder_get_presentation_definition_v2(
        &self,
        proof: &Proof,
        context: Value,
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            VerificationProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        let interaction_data = self.parse_interaction_data(context, transport)?;

        get_presentation_definition_v2(
            interaction_data.dcql_query,
            proof,
            &*self.credential_repository,
            &*self.credential_schema_repository,
            &*self.credential_formatter_provider,
            &*self.ecosystem_provider,
            &*self.wrp_validator,
            &self.config,
            None,
            &[],
            None,
        )
        .await
    }

    fn config_name(&self) -> &str {
        &self.config_id
    }
}

async fn interaction_data_from_proof(proof: &Proof) -> Result<Value, VerificationProtocolError> {
    let interaction = proof
        .interaction
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "missing interaction".to_string(),
        ))?
        .as_ref()
        .await?;
    let interaction_data_bytes =
        interaction
            .data
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "missing interaction data".to_string(),
            ))?;
    let interaction_data = serde_json::from_slice(interaction_data_bytes)?;
    Ok(interaction_data)
}

async fn get_transport(proof: &Proof) -> Result<Vec<TransportType>, VerificationProtocolError> {
    let transport = if proof.transport.is_empty() {
        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "missing interaction".to_string(),
            ))?
            .as_ref()
            .await?;
        let interaction_data =
            interaction
                .data
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(
                    "Missing interaction data".to_string(),
                ))?;

        let data: CreateProofInteractionData = serde_json::from_slice(interaction_data)?;

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
    interaction_repository: &dyn InteractionRepository,
) -> Result<(InteractionId, Proof), VerificationProtocolError> {
    let now = crate::clock::now_utc();
    let interaction = Interaction {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        data: interaction_data,
        organisation: organisation.into(),
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };

    let interaction_id = interaction_repository
        .create_interaction(interaction.clone())
        .await
        .error_while("creating interaction")?;

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

    client_id: &'a str,
    nonce: &'a str,

    presentation_formatter_provider: &'a dyn PresentationFormatterProvider,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: &'a dyn KeyProvider,

    config: Arc<CoreConfig>,
}

pub(super) async fn create_presentation(
    params: CreatePresentationParams<'_>,
) -> Result<VpTokenResponse, VerificationProtocolError> {
    let mut vp_token = HashMap::new();

    // For DCQL each credential gets a presentation individually
    for credential_presentation in &params.credential_presentations {
        let credential_format = format_to_type(credential_presentation, &params.config).await?;
        let presentation_format = match credential_format {
            FormatType::SdJwt => FormatType::SdJwt,
            FormatType::SdJwtVc => FormatType::SdJwtVc,
            FormatType::JsonLdClassic | FormatType::JsonLdBbsPlus => FormatType::JsonLdClassic,
            FormatType::Mdoc => FormatType::Mdoc,
            FormatType::Jwt => FormatType::Jwt,
        };

        let presentation_formatter = params
            .presentation_formatter_provider
            .get_presentation_formatter(&presentation_format.to_string())
            .ok_or_else(|| VerificationProtocolError::Failed("Formatter not found".to_string()))?;

        let auth_fn = params.key_provider.get_signature_provider(
            &credential_presentation.key,
            credential_presentation.jwk_key_id.to_owned(),
            params.key_algorithm_provider.clone(),
        )?;

        let credentials = CredentialToPresent {
            credential_token: credential_presentation.presentation.to_owned(),
            credential_format,
        };
        let formatted_presentation = presentation_formatter
            .format_presentation(
                vec![credentials],
                auth_fn,
                format_presentation_context(
                    &params,
                    presentation_format,
                    &credential_presentation.holder_did,
                )?,
            )
            .await
            .error_while("formatting presentation")?;
        let credential_query_id = credential_presentation.credential_query_id.to_string();
        vp_token
            .entry(credential_query_id)
            .and_modify(|presentations: &mut Vec<String>| {
                presentations.push(formatted_presentation.vp_token.to_owned())
            })
            .or_insert(vec![formatted_presentation.vp_token]);
    }

    Ok(VpTokenResponse { vp_token })
}

pub(super) struct ProofShareParams<'a> {
    proof: &'a Proof,
    interaction_id: InteractionId,
    key_id: KeyId,

    format_to_type_mapper: FormatMapper,

    formatter_provider: &'a dyn CredentialFormatterProvider,
    key_provider: &'a dyn KeyProvider,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

pub(super) async fn prepare_proof_share(
    params: ProofShareParams<'_>,
) -> Result<
    (
        OpenID4VPPresentationDefinition,
        DcqlQuery,
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
        ))?
        .as_ref()
        .await?;

    let dcql_query = create_dcql_query(
        &proof_schema,
        &params.format_to_type_mapper,
        params.formatter_provider,
    )
    .await?;

    // only used when a legacy wallet negotiates proximity protocol version 1
    let presentation_definition = create_open_id_for_vp_presentation_definition(
        params.interaction_id,
        proof_schema.to_owned(),
        params.format_to_type_mapper,
        params.formatter_provider,
    )
    .await?;

    let verifier_identifier = params
        .proof
        .verifier_identifier
        .as_ref()
        .ok_or(VerificationProtocolError::InvalidRequest(
            "Missing verifier identifier".to_string(),
        ))?
        .as_ref()
        .await?;

    let Identifier {
        data: IdentifierData::Did(verifier_did),
        ..
    } = verifier_identifier.as_ref()
    else {
        return Err(VerificationProtocolError::InvalidRequest(format!(
            "Verifier not a DID for proof {}",
            params.proof.id
        )));
    };
    let verifier_did = verifier_did.as_ref().await?;

    let Ok(verifier_key) = verifier_did
        .find_key(
            &params.key_id,
            &KeyFilter::did_role(KeyRole::Authentication),
        )
        .await
    else {
        return Err(VerificationProtocolError::InvalidRequest(format!(
            "Verifier key {} not found for proof {}",
            params.key_id,
            { params.proof.id }
        )));
    };

    let verifier_jwk_key_id = verifier_did.verification_method_id(&verifier_key);

    let auth_fn_ble = params.key_provider.get_signature_provider(
        &verifier_key.key,
        Some(verifier_jwk_key_id.clone()),
        params.key_algorithm_provider.clone(),
    )?;
    let auth_fn_mqtt = params.key_provider.get_signature_provider(
        &verifier_key.key,
        Some(verifier_jwk_key_id),
        params.key_algorithm_provider,
    )?;

    Ok((
        presentation_definition,
        dcql_query,
        verifier_did.to_owned(),
        auth_fn_ble,
        auth_fn_mqtt,
    ))
}

fn format_presentation_context(
    params: &CreatePresentationParams<'_>,
    presentation_format: FormatType,
    holder_did: &Option<Did>,
) -> Result<FormatPresentationCtx, VerificationProtocolError> {
    let ctx = if presentation_format == FormatType::Mdoc {
        mdoc_presentation_context(
            Handover::OID4VPFinal1_0(
                OID4VPFinal1_0Handover::compute(
                    params.client_id,
                    params.client_id,
                    params.nonce,
                    None,
                )
                .error_while("computing handover")?,
            ),
            None,
        )?
    } else {
        FormatPresentationCtx {
            nonce: Some(params.nonce.to_owned()),
            audience: Some(params.client_id.to_owned()),
            holder_did: holder_did.as_ref().map(|did| did.did.to_owned()),
            ..Default::default()
        }
    };
    Ok(ctx)
}
