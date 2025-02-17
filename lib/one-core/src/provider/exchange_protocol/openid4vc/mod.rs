//! Implementation of OpenID4VCI + OpenID4VP.
//! https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html
//! https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use futures::future::BoxFuture;
use futures::FutureExt;
use key_agreement_key::KeyAgreementKey;
use mapper::{get_claim_name_by_json_path, presentation_definition_from_interaction_data};
use model::{ClientIdSchemaType, OpenID4VPHolderInteractionData};
use one_dto_mapper::convert_inner;
use openidvc_ble::model::BLEOpenID4VPInteractionData;
use openidvc_ble::OpenID4VCBLE;
use openidvc_http::OpenID4VCHTTP;
use openidvc_mqtt::model::MQTTOpenID4VPInteractionDataHolder;
use openidvc_mqtt::OpenId4VcMqtt;
use serde_json::json;
use shared_types::KeyId;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use super::dto::{ExchangeProtocolCapabilities, Operation, PresentationDefinitionResponseDTO};
use super::{
    ExchangeProtocol, ExchangeProtocolError, ExchangeProtocolImpl, FormatMapper,
    HandleInvitationOperationsAccess, StorageAccess, TypeToDescriptorMapper,
};
use crate::config::core_config::{CoreConfig, TransportType};
use crate::model::credential::Credential;
use crate::model::did::Did;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::exchange_protocol::dto::{CredentialGroup, CredentialGroupItem};
use crate::provider::exchange_protocol::mapper::{
    gather_object_datatypes_from_config, get_relevant_credentials_to_credential_schemas,
};
use crate::provider::exchange_protocol::openid4vc::model::{
    InvitationResponseDTO, OpenID4VCParams, OpenID4VPFormat, PresentedCredential, ShareResponse,
    SubmitIssuerResponse, UpdateResponse,
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
    params: OpenID4VCParams,
    openid_http: OpenID4VCHTTP,
    openid_ble: OpenID4VCBLE,
    openid_mqtt: Option<OpenId4VcMqtt>,
}

impl OpenID4VC {
    pub fn new(
        config: Arc<CoreConfig>,
        params: OpenID4VCParams,
        openid_http: OpenID4VCHTTP,
        openid_ble: OpenID4VCBLE,
        mqtt: Option<OpenId4VcMqtt>,
    ) -> Self {
        Self {
            config,
            params,
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

    fn holder_can_handle(&self, url: &Url) -> bool {
        self.openid_http.can_handle(url)
            || self.openid_ble.holder_can_handle(url)
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
        handle_invitation_operations: &HandleInvitationOperationsAccess,
        transport: String,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        let transport = TransportType::try_from(transport.as_str()).map_err(|err| {
            ExchangeProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        match transport {
            TransportType::Ble => {
                if self.openid_ble.holder_can_handle(&url) {
                    return self
                        .openid_ble
                        .holder_handle_invitation(url, organisation)
                        .await;
                }
            }
            TransportType::Http => {
                if self.openid_http.can_handle(&url) {
                    return self
                        .openid_http
                        .holder_handle_invitation(
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

                if client.holder_can_handle(&url) {
                    return client.holder_handle_invitation(url, organisation).await;
                }
            }
        }

        Err(ExchangeProtocolError::Failed(
            "No OpenID4VC query params detected".to_string(),
        ))
    }

    async fn holder_reject_proof(&self, proof: &Proof) -> Result<(), ExchangeProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            ExchangeProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        match transport {
            TransportType::Ble => self.openid_ble.holder_reject_proof(proof).await,
            TransportType::Http => self.openid_http.holder_reject_proof(proof).await,
            TransportType::Mqtt => {
                let client = self.openid_mqtt.as_ref().ok_or_else(|| {
                    ExchangeProtocolError::Failed("MQTT client not configured".to_string())
                })?;
                client.holder_reject_proof(proof).await
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
        format_map: HashMap<String, String>,
        presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            ExchangeProtocolError::Failed(format!("Invalid transport type: {err}"))
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
                        format_map,
                        presentation_format_map,
                    )
                    .await
            }
            TransportType::Http => {
                self.openid_http
                    .holder_submit_proof(
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
                    .holder_submit_proof(
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

    async fn holder_accept_credential(
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
            .holder_accept_credential(
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

    async fn holder_reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        self.openid_http.holder_reject_credential(credential).await
    }

    async fn issuer_share_credential(
        &self,
        credential: &Credential,
        credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        self.openid_http
            .issuer_share_credential(credential, credential_format)
            .await
            .map(|context| ShareResponse {
                url: context.url,
                interaction_id: context.interaction_id,
                context: json!(context.context),
            })
    }

    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
        callback: Option<BoxFuture<'static, ()>>,
        client_id_schema: ClientIdSchemaType,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
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
                        url,
                        interaction_id,
                        context: json!({}),
                    })
            }
            [TransportType::Http] => self
                .openid_http
                .verifier_share_proof(
                    proof,
                    format_to_type_mapper,
                    key_id,
                    encryption_key_jwk,
                    vp_formats,
                    type_to_descriptor,
                    client_id_schema,
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
                    ExchangeProtocolError::Failed("MQTT client not configured".to_string())
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

                let ble_response = self
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
                    .map_err(|e| {
                        ExchangeProtocolError::Failed(format!(
                            "Failed to serialize create proof interaction data: {e}"
                        ))
                    })?,
                })
            }
            other => Err(ExchangeProtocolError::Failed(format!(
                "Invalid transport selection: {other:?}",
            ))),
        }
    }

    async fn holder_get_presentation_definition(
        &self,
        proof: &Proof,
        interaction_data: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        format_map: HashMap<String, String>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        let transport = TransportType::try_from(proof.transport.as_str()).map_err(|err| {
            ExchangeProtocolError::Failed(format!("Invalid transport type: {err}"))
        })?;

        let presentation_definition = match transport {
            TransportType::Ble => {
                let interaction_data: BLEOpenID4VPInteractionData =
                    serde_json::from_value(interaction_data)
                        .map_err(ExchangeProtocolError::JsonError)?;

                interaction_data.openid_request.presentation_definition
            }
            TransportType::Http => {
                let interaction_data: OpenID4VPHolderInteractionData =
                    serde_json::from_value(interaction_data)
                        .map_err(ExchangeProtocolError::JsonError)?;

                interaction_data.presentation_definition
            }
            TransportType::Mqtt => {
                let interaction_data: MQTTOpenID4VPInteractionDataHolder =
                    serde_json::from_value(interaction_data)
                        .map_err(ExchangeProtocolError::JsonError)?;

                interaction_data.presentation_definition
            }
        }
        .ok_or(ExchangeProtocolError::Failed(
            "presentation_definition is None".to_string(),
        ))?;

        let mut credential_groups: Vec<CredentialGroup> = vec![];
        let mut group_id_to_schema_id: HashMap<String, String> = HashMap::new();

        let mut allowed_oidc_formats = HashSet::new();

        for input_descriptor in presentation_definition.input_descriptors {
            input_descriptor.format.keys().for_each(|key| {
                allowed_oidc_formats.insert(key.to_owned());
            });
            let validity_credential_nbf = input_descriptor.constraints.validity_credential_nbf;

            let mut fields = input_descriptor.constraints.fields;

            let schema_id_filter_index = fields
                .iter()
                .position(|field| {
                    field.filter.is_some()
                        && field.path.contains(&"$.credentialSchema.id".to_string())
                })
                .ok_or(ExchangeProtocolError::Failed(
                    "schema_id filter not found".to_string(),
                ))?;

            let schema_id_filter = fields.remove(schema_id_filter_index).filter.ok_or(
                ExchangeProtocolError::Failed("schema_id filter not found".to_string()),
            )?;

            group_id_to_schema_id.insert(input_descriptor.id.clone(), schema_id_filter.r#const);
            credential_groups.push(CredentialGroup {
                id: input_descriptor.id,
                name: input_descriptor.name,
                purpose: input_descriptor.purpose,
                claims: fields
                    .iter()
                    .filter(|requested| requested.id.is_some())
                    .map(|requested_claim| {
                        Ok(CredentialGroupItem {
                            id: requested_claim
                                .id
                                .ok_or(ExchangeProtocolError::Failed(
                                    "requested_claim id is None".to_string(),
                                ))?
                                .to_string(),
                            key: get_claim_name_by_json_path(&requested_claim.path)?,
                            required: !requested_claim.optional.is_some_and(|optional| optional),
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>, _>>()?,
                applicable_credentials: vec![],
                inapplicable_credentials: vec![],
                validity_credential_nbf,
            });
        }

        let allowed_schema_formats: HashSet<_> = allowed_oidc_formats
            .iter()
            .map(|oidc_format| {
                format_map
                    .get(oidc_format)
                    .ok_or_else(|| {
                        ExchangeProtocolError::Failed(format!("unknown format {oidc_format}"))
                    })
                    .map(String::as_str)
            })
            .collect::<Result<_, _>>()?;

        let organisation = proof
            .interaction
            .as_ref()
            .and_then(|interaction| interaction.organisation.as_ref())
            .ok_or(ExchangeProtocolError::Failed(
                "proof organisation missing".to_string(),
            ))?;

        let (credentials, credential_groups) = get_relevant_credentials_to_credential_schemas(
            storage_access,
            convert_inner(credential_groups),
            group_id_to_schema_id,
            &allowed_schema_formats,
            &gather_object_datatypes_from_config(&self.config.datatype),
            organisation.id,
        )
        .await?;

        presentation_definition_from_interaction_data(
            proof.id,
            convert_inner(credentials),
            convert_inner(credential_groups),
            &self.config,
        )
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
                        .retract_proof(&proof.id)
                        .await;
                }
            }
        }

        Ok(())
    }

    fn get_capabilities(&self) -> ExchangeProtocolCapabilities {
        let mut operations = vec![];
        if !self.params.issuance.disabled {
            operations.push(Operation::ISSUANCE)
        }
        if !self.params.presentation.disabled {
            operations.push(Operation::VERIFICATION)
        }

        let issuance_did_methods = vec![
            "KEY".to_owned(),
            "JWK".to_owned(),
            "WEB".to_owned(),
            "MDL".to_owned(),
        ];

        let mut verification_did_methods = vec![
            "KEY".to_owned(),
            "JWK".to_owned(),
            "WEB".to_owned(),
            "MDL".to_owned(),
        ];
        if self
            .params
            .presentation
            .verifier
            .supported_client_id_schemes
            .contains(&ClientIdSchemaType::X509SanDns)
        {
            verification_did_methods = vec!["MDL".to_owned()];
        }

        ExchangeProtocolCapabilities {
            supported_transports: vec!["HTTP".to_owned(), "BLE".to_owned(), "MQTT".to_owned()],
            operations,
            issuance_did_methods,
            verification_did_methods,
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
