use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use shared_types::KeyId;
use tokio::sync::RwLock;
use tracing::Instrument;
use url::Url;
use uuid::Uuid;

use super::mapper::create_open_id_for_vp_presentation_definition;
use super::model::{
    DatatypeType, InvitationResponseDTO, OpenID4VPFormat, PresentedCredential, ShareResponse,
    SubmitIssuerResponse, UpdateResponse,
};
use super::openidvc_ble::KeyAgreementKey;
use super::service::FnMapExternalFormatToExternalDetailed;
use super::validator::throw_if_latest_proof_state_not_eq;
use crate::config::core_config::CoreConfig;
use crate::model::credential::Credential;
use crate::model::did::Did;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::exchange_protocol::dto::{
    ExchangeProtocolCapabilities, PresentationDefinitionResponseDTO,
};
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::provider::exchange_protocol::{
    ExchangeProtocolImpl, FormatMapper, HandleInvitationOperationsAccess, StorageAccess,
    TypeToDescriptorMapper,
};
use crate::provider::mqtt_client::MqttClient;
use crate::service::key::dto::PublicKeyJwkDTO;

pub struct OpenId4VcMqtt {
    mqtt_client: Arc<dyn MqttClient>,
    config: Arc<CoreConfig>,
    params: ConfigParams,
    handle: RwLock<Option<SubscriptionHandle>>,
}

pub struct ConfigParams {
    broker_url: Url,
    broker_addr: String,
    broker_port: u16,
}

impl<'de> Deserialize<'de> for ConfigParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub struct Params {
            broker_url: Url,
        }

        let params = Params::deserialize(deserializer)?;
        let port = params.broker_url.port().unwrap_or(1883);

        let mut params = params;
        params
            .broker_url
            .set_port(None)
            .map_err(|_| serde::de::Error::custom("Cannot set port to None"))?;

        let broker_addr = params.broker_url.to_string();

        params
            .broker_url
            .set_port(Some(port))
            .map_err(|_| serde::de::Error::custom("Cannot set port"))?;

        Ok(ConfigParams {
            broker_addr,
            broker_port: port,
            broker_url: params.broker_url,
        })
    }
}

struct SubscriptionHandle {
    _task_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl OpenId4VcMqtt {
    pub fn new(
        mqtt_client: Arc<dyn MqttClient>,
        config: Arc<CoreConfig>,
        params: ConfigParams,
    ) -> OpenId4VcMqtt {
        OpenId4VcMqtt {
            mqtt_client,
            config,
            params,
            handle: RwLock::new(None),
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn start_detached_subscriber(&self, topic: String) -> Result<(), ExchangeProtocolError> {
        let subscription_handle = self
            .mqtt_client
            .subscribe(
                self.params.broker_addr.clone(),
                self.params.broker_port,
                topic,
            )
            .await
            .map_err(|error| {
                tracing::error!(%error, "Failed to subscribe to topic during proof sharing");

                ExchangeProtocolError::Failed("Failed to subscribe to topic".to_owned())
            })?;

        let current_span = tracing::Span::current();
        let handle = tokio::spawn(
            async move {
                let mut subscription_handle = subscription_handle;

                let _res = subscription_handle.recv().await;

                tracing::debug!("Result: {_res:?}");

                Ok(())
            }
            .instrument(current_span),
        );

        self.handle.write().await.replace(SubscriptionHandle {
            _task_handle: handle,
        });

        Ok(())
    }
}

#[async_trait]
impl ExchangeProtocolImpl for OpenId4VcMqtt {
    type VCInteractionContext = ();
    type VPInteractionContext = serde_json::Value;

    fn can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        url.scheme() == "openid4vp" && query_has_key("brokerUrl") && query_has_key("key")
    }

    async fn handle_invitation(
        &self,
        _url: Url,
        _organisation: Organisation,
        _storage_access: &StorageAccess,
        _handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn reject_proof(&self, _proof: &Proof) -> Result<(), ExchangeProtocolError> {
        Err(ExchangeProtocolError::OperationNotSupported)
    }

    async fn submit_proof(
        &self,
        _proof: &Proof,
        _credential_presentations: Vec<PresentedCredential>,
        _holder_did: &Did,
        _key: &Key,
        _jwk_key_id: Option<String>,
        // LOCAL_CREDENTIAL_FORMAT -> oidc_vc_format
        _format_map: HashMap<String, String>,
        // oidc_vp_format -> LOCAL_PRESENTATION_FORMAT
        _presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn accept_credential(
        &self,
        _credential: &Credential,
        _holder_did: &Did,
        _key: &Key,
        _jwk_key_id: Option<String>,
        _credential_format: &str,
        _storage_access: &StorageAccess,
        _map_external_format_to_external_detailed: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn reject_credential(
        &self,
        _credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        Err(ExchangeProtocolError::OperationNotSupported)
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
        _credential: &Credential,
        _credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        unimplemented!()
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        _key_id: KeyId,
        _encryption_key_jwk: PublicKeyJwkDTO,
        _vp_formats: HashMap<String, OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        // todo(mite): these need to be passed as arguments
        let keypair = KeyAgreementKey::new_random();
        let interaction_id = Uuid::new_v4();

        let url = format!(
            "openid4vp://?key={}&brokerUrl={}",
            hex::encode(keypair.public_key_bytes()),
            self.params.broker_url
        );

        let _presentation_definition = create_open_id_for_vp_presentation_definition(
            interaction_id,
            proof,
            type_to_descriptor,
            format_to_type_mapper,
        )?;

        if !self.config.transport.mqtt_enabled_for(&proof.transport) {
            return Err(ExchangeProtocolError::Disabled(
                "MQTT transport is disabled".to_string(),
            ));
        }

        // note that the "+" means single-level wildcard i.e. only one string can be put in it's place
        let topic = format!("/proof/{}/presentation-submission/+", proof.id);
        self.start_detached_subscriber(topic).await?;

        Ok(ShareResponse {
            url,
            interaction_id,
            context: serde_json::json!({}),
        })
    }

    async fn get_presentation_definition(
        &self,
        _proof: &Proof,
        _interaction_data: Self::VPInteractionContext,
        _storage_access: &StorageAccess,
        _format_map: HashMap<String, String>,
        _types: HashMap<String, DatatypeType>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        Err(ExchangeProtocolError::OperationNotSupported)
    }

    async fn retract_proof(&self, _proof: &Proof) -> Result<(), ExchangeProtocolError> {
        unimplemented!()
    }

    fn get_capabilities(&self) -> ExchangeProtocolCapabilities {
        unimplemented!()
    }
}
