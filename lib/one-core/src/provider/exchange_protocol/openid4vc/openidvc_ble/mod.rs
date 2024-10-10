use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::{Stream, TryStreamExt};
use oidc_ble_holder::OpenID4VCBLEHolder;
use oidc_ble_verifier::OpenID4VCBLEVerifier;
use one_dto_mapper::convert_inner;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use shared_types::KeyId;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::dto::OpenID4VPBleData;
use super::mapper::{
    create_presentation_submission, get_claim_name_by_json_path,
    presentation_definition_from_interaction_data,
};
use super::model::BLEOpenID4VPInteractionData;
use super::openidvc_http::mappers::map_credential_formats_to_presentation_format;
use crate::common_validator::throw_if_latest_proof_state_not_eq;
use crate::config::core_config::{self, TransportType};
use crate::model::credential::Credential;
use crate::model::did::Did;
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::provider::bluetooth_low_energy::low_level::dto::DeviceInfo;
use crate::provider::bluetooth_low_energy::BleError;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    OID4VPHandover, SessionTranscript,
};
use crate::provider::credential_formatter::model::{DetailCredential, FormatPresentationCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::exchange_protocol::dto::{
    CredentialGroup, CredentialGroupItem, ExchangeProtocolCapabilities,
    PresentationDefinitionResponseDTO,
};
use crate::provider::exchange_protocol::iso_mdl::common::to_cbor;
use crate::provider::exchange_protocol::mapper::{
    get_relevant_credentials_to_credential_schemas, proof_from_handle_invitation,
};
use crate::provider::exchange_protocol::openid4vc::mapper::create_open_id_for_vp_presentation_definition;
use crate::provider::exchange_protocol::openid4vc::model::{
    DatatypeType, InvitationResponseDTO, OpenID4VPFormat, PresentedCredential, ShareResponse,
    SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::exchange_protocol::openid4vc::peer_encryption::PeerEncryption;
use crate::provider::exchange_protocol::openid4vc::service::FnMapExternalFormatToExternalDetailed;
use crate::provider::exchange_protocol::openid4vc::{
    FormatMapper, HandleInvitationOperationsAccess, TypeToDescriptorMapper,
};
use crate::provider::exchange_protocol::{
    deserialize_interaction_data, ExchangeProtocolError, ExchangeProtocolImpl, StorageAccess,
};
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::service::error::ServiceError;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::util::ble_resource::{Abort, BleWaiter};
use crate::util::oidc::{create_core_to_oicd_format_map, map_from_oidc_format_to_core};

pub mod oidc_ble_holder;
pub mod oidc_ble_verifier;

// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#section-10
pub const SERVICE_UUID: &str = "00000001-5026-444A-9E0E-D6F2450F3A77";
pub const REQUEST_SIZE_UUID: &str = "00000004-5026-444A-9E0E-D6F2450F3A77";
pub const PRESENTATION_REQUEST_UUID: &str = "00000005-5026-444A-9E0E-D6F2450F3A77";
pub const IDENTITY_UUID: &str = "00000006-5026-444A-9E0E-D6F2450F3A77";
pub const CONTENT_SIZE_UUID: &str = "00000007-5026-444A-9E0E-D6F2450F3A77";
pub const SUBMIT_VC_UUID: &str = "00000008-5026-444A-9E0E-D6F2450F3A77";
pub const TRANSFER_SUMMARY_REQUEST_UUID: &str = "00000009-5026-444A-9E0E-D6F2450F3A77";
pub const TRANSFER_SUMMARY_REPORT_UUID: &str = "0000000A-5026-444A-9E0E-D6F2450F3A77";
pub const DISCONNECT_UUID: &str = "0000000B-5026-444A-9E0E-D6F2450F3A77";

pub static OIDC_BLE_FLOW: LazyLock<Uuid> = LazyLock::new(Uuid::new_v4);

pub type MessageSize = u16;

// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#name-transfer-summary-report
pub(crate) type TransferSummaryReport = Vec<u16>;

// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#section-5.3
#[derive(Clone, Debug)]
pub struct IdentityRequest {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

impl IdentityRequest {
    pub fn encode(self) -> Vec<u8> {
        self.key
            .iter()
            .chain(&self.nonce)
            .copied()
            .collect::<Vec<u8>>()
    }
}

#[async_trait::async_trait]
pub trait BLEParse<T, Error> {
    async fn parse(self) -> Result<T, Error>;
}

#[async_trait::async_trait]
impl<T> BLEParse<TransferSummaryReport, anyhow::Error> for T
where
    T: Stream<Item = Result<Vec<u8>, BleError>> + Send,
{
    async fn parse(self) -> Result<TransferSummaryReport> {
        tokio::pin!(self);
        let data = self
            .try_next()
            .await?
            .ok_or(anyhow!("Failed to read transfer summary report"))?;

        data.chunks(2)
            .map(|chunk| {
                Ok(u16::from_be_bytes(chunk.try_into().map_err(|_| {
                    anyhow!("Failed to convert chunk to [u8; 2]")
                })?))
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl<T> BLEParse<MessageSize, anyhow::Error> for T
where
    T: Stream<Item = Result<Vec<u8>, BleError>> + Send,
{
    async fn parse(self) -> Result<u16> {
        tokio::pin!(self);
        let data = self
            .try_next()
            .await?
            .ok_or(anyhow!("Failed to read message size"))?;

        let arr = data
            .try_into()
            .map_err(|_| anyhow!("cannot convert request to [u8; 2]"))?;

        Ok(u16::from_be_bytes(arr))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BLEPeer {
    pub device_info: DeviceInfo,
    peer_encryption: PeerEncryption,
}

impl BLEPeer {
    pub fn new(
        device_info: DeviceInfo,
        sender_aes_key: [u8; 32],
        receiver_aes_key: [u8; 32],
        nonce: [u8; 12],
    ) -> Self {
        Self {
            device_info,
            peer_encryption: PeerEncryption::new(sender_aes_key, receiver_aes_key, nonce),
        }
    }

    pub fn encrypt<T>(&self, data: T) -> anyhow::Result<Vec<u8>>
    where
        T: Serialize,
    {
        self.peer_encryption.encrypt(data)
    }

    pub fn decrypt<T>(&self, ciphertext: &[u8]) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
    {
        self.peer_encryption.decrypt(ciphertext)
    }
}

const PRESENTATION_DEFINITION_BLE_NAME: &str = "name";
const PRESENTATION_DEFINITION_BLE_KEY: &str = "key";

pub(crate) struct OpenID4VCBLE {
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    ble: Option<BleWaiter>,
    config: Arc<core_config::CoreConfig>,
}

impl OpenID4VCBLE {
    pub fn new(
        proof_repository: Arc<dyn ProofRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        ble: Option<BleWaiter>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            proof_repository,
            interaction_repository,
            formatter_provider,
            key_provider,
            ble,
            config,
        }
    }
}

#[async_trait]
impl ExchangeProtocolImpl for OpenID4VCBLE {
    type VCInteractionContext = ();
    type VPInteractionContext = Option<BLEOpenID4VPInteractionData>;

    fn can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        url.scheme() == "openid4vp"
            && query_has_key(PRESENTATION_DEFINITION_BLE_NAME)
            && query_has_key(PRESENTATION_DEFINITION_BLE_KEY)
    }

    async fn handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        _storage_access: &StorageAccess,
        _handle_invitation_operations: &HandleInvitationOperationsAccess,
        _transport: Vec<String>,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        if !self.can_handle(&url) {
            return Err(ExchangeProtocolError::Failed(
                "No OpenID4VC over BLE query params detected".to_string(),
            ));
        }

        if !self
            .config
            .transport
            .ble_enabled_for(TransportType::Ble.as_ref())
        {
            return Err(ExchangeProtocolError::Disabled(
                "BLE transport is disabled".to_string(),
            ));
        }

        let ble = self.ble.clone().ok_or_else(|| {
            ExchangeProtocolError::Failed("BLE central not available".to_string())
        })?;

        let query = url.query().ok_or(ExchangeProtocolError::InvalidRequest(
            "Query cannot be empty".to_string(),
        ))?;

        let OpenID4VPBleData { name, key } = serde_qs::from_str(query)
            .map_err(|e| ExchangeProtocolError::InvalidRequest(e.to_string()))?;

        let mut ble_holder = OpenID4VCBLEHolder::new(
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
            ble,
        );

        if !ble_holder.enabled().await? {
            return Err(ExchangeProtocolError::Disabled(
                "BLE adapter is disabled".into(),
            ));
        }

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

        let proof_id = Uuid::new_v4().into();
        let proof = proof_from_handle_invitation(
            &proof_id,
            "OPENID4VC",
            None,
            None,
            interaction,
            now,
            None,
            "BLE",
            ProofStateEnum::Pending,
        );

        ble_holder
            .handle_invitation(name, key, proof.id, interaction_id, organisation)
            .await?;

        Ok(InvitationResponseDTO::ProofRequest {
            interaction_id,
            proof: Box::new(proof),
        })
    }

    async fn reject_proof(&self, _proof: &Proof) -> Result<(), ExchangeProtocolError> {
        let ble_holder = OpenID4VCBLEHolder::new(
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
            self.ble.clone().ok_or_else(|| {
                ExchangeProtocolError::Failed("Missing BLE central for reject proof".to_string())
            })?,
        );

        ble_holder.disconnect_from_verifier().await;
        Ok(())
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
        let ble = self.ble.clone().ok_or_else(|| {
            ExchangeProtocolError::Failed("Missing BLE central for submit proof".to_string())
        })?;

        let interaction_data: BLEOpenID4VPInteractionData = deserialize_interaction_data(
            proof
                .interaction
                .as_ref()
                .and_then(|interaction| interaction.data.as_ref()),
        )?;

        let ble_holder = OpenID4VCBLEHolder::new(
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
            ble,
        );

        if !ble_holder.enabled().await? {
            return Err(ExchangeProtocolError::Failed(
                "BLE adapter disabled".to_string(),
            ));
        }

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
            nonce: interaction_data.nonce.clone(),
            token_formats: Some(token_formats),
            vc_format_map: format_map,
            ..Default::default()
        };

        if format == "MDOC" {
            let mdoc_generated_nonce = interaction_data
                .identity_request_nonce
                .as_deref()
                .ok_or_else(|| {
                    ExchangeProtocolError::Failed(
                        "Cannot format MDOC - missing identity request nonce".to_string(),
                    )
                })?;
            let client_id = interaction_data.client_id.as_deref().ok_or_else(|| {
                ExchangeProtocolError::Failed("Cannot format MDOC - missing client_id".to_string())
            })?;
            let nonce = interaction_data.nonce.as_deref().ok_or_else(|| {
                ExchangeProtocolError::Failed("Cannot format MDOC - missing nonce".to_string())
            })?;

            ctx.mdoc_session_transcript = Some(
                to_cbor(&SessionTranscript {
                    handover: OID4VPHandover::compute(
                        client_id,
                        client_id,
                        nonce,
                        mdoc_generated_nonce,
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

        ble_holder
            .submit_presentation(vp_token, presentation_submission, &interaction_data)
            .await?;

        Ok(UpdateResponse {
            result: (),
            update_proof: None,
            create_did: None,
            update_credential: None,
            update_credential_schema: None,
        })
    }

    async fn accept_credential(
        &self,
        _credential: &Credential,
        _holder_did: &Did,
        _key: &Key,
        _jwk_key_id: Option<String>,
        _format: &str,
        _storage_access: &StorageAccess,
        _map_oidc_format_to_external: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        Err(ExchangeProtocolError::OperationNotSupported)
    }

    async fn reject_credential(
        &self,
        _credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        Err(ExchangeProtocolError::OperationNotSupported)
    }

    async fn share_credential(
        &self,
        _credential: &Credential,
        _credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        Err(ExchangeProtocolError::OperationNotSupported)
    }

    async fn share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        _key_id: KeyId,
        _encryption_key_jwk: PublicKeyJwkDTO,
        _vp_formats: HashMap<String, OpenID4VPFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        let interaction_id = Uuid::new_v4();

        // Pass the expected presentation content to interaction for verification
        let presentation_definition = create_open_id_for_vp_presentation_definition(
            interaction_id,
            proof,
            type_to_descriptor,
            format_to_type_mapper,
        )?;

        if !self.config.transport.ble_enabled_for(&proof.transport) {
            return Err(ExchangeProtocolError::Disabled(
                "BLE transport is disabled".to_string(),
            ));
        }

        let ble = self.ble.clone().ok_or_else(|| {
            ExchangeProtocolError::Failed("BLE central not available".to_string())
        })?;

        let ble_verifier = OpenID4VCBLEVerifier::new(
            ble,
            self.proof_repository.clone(),
            self.interaction_repository.clone(),
        )?;

        if !ble_verifier.enabled().await? {
            return Err(ExchangeProtocolError::Disabled(
                "BLE adapter is disabled".into(),
            ));
        }

        ble_verifier
            .share_proof(presentation_definition, proof.id, interaction_id)
            .await
            .map(|url| ShareResponse {
                url,
                interaction_id,
                context: None,
            })
    }

    async fn get_presentation_definition(
        &self,
        proof: &Proof,
        interaction_data: Self::VPInteractionContext,
        storage_access: &StorageAccess,
        _format_map: HashMap<String, String>,
        _types: HashMap<String, DatatypeType>,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        let presentation_definition = interaction_data
            .and_then(|i| i.presentation_definition)
            .ok_or_else(|| ExchangeProtocolError::Failed("missing interaction data".to_owned()))?;

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
                    .collect::<Result<Vec<_>, _>>()?,
                applicable_credentials: vec![],
                validity_credential_nbf,
            });
        }

        let mut allowed_schema_formats = HashSet::new();
        allowed_oidc_formats
            .iter()
            .try_for_each(|oidc_format| {
                let schema_type = map_from_oidc_format_to_core(oidc_format)?;

                self.config.format.iter().for_each(|(key, fields)| {
                    if fields.r#type.to_string().starts_with(&schema_type) {
                        allowed_schema_formats.insert(key);
                    }
                });
                Ok(())
            })
            .map_err(|e: ServiceError| ExchangeProtocolError::Failed(e.to_string()))?;

        let (credentials, credential_groups) = get_relevant_credentials_to_credential_schemas(
            storage_access,
            convert_inner(credential_groups),
            group_id_to_schema_id,
            &allowed_schema_formats,
        )
        .await?;
        presentation_definition_from_interaction_data(
            proof.id,
            convert_inner(credentials),
            convert_inner(credential_groups),
            &self.config,
        )
        .map(Into::into)
    }

    async fn validate_proof_for_submission(
        &self,
        proof: &Proof,
    ) -> std::result::Result<(), ExchangeProtocolError> {
        throw_if_latest_proof_state_not_eq(proof, ProofStateEnum::Pending)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn retract_proof(&self, _proof: &Proof) -> Result<(), ExchangeProtocolError> {
        self.ble
            .as_ref()
            .ok_or_else(|| ExchangeProtocolError::Failed("BLE is missing in service".to_string()))?
            .abort(Abort::Flow(*OIDC_BLE_FLOW))
            .await;

        Ok(())
    }

    fn get_capabilities(&self) -> ExchangeProtocolCapabilities {
        unimplemented!()
    }
}
