use std::collections::HashMap;

use anyhow::Context;
use dto_mapper::{convert_inner, From, Into};
use one_providers::exchange_protocol::openid4vc::model::OpenID4VPClientMetadata;
use serde::{Deserialize, Serialize};
use shared_types::ClaimSchemaId;
use time::OffsetDateTime;
use url::Url;

use super::openidvc_ble::MessageSize;
use crate::common_mapper::deserialize_with_serde_json;
use crate::model::interaction::InteractionId;

#[derive(Clone, Serialize, Deserialize, Debug, From, Into)]
#[from(one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinition)]
#[into(one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinition)]
pub struct OpenID4VPPresentationDefinition {
    pub id: InteractionId,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub input_descriptors: Vec<OpenID4VPPresentationDefinitionInputDescriptor>,
}

#[derive(Clone, Serialize, Deserialize, Debug, From, Into)]
#[from(one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinitionInputDescriptor)]
#[into(one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinitionInputDescriptor)]
pub struct OpenID4VPPresentationDefinitionInputDescriptor {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub format: HashMap<String, OpenID4VPPresentationDefinitionInputDescriptorFormat>,
    pub constraints: OpenID4VPPresentationDefinitionConstraint,
}

#[derive(Clone, Deserialize, Serialize, Debug, From, Into)]
#[from(one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinitionInputDescriptorFormat)]
#[into(one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinitionInputDescriptorFormat)]
pub struct OpenID4VPPresentationDefinitionInputDescriptorFormat {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alg: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof_type: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, From, Into)]
#[from(
    one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinitionConstraint
)]
#[into(
    one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinitionConstraint
)]
pub struct OpenID4VPPresentationDefinitionConstraint {
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub fields: Vec<OpenID4VPPresentationDefinitionConstraintField>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[derive(Clone, Serialize, Deserialize, Debug, From, Into)]
#[from(
    one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinitionConstraintField
)]
#[into(
    one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinitionConstraintField
)]
pub struct OpenID4VPPresentationDefinitionConstraintField {
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub id: Option<ClaimSchemaId>,
    pub path: Vec<String>,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub optional: Option<bool>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub filter: Option<OpenID4VPPresentationDefinitionConstraintFieldFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize, Debug, From, Into)]
#[from(
    one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinitionConstraintFieldFilter
)]
#[into(
    one_providers::exchange_protocol::openid4vc::model::OpenID4VPPresentationDefinitionConstraintFieldFilter
)]
pub struct OpenID4VPPresentationDefinitionConstraintFieldFilter {
    pub r#type: String,
    pub r#const: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPInteractionData {
    pub response_type: String,
    pub state: Option<String>,
    pub nonce: String,
    pub client_id_scheme: String,
    pub client_id: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub client_metadata: Option<OpenID4VPClientMetadata>,
    pub client_metadata_uri: Option<Url>,
    pub response_mode: String,
    pub response_uri: Url,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    pub presentation_definition_uri: Option<Url>,

    #[serde(skip_serializing)]
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPBleData {
    pub key: String,
    pub name: String,
}

#[derive(Debug)]
pub struct Chunk {
    pub index: MessageSize,
    pub payload: Vec<u8>,
    pub checksum: u16,
}

impl Chunk {
    pub fn new(index: MessageSize, payload: Vec<u8>) -> Self {
        let idx_bytes = index.to_be_bytes();

        let crc = crc::Crc::<u16>::new(&crc::CRC_16_IBM_3740);

        let checksum = crc.checksum(
            [idx_bytes.as_slice(), payload.as_slice()]
                .concat()
                .as_slice(),
        );
        Self {
            index,
            payload,
            checksum,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [
            self.index.to_be_bytes().as_slice(),
            &self.payload,
            self.checksum.to_be_bytes().as_slice(),
        ]
        .concat()
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let (index, rest) = bytes.split_at(2);
        let (payload, checksum) = rest.split_at(rest.len() - 2);

        let chunk_index = index.try_into().context("Failed to read chunk index")?;
        let received_checksum =
            u16::from_be_bytes(checksum.try_into().context("Failed to read checksum")?);

        let crc = crc::Crc::<u16>::new(&crc::CRC_16_IBM_3740);

        let calculated_checksum = crc.checksum([index, payload].concat().as_slice());

        if received_checksum != calculated_checksum {
            return Err(anyhow::anyhow!(
                "Invalid checksum. Computed: {calculated_checksum}, received: {:?}",
                received_checksum
            ));
        }

        Ok(Self {
            index: MessageSize::from_be_bytes(chunk_index),
            payload: payload.to_owned(),
            checksum: received_checksum,
        })
    }
}

pub type Chunks = Vec<Chunk>;

pub trait ChunkExt {
    fn from_bytes(bytes: &[u8], chunk_size: MessageSize) -> Chunks;
}

impl ChunkExt for Chunks {
    fn from_bytes(bytes: &[u8], chunk_size: MessageSize) -> Self {
        bytes
            .chunks((chunk_size - 4) as usize)
            .enumerate()
            .map(|(index, chunk)| Chunk::new((index + 1) as MessageSize, chunk.to_vec()))
            .collect()
    }
}
