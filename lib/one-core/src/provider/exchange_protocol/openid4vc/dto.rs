use std::collections::HashMap;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use shared_types::{ClaimSchemaId, KeyId};
use strum::Display;
use time::OffsetDateTime;
use url::Url;

use crate::common_mapper::deserialize_with_serde_json;
use crate::model::credential_schema::WalletStorageTypeEnum;
use crate::model::interaction::InteractionId;
use crate::provider::dto::PublicKeyJwkDTO;

use super::openidvc_ble::MessageSize;

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenID4VCICredential {
    pub format: String,
    pub credential_definition: Option<OpenID4VCICredentialDefinition>,
    pub doctype: Option<String>,
    pub proof: OpenID4VCIProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCIProof {
    pub proof_type: String,
    pub jwt: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialDefinition {
    pub r#type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<OpenID4VCICredentialSubject>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialOfferCredentialDTO {
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_definition: Option<OpenID4VCICredentialDefinition>,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<HashMap<String, OpenID4VCICredentialOfferClaim>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VCICredentialOfferClaim {
    pub value: OpenID4VCICredentialOfferClaimValue,
    pub value_type: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum OpenID4VCICredentialOfferClaimValue {
    Nested(HashMap<String, OpenID4VCICredentialOfferClaim>),
    String(String),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialOfferDTO {
    pub credential_issuer: String,
    pub credentials: Vec<OpenID4VCICredentialOfferCredentialDTO>,
    pub grants: OpenID4VCIGrants,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCICredentialSubject {
    #[serde(flatten)]
    pub keys: HashMap<String, OpenID4VCICredentialValueDetails>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VCICredentialValueDetails {
    pub value: String,
    pub value_type: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCIGrants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub code: OpenID4VCIGrant,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCIGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VPClientMetadata {
    #[serde(default)]
    pub jwks: Vec<OpenID4VPClientMetadataJwkDTO>,
    pub vp_formats: HashMap<String, OpenID4VPFormat>,
    pub client_id_scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_alg: Option<AuthorizationEncryptedResponseAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_encrypted_response_enc:
        Option<AuthorizationEncryptedResponseContentEncryptionAlgorithm>,
}

// https://datatracker.ietf.org/doc/html/rfc7518#section-4.1
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Display)]
pub enum AuthorizationEncryptedResponseAlgorithm {
    // Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
    #[serde(rename = "ECDH-ES")]
    #[strum(serialize = "ECDH-ES")]
    EcdhEs,
}

// https://datatracker.ietf.org/doc/html/rfc7518#section-5.1
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Display)]
pub enum AuthorizationEncryptedResponseContentEncryptionAlgorithm {
    // AES GCM using 256-bit key
    A256GCM,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VPClientMetadataJwkDTO {
    #[serde(rename = "kid")]
    pub key_id: KeyId,
    #[serde(flatten)]
    pub jwk: PublicKeyJwkDTO,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct OpenID4VPFormat {
    pub alg: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VPPresentationDefinition {
    pub id: InteractionId,
    pub input_descriptors: Vec<OpenID4VPPresentationDefinitionInputDescriptor>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VPPresentationDefinitionInputDescriptor {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub format: HashMap<String, OpenID4VPPresentationDefinitionInputDescriptorFormat>,
    pub constraints: OpenID4VPPresentationDefinitionConstraint,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPPresentationDefinitionInputDescriptorFormat {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alg: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof_type: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VPPresentationDefinitionConstraint {
    pub fields: Vec<OpenID4VPPresentationDefinitionConstraintField>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VPPresentationDefinitionConstraintField {
    pub id: Option<ClaimSchemaId>,
    pub path: Vec<String>,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub optional: Option<bool>,
    pub filter: Option<OpenID4VPPresentationDefinitionConstraintFieldFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
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
    pub client_id: Url,
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
