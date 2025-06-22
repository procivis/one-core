use anyhow::anyhow;
use ciborium::cbor;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize, Serializer, de, ser};
use serde_with::skip_serializing_none;
use sha2::{Digest, Sha256};

use crate::provider::verification_protocol::iso_mdl::common::EReaderKey;
use crate::provider::verification_protocol::iso_mdl::device_engagement::DeviceEngagement;
use crate::util::cose::CoseSign1;
use crate::util::mdoc::{
    Bstr, DataElementIdentifier, DataElementValue, EmbeddedCbor, IssuerSigned, Namespace,
};

pub type DeviceSignedItems = IndexMap<DataElementIdentifier, DataElementValue>;
pub type DeviceNamespaces = IndexMap<Namespace, DeviceSignedItems>;

pub type DocType = String;
pub type ErrorCode = i64;
pub type DocumentError = IndexMap<DocType, ErrorCode>;
pub type Errors = IndexMap<Namespace, ErrorItems>;
pub type ErrorItems = IndexMap<DataElementIdentifier, ErrorCode>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DeviceResponseVersion {
    #[serde(rename = "1.0")]
    V1_0,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    pub version: DeviceResponseVersion,
    pub documents: Option<Vec<Document>>,
    pub document_errors: Option<Vec<DocumentError>>,
    pub status: u64,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub doc_type: DocType,
    pub issuer_signed: IssuerSigned,
    pub device_signed: DeviceSigned,
    pub errors: Option<Errors>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSigned {
    pub name_spaces: EmbeddedCbor<DeviceNamespaces>,
    pub device_auth: DeviceAuth,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAuth {
    pub device_signature: Option<CoseSign1>,
}

// used in DeviceSigned as detached payload
// should be serialized as cbor array: DeviceAuthentication = ["DeviceAuthentication", SessionTranscriptBytes, DocType; DeviceNameSpaceBytes]
#[derive(Debug, PartialEq)]
pub(crate) struct DeviceAuthentication {
    pub session_transcript: SessionTranscript,
    pub doctype: DocType,
    pub device_namespaces: EmbeddedCbor<DeviceNamespaces>,
}

impl Serialize for DeviceAuthentication {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!([
            "DeviceAuthentication",
            self.session_transcript,
            self.doctype,
            self.device_namespaces,
        ])
        .map_err(ser::Error::custom)?
        .serialize(serializer)
    }
}

//  SessionTranscript = [
//    DeviceEngagementBytes,
//    EReaderKeyBytes,
//    OID4VPHandover
//  ]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SessionTranscript {
    pub device_engagement_bytes: Option<EmbeddedCbor<DeviceEngagement>>,
    pub e_reader_key_bytes: Option<EmbeddedCbor<EReaderKey>>,
    pub handover: Option<OID4VPHandover>,
}

impl Serialize for SessionTranscript {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!([
            self.device_engagement_bytes,
            self.e_reader_key_bytes,
            self.handover
        ])
        .map_err(ser::Error::custom)?
        .serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for SessionTranscript {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'a>,
    {
        let (device_engagement_bytes, e_reader_key_bytes, handover) =
            ciborium::Value::deserialize(deserializer)?
                .deserialized()
                .map_err(de::Error::custom)?;

        Ok(Self {
            device_engagement_bytes,
            e_reader_key_bytes,
            handover,
        })
    }
}

//  OID4VPHandover = [
//    clientIdHash,
//    responseUriHash,
//    nonce
//  ]
#[derive(Debug, Clone, PartialEq)]
pub struct OID4VPHandover {
    client_id_hash: Bstr,
    response_uri_hash: Bstr,
    nonce: String,
}

impl OID4VPHandover {
    pub(crate) fn compute(
        client_id: &str,
        response_uri: &str,
        nonce: &str,
        mdoc_generated_nonce: &str,
    ) -> Result<Self, anyhow::Error> {
        let client_id_to_hash = [client_id, mdoc_generated_nonce];
        let response_uri_to_hash = [response_uri, mdoc_generated_nonce];

        let client_id_hash = Self::compute_hash(&client_id_to_hash)?;
        let response_uri_hash = Self::compute_hash(&response_uri_to_hash)?;

        Ok(Self {
            client_id_hash,
            response_uri_hash,
            nonce: nonce.to_owned(),
        })
    }

    fn compute_hash(values_to_hash: &[&str]) -> Result<Bstr, anyhow::Error> {
        let cbor_value = cbor!(values_to_hash).map_err(|e| anyhow!("CBOR error: {}", e))?;

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&cbor_value, &mut buf)
            .map_err(|e| anyhow!("CBOR serialization error: {}", e))?;

        Ok(Bstr(Sha256::digest(&buf).to_vec()))
    }
}

impl Serialize for OID4VPHandover {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!([self.client_id_hash, self.response_uri_hash, self.nonce])
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for OID4VPHandover {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'a>,
    {
        let (client_id_hash, response_uri_hash, nonce) =
            ciborium::Value::deserialize(deserializer)?
                .deserialized()
                .map_err(de::Error::custom)?;

        Ok(Self {
            client_id_hash,
            response_uri_hash,
            nonce,
        })
    }
}
