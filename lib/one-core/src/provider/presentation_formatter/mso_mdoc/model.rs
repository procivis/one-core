use ciborium::cbor;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize, Serializer, ser};
use serde_with::skip_serializing_none;

use super::session_transcript::SessionTranscript;
use crate::proto::cose::CoseSign1;
use crate::util::mdoc::{
    DataElementIdentifier, DataElementValue, EmbeddedCbor, IssuerSigned, Namespace,
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
