use anyhow::anyhow;
use ciborium::{cbor, tag::Required, Value};
use coset::AsCborValue;
use indexmap::IndexMap;
use serde::{
    de::{self, DeserializeOwned},
    ser, Deserialize, Serialize, Serializer,
};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use url::Url;

pub type Namespace = String;

pub type Namespaces = IndexMap<Namespace, Vec<EmbeddedCbor<IssuerSignedItem>>>;

pub type DeviceNamespaces = IndexMap<Namespace, DeviceSignedItems>;
pub type DeviceSignedItems = IndexMap<DataElementIdentifier, DataElementValue>;

pub type ValueDigests = IndexMap<Namespace, DigestIDs>;

pub type DigestIDs = IndexMap<u64, Bstr>; // latter is the sha result

pub type DocumentError = IndexMap<DocType, ErrorCode>;
pub type Errors = IndexMap<Namespace, ErrorItems>;
pub type ErrorItems = IndexMap<DataElementIdentifier, ErrorCode>;
pub type DocType = String;
pub type ErrorCode = i64;

pub type DataElementIdentifier = String;
// DataElementValue = any
pub type DataElementValue = ciborium::Value;

const EMBEDDED_CBOR_TAG: u64 = 24;
const DATE_TIME_CBOR_TAG: u64 = 0;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    pub version: DeviceResponseVersion,
    pub documents: Option<Vec<Document>>,
    pub document_errors: Option<Vec<DocumentError>>,
    pub status: u64,
}

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
pub struct IssuerSigned {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_spaces: Option<Namespaces>,
    pub issuer_auth: CoseSign1,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItem {
    #[serde(rename = "digestID")]
    pub digest_id: u64, // Compare with namespace
    pub random: Bstr,
    pub element_identifier: DataElementIdentifier,
    pub element_value: DataElementValue,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSigned {
    pub name_spaces: EmbeddedCbor<DeviceNamespaces>,
    pub device_auth: DeviceAuth,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAuth {
    pub device_signature: Option<CoseSign1>,
}

#[derive(Debug, PartialEq)]
pub struct CoseSign1(pub coset::CoseSign1);

impl From<coset::CoseSign1> for CoseSign1 {
    fn from(cose_sign1: coset::CoseSign1) -> Self {
        Self(cose_sign1)
    }
}

impl Serialize for CoseSign1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0
            .clone()
            .to_cbor_value()
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CoseSign1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let value = ciborium::Value::deserialize(deserializer)?;

        coset::CoseSign1::from_cbor_value(value)
            .map(CoseSign1)
            .map_err(de::Error::custom)
    }
}

// payload for the IssuerAuth CoseSign1
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MobileSecurityObject {
    pub version: MobileSecurityObjectVersion,
    pub digest_algorithm: DigestAlgorithm,
    pub value_digests: ValueDigests,
    pub device_key_info: DeviceKeyInfo,
    pub doc_type: String,
    pub validity_info: ValidityInfo,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum MobileSecurityObjectVersion {
    #[serde(rename = "1.0")]
    V1_0,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum DeviceResponseVersion {
    #[serde(rename = "1.0")]
    V1_0,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum DigestAlgorithm {
    #[serde(rename = "SHA-256")]
    Sha256,
    #[serde(rename = "SHA-348")]
    Sha384,
    #[serde(rename = "SHA-512")]
    Sha512,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    pub device_key: DeviceKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_authorizations: Option<KeyAuthorizations>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_info: Option<KeyInfo>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(try_from = "ciborium::Value")]
pub struct DeviceKey(pub coset::CoseKey);

impl Serialize for DeviceKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let device_key = self.0.clone().to_cbor_value().map_err(ser::Error::custom)?;

        device_key.serialize(serializer)
    }
}

impl TryFrom<ciborium::Value> for DeviceKey {
    type Error = coset::CoseError;

    fn try_from(value: ciborium::Value) -> Result<Self, Self::Error> {
        let key = coset::CoseKey::from_cbor_value(value)?;
        Ok(Self(key))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KeyAuthorizations {
    // authorized namespaces
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_spaces: Option<Vec<String>>,
    // authorized data elements
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_elements: Option<IndexMap<String, Vec<String>>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct KeyInfo(IndexMap<i64, ciborium::Value>);

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ValidityInfo {
    pub signed: DateTime,
    pub valid_from: DateTime,
    pub valid_until: DateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_update: Option<DateTime>,
}

// datetime for cbor should be in RFC-3339 format as String
#[derive(Debug, PartialEq)]
pub struct DateTime(pub OffsetDateTime);

impl Serialize for DateTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        //Should be serialized as Rfc3339 without fraction seconds
        self.0
            .replace_microsecond(0)
            // SAFETY: 0 is a valid microsecond
            .unwrap()
            .format(&Rfc3339)
            .map(ciborium::tag::Required::<String, DATE_TIME_CBOR_TAG>)
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DateTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let datetime =
            ciborium::tag::Required::<String, DATE_TIME_CBOR_TAG>::deserialize(deserializer)?;

        OffsetDateTime::parse(&datetime.0, &Rfc3339)
            .map(DateTime)
            .map_err(de::Error::custom)
    }
}

impl From<DateTime> for OffsetDateTime {
    fn from(value: DateTime) -> Self {
        value.0
    }
}

// using custom type since ciborium doesn't understand if a Vec<u8> is Value::Bytes(..) or Value::Array(Value)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(try_from = "ciborium::Value", into = "ciborium::Value")]
pub struct Bstr(pub Vec<u8>);

impl From<Bstr> for ciborium::Value {
    fn from(Bstr(value): Bstr) -> Self {
        Self::Bytes(value)
    }
}

impl TryFrom<ciborium::Value> for Bstr {
    type Error = anyhow::Error;

    fn try_from(value: ciborium::Value) -> Result<Self, Self::Error> {
        Ok(Self(
            value.into_bytes().map_err(|_| anyhow!("Value not bytes"))?,
        ))
    }
}

// used in DeviceSigned as detached payload
// should be serialized as cbor array: DeviceAuthentication = ["DeviceAuthentication", SessionTranscriptBytes, DocType; DeviceNameSpaceBytes]
#[derive(Debug, PartialEq)]
pub struct DeviceAuthentication {
    pub session_transcript: EmbeddedCbor<SessionTranscript>,
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
//       DeviceEngagementBytes = null,
//       EReaderKeyBytes = null,
//       OID4VPHandover
//     ]
#[derive(Debug, PartialEq)]
pub struct SessionTranscript {
    pub handover: OID4VPHandover,
}

impl Serialize for SessionTranscript {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!([Value::Null, Value::Null, self.handover])
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

//  OID4VPHandover = [
//    clientIdHash,
//    responseUriHash,
//    nonce
//  ]
#[derive(Debug, PartialEq)]
pub struct OID4VPHandover {
    client_id_hash: Bstr,
    response_uri_hash: Bstr,
    nonce: String,
}

impl OID4VPHandover {
    pub(crate) fn compute(
        client_id: &str,
        response_uri: &Url,
        nonce: &str,
        mdoc_generated_nonce: &str,
    ) -> Self {
        let client_id_hash = Sha256::digest([client_id, mdoc_generated_nonce].concat()).to_vec();
        let response_uri_hash =
            Sha256::digest([response_uri.as_str(), mdoc_generated_nonce].concat()).to_vec();

        Self {
            client_id_hash: Bstr(client_id_hash),
            response_uri_hash: Bstr(response_uri_hash),
            nonce: nonce.to_owned(),
        }
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

/// Represents Embedded CBOR type, where T gets converted to a byte array(`bstr`).
/// In CDDL this is represented as: `#6.24(bstr .cbor T)`
#[derive(Debug, PartialEq, Clone)]
pub struct EmbeddedCbor<T>(pub T);

impl<T> EmbeddedCbor<T> {
    pub(crate) fn to_vec(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>>
    where
        Self: Serialize,
    {
        let mut output = Vec::with_capacity(128);
        ciborium::into_writer(self, &mut output)?;

        Ok(output)
    }
}

impl<T: Serialize> Serialize for EmbeddedCbor<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut t = Vec::with_capacity(128);
        ciborium::into_writer(&self.0, &mut t).map_err(ser::Error::custom)?;

        let tagged_value = Required::<_, EMBEDDED_CBOR_TAG>(Bstr(t));

        tagged_value.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for EmbeddedCbor<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let Required(Bstr(embedded_cbor)) =
            Required::<_, EMBEDDED_CBOR_TAG>::deserialize(deserializer)?;
        let t: T = ciborium::from_reader(&embedded_cbor[..]).map_err(de::Error::custom)?;

        Ok(Self(t))
    }
}
