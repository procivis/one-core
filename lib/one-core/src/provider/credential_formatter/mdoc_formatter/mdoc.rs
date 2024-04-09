use ciborium::tag::Required;
use coset::{AsCborValue, CoseKey, CoseSign1};
use indexmap::IndexMap;
use serde::{ser, Deserialize, Serialize, Serializer};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub type Namespace = String;

pub type Namespaces = IndexMap<Namespace, Vec<IssuerSignedItemBytes>>;

pub type ValueDigests = IndexMap<Namespace, DigestIDs>;

pub type DigestIDs = IndexMap<u64, Bstr>;

type EmbeddedCborTag = Required<Bstr, 24>;

type DateTimeCborTag = Required<String, 0>;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    pub name_spaces: Option<Namespaces>,
    pub issuer_auth: IssuerAuth,
}
impl IssuerSigned {
    pub(crate) fn to_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut output = vec![];
        ciborium::into_writer(self, &mut output)?;

        Ok(output)
    }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(try_from = "EmbeddedCborTag")]
pub struct IssuerSignedItemBytes(pub IssuerSignedItem);

impl IssuerSignedItemBytes {
    pub(crate) fn to_embedded_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut output = vec![];
        ciborium::into_writer(self, &mut output)?;

        Ok(output)
    }
}

impl Serialize for IssuerSignedItemBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_embedded_cbor(&self.0, serializer)
    }
}

impl TryFrom<EmbeddedCborTag> for IssuerSignedItemBytes {
    type Error = ciborium::de::Error<std::io::Error>;

    fn try_from(Required(Bstr(value)): EmbeddedCborTag) -> Result<Self, Self::Error> {
        let signed_item: IssuerSignedItem = ciborium::from_reader(value.as_slice())?;

        Ok(Self(signed_item))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItem {
    #[serde(rename = "digestID")]
    pub digest_id: u64,
    pub random: Bstr,
    pub element_identifier: String,
    // DataElementValue = any
    pub element_value: ciborium::Value,
}

// The payload for CoseSign1 is MobileSecurityObjectBytes
#[derive(Debug, Deserialize, PartialEq)]
#[serde(try_from = "ciborium::Value")]
pub struct IssuerAuth(pub CoseSign1);

impl Serialize for IssuerAuth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let issuer_auth = self.0.clone().to_cbor_value().map_err(ser::Error::custom)?;

        issuer_auth.serialize(serializer)
    }
}

impl TryFrom<ciborium::Value> for IssuerAuth {
    type Error = coset::CoseError;

    fn try_from(value: ciborium::Value) -> Result<Self, Self::Error> {
        let sign = CoseSign1::from_cbor_value(value)?;

        Ok(Self(sign))
    }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(try_from = "EmbeddedCborTag")]
pub struct MobileSecurityObjectBytes(pub MobileSecurityObject);

impl MobileSecurityObjectBytes {
    pub(crate) fn to_cbor_bytes(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut output = vec![];
        ciborium::into_writer(self, &mut output)?;

        Ok(output)
    }
}

impl Serialize for MobileSecurityObjectBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_embedded_cbor(&self.0, serializer)
    }
}

impl TryFrom<EmbeddedCborTag> for MobileSecurityObjectBytes {
    type Error = ciborium::de::Error<std::io::Error>;

    fn try_from(Required(Bstr(value)): EmbeddedCborTag) -> Result<Self, Self::Error> {
        let mso: MobileSecurityObject = ciborium::from_reader(value.as_slice())?;

        Ok(Self(mso))
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
    pub key_authorizations: Option<KeyAuthorizations>,
    pub key_info: Option<KeyInfo>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(try_from = "ciborium::Value")]
pub struct DeviceKey(pub CoseKey);

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
        let key = CoseKey::from_cbor_value(value)?;
        Ok(Self(key))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KeyAuthorizations {
    // authorized namespaces
    pub name_spaces: Option<Vec<String>>,
    // authorized data elements
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
    pub expected_update: Option<DateTime>,
}

// datetime for cbor should be in RFC-3339 format as String
#[derive(Debug, Deserialize, PartialEq)]
#[serde(try_from = "DateTimeCborTag")]
pub struct DateTime(pub OffsetDateTime);

impl Serialize for DateTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        //Should be serialized as Rfc3339 without fraction seconds
        let datetime = self
            .0
            .replace_microsecond(0)
            // SAFETY: 0 is a valid microsecond
            .unwrap()
            .format(&Rfc3339)
            .map_err(ser::Error::custom)?;

        ciborium::tag::Required::<_, 0>(datetime).serialize(serializer)
    }
}

impl TryFrom<DateTimeCborTag> for DateTime {
    type Error = time::Error;

    fn try_from(value: DateTimeCborTag) -> Result<Self, Self::Error> {
        let datetime = OffsetDateTime::parse(&value.0, &Rfc3339)?;

        Ok(Self(datetime))
    }
}

// using custom type since when serializing ciborium doesn't understand if a Vec<u8> is Value::Bytes(..) or Value::Array(Value)
#[derive(Debug, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct Bstr(pub Vec<u8>);

impl Serialize for Bstr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ciborium::Value::Bytes(self.0.to_vec()).serialize(serializer)
    }
}

fn serialize_embedded_cbor<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    let mut embedded_cbor = vec![];
    ciborium::into_writer(value, &mut embedded_cbor).map_err(ser::Error::custom)?;

    let embedded_cbor = ciborium::Value::Bytes(embedded_cbor);

    Required::<_, 24>(embedded_cbor).serialize(serializer)
}
