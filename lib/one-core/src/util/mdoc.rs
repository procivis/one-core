use anyhow::{Context, anyhow};
use ciborium::Value;
use ciborium::tag::Required;
use coset::iana::EnumI64;
use coset::{AsCborValue, Label, ProtectedHeader, RegisteredLabelWithPrivate, iana};
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use indexmap::IndexMap;
use pem::{EncodeConfig, LineEnding, Pem, encode_many_config};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer, de, ser};
use serde_with::skip_serializing_none;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::CertificateDetails;
use crate::service::certificate::validator::{
    CertificateValidationOptions, CertificateValidator, EnforceKeyUsage, ParsedCertificate,
};
use crate::util::cose::CoseSign1;

const EMBEDDED_CBOR_TAG: u64 = 24;
const DATE_TIME_CBOR_TAG: u64 = 0;

pub type DataElementIdentifier = String;
pub type DataElementValue = ciborium::Value;
pub type Namespace = String;
pub type Namespaces = IndexMap<Namespace, Vec<EmbeddedCbor<IssuerSignedItem>>>;
pub type ValueDigests = IndexMap<Namespace, DigestIDs>;

pub type DigestIDs = IndexMap<u64, Bstr>; // latter is the sha result

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    pub name_spaces: Option<Namespaces>,
    pub issuer_auth: CoseSign1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItem {
    #[serde(rename = "digestID")]
    pub digest_id: u64, // Compare with namespace
    pub random: Bstr,
    pub element_identifier: DataElementIdentifier,
    pub element_value: DataElementValue,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct KeyInfo(IndexMap<i64, Value>);

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ValidityInfo {
    pub signed: DateTime,
    pub valid_from: DateTime,
    pub valid_until: DateTime,
    pub expected_update: Option<DateTime>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KeyAuthorizations {
    // authorized namespaces
    pub name_spaces: Option<Vec<String>>,
    // authorized data elements
    pub data_elements: Option<IndexMap<String, Vec<String>>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    pub device_key: DeviceKey,
    pub key_authorizations: Option<KeyAuthorizations>,
    pub key_info: Option<KeyInfo>,
}

// payload for the IssuerAuth CoseSign1
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MobileSecurityObject {
    pub version: MobileSecurityObjectVersion,
    pub digest_algorithm: DigestAlgorithm,
    pub value_digests: ValueDigests,
    pub device_key_info: DeviceKeyInfo,
    pub doc_type: String,
    pub validity_info: ValidityInfo,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
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

// datetime for cbor should be in RFC-3339 format as String
#[derive(Clone, Debug, PartialEq)]
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
            .map_err(ser::Error::custom)?
            .format(&Rfc3339)
            .map(Required::<String, DATE_TIME_CBOR_TAG>)
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

/// Represents Embedded CBOR type, where T gets converted to a byte array(`bstr`).
/// In CDDL this is represented as: `#6.24(bstr .cbor T)`
#[derive(Debug, PartialEq, Clone)]
pub struct EmbeddedCbor<T> {
    inner: T,
    original_bytes: Vec<u8>,
}

impl<T> EmbeddedCbor<T> {
    pub(crate) fn new(inner: T) -> Result<Self, ciborium::ser::Error<std::io::Error>>
    where
        T: Serialize,
    {
        let mut t: Vec<u8> = Vec::with_capacity(128);
        ciborium::into_writer(&inner, &mut t)?;

        let tagged_value = Required::<_, EMBEDDED_CBOR_TAG>(Bstr(t));

        let mut original_bytes: Vec<u8> = Vec::with_capacity(128);
        ciborium::into_writer(&tagged_value, &mut original_bytes)?;

        Ok(Self {
            original_bytes,
            inner,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.original_bytes.as_slice()
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.original_bytes
    }

    pub(crate) fn inner(&self) -> &T {
        &self.inner
    }

    pub(crate) fn into_inner(self) -> T {
        self.inner
    }

    pub(crate) fn inner_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let Required::<_, EMBEDDED_CBOR_TAG>(Bstr(embedded_cbor)) =
            ciborium::from_reader(self.original_bytes.as_slice())?;

        Ok(embedded_cbor)
    }
}

impl<T: Serialize> Serialize for EmbeddedCbor<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Required::<_, EMBEDDED_CBOR_TAG>(Bstr(embedded_cbor)) =
            ciborium::from_reader(self.original_bytes.as_slice()).map_err(ser::Error::custom)?;

        let tagged_value = Required::<_, EMBEDDED_CBOR_TAG>(Bstr(embedded_cbor));

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

        let inner: T =
            ciborium::from_reader(embedded_cbor.as_slice()).map_err(de::Error::custom)?;

        let tagged_value = Required::<_, EMBEDDED_CBOR_TAG>(Bstr(embedded_cbor));

        let mut original_bytes: Vec<u8> = Vec::with_capacity(128);
        ciborium::into_writer(&tagged_value, &mut original_bytes).map_err(de::Error::custom)?;

        Ok(Self {
            inner,
            original_bytes,
        })
    }
}

pub(crate) async fn extract_certificate_from_x5chain_header(
    certificate_validator: &dyn CertificateValidator,
    CoseSign1(cose_sign1): &CoseSign1,
    verify: bool,
) -> Result<CertificateDetails, FormatterError> {
    let x5chain_label = Label::Int(coset::iana::HeaderParameter::X5Chain.to_i64());

    let (_, x5c) = cose_sign1
        .unprotected
        .rest
        .iter()
        .find(|(label, _)| label == &x5chain_label)
        .ok_or(FormatterError::Failed("Missing x5chain header".to_string()))?;

    let pem_chain_bytes = match x5c {
        Value::Bytes(single_cert) => {
            vec![single_cert.clone()]
        }
        Value::Array(many_certs) => many_certs
            .iter()
            .flat_map(|val| val.as_bytes().into_iter().cloned())
            .collect(),
        val => {
            return Err(FormatterError::Failed(format!(
                "Unexpected value in x5chain header: {val:?}"
            )));
        }
    };
    let pems: Vec<Pem> =
        pem_chain_bytes
            .into_iter()
            .try_fold(Vec::new(), |mut aggr, der_bytes| {
                aggr.push(Pem::new("CERTIFICATE", der_bytes));
                Ok::<_, FormatterError>(aggr)
            })?;
    let chain = encode_many_config(&pems, EncodeConfig::new().set_line_ending(LineEnding::LF));

    let validation_context = if verify {
        CertificateValidationOptions::signature_and_revocation(Some(vec![
            EnforceKeyUsage::DigitalSignature,
        ]))
    } else {
        CertificateValidationOptions::no_validation()
    };

    let ParsedCertificate {
        attributes,
        subject_common_name,
        ..
    } = certificate_validator
        .parse_pem_chain(&chain, validation_context)
        .await
        .map_err(|err| FormatterError::Failed(format!("Failed to validate pem chain: {err}")))?;

    Ok(CertificateDetails {
        chain,
        fingerprint: attributes.fingerprint,
        expiry: attributes.not_after,
        subject_common_name,
    })
}

pub(crate) fn extract_algorithm_from_header(
    cose_sign1: &coset::CoseSign1,
) -> Option<KeyAlgorithmType> {
    let alg = &cose_sign1.protected.header.alg;

    if let Some(RegisteredLabelWithPrivate::Assigned(algorithm)) = alg {
        match algorithm {
            iana::Algorithm::ES256 => Some(KeyAlgorithmType::Ecdsa),
            iana::Algorithm::EdDSA => Some(KeyAlgorithmType::Eddsa),
            _ => None,
        }
    } else {
        None
    }
}

pub(crate) fn try_build_algorithm_header(
    algorithm: KeyAlgorithmType,
) -> Result<ProtectedHeader, FormatterError> {
    let algorithm = match algorithm {
        KeyAlgorithmType::Ecdsa => iana::Algorithm::ES256,
        KeyAlgorithmType::Eddsa => iana::Algorithm::EdDSA,
        _ => {
            return Err(FormatterError::Failed(format!(
                "Failed mapping algorithm `{algorithm}` to name compatible with allowed COSE Algorithms"
            )));
        }
    };
    let algorithm_header = coset::HeaderBuilder::new().algorithm(algorithm).build();

    Ok(ProtectedHeader {
        original_data: None,
        header: algorithm_header,
    })
}

pub(crate) fn try_extract_mobile_security_object(
    CoseSign1(cose_sign1): &CoseSign1,
) -> Result<MobileSecurityObject, FormatterError> {
    let Some(payload) = &cose_sign1.payload else {
        return Err(FormatterError::Failed(
            "IssuerAuth doesn't contain payload".to_owned(),
        ));
    };

    let mso: EmbeddedCbor<MobileSecurityObject> =
        ciborium::from_reader(&payload[..]).map_err(|err| {
            FormatterError::Failed(format!(
                "IssuerAuth payload cannot be converted to MSO: {err}"
            ))
        })?;

    Ok(mso.into_inner())
}
pub(crate) fn try_extract_holder_public_key(
    CoseSign1(issuer_auth): &CoseSign1,
) -> Result<PublicKeyJwk, FormatterError> {
    let mso = issuer_auth
        .payload
        .as_ref()
        .ok_or_else(|| FormatterError::Failed("Issuer auth missing mso object".to_owned()))?;

    let mso: EmbeddedCbor<MobileSecurityObject> = ciborium::from_reader(&mso[..])
        .map_err(|err| FormatterError::Failed(format!("Failed deserializing MSO: {err}")))?;

    let DeviceKey(cose_key) = mso.into_inner().device_key_info.device_key;

    let get_param_value = |key| {
        cose_key
            .params
            .iter()
            .find_map(|(k, v)| (k == &key).then_some(v))
    };

    match cose_key.kty {
        coset::RegisteredLabel::Assigned(iana::KeyType::EC2) => (|| -> anyhow::Result<_> {
            let _crv = get_param_value(Label::Int(iana::Ec2KeyParameter::Crv.to_i64()))
                .and_then(|v| v.as_integer())
                .filter(|v| v == &iana::EllipticCurve::P_256.to_i64().into())
                .context("Missing P-256 curve in params")?;

            let x = get_param_value(Label::Int(iana::Ec2KeyParameter::X.to_i64()))
                .and_then(|v| v.as_bytes())
                .and_then(|v| Base64UrlSafeNoPadding::encode_to_string(v).ok())
                .context("Missing P-256 X value in params")?;

            let y = get_param_value(Label::Int(iana::Ec2KeyParameter::Y.to_i64()))
                .and_then(|v| v.as_bytes())
                .and_then(|v| Base64UrlSafeNoPadding::encode_to_string(v).ok())
                .context("Missing P-256  Y value in params")?;

            let key = PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                alg: None,
                r#use: None,
                kid: None,
                crv: "P-256".to_owned(),
                x,
                y: Some(y),
            });

            Ok(key)
        })()
        .map_err(|err| {
            FormatterError::Failed(format!("Cannot build P-256 public key from CoseKey: {err}"))
        }),

        coset::RegisteredLabel::Assigned(iana::KeyType::OKP) => (|| -> anyhow::Result<_> {
            let _crv = get_param_value(Label::Int(iana::Ec2KeyParameter::Crv.to_i64()))
                .and_then(|v| v.as_integer())
                .filter(|v| v == &iana::EllipticCurve::Ed25519.to_i64().into())
                .context("Missing Ed25519 curve in params")?;

            let x = get_param_value(Label::Int(iana::Ec2KeyParameter::X.to_i64()))
                .and_then(|v| v.as_bytes())
                .and_then(|v| Base64UrlSafeNoPadding::encode_to_string(v).ok())
                .context("Missing Ed25519 X value in params")?;

            let key = PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                alg: None,
                r#use: None,
                kid: None,
                crv: "Ed25519".to_owned(),
                x,
                y: None,
            });

            Ok(key)
        })()
        .map_err(|err| {
            FormatterError::Failed(format!(
                "Cannot build Ed25519 public key from CoseKey: {err}"
            ))
        }),
        other => Err(FormatterError::Failed(format!(
            "CoseKey contains invalid kty `{other:?}`, only EC2 and OKP keys are supported"
        ))),
    }
}
