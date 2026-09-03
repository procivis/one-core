use std::collections::HashMap;

use ciborium::Value;
use ciborium::tag::Required;
use coset::iana::EnumI64;
use coset::{AsCborValue, Label, RegisteredLabelWithPrivate, iana};
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use indexmap::IndexMap;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer, de, ser};
use serde_with::{DefaultOnError, serde_as, skip_serializing_none};
use standardized_types::jwk::{PublicJwk, PublicJwkEc};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::der_chain_into_pem_chain;
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, EnforceKeyUsage, ParsedCertificate,
};
use crate::proto::cose::CoseSign1;
use crate::proto::http_client::HttpClient;
use crate::provider::credential_formatter::common::resolve_x5u;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CertificateDetails, CredentialStatus, X5References,
};

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
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MobileSecurityObject {
    pub version: MDLVersion<1, 0>,
    pub digest_algorithm: DigestAlgorithm,
    pub value_digests: ValueDigests,
    pub device_key_info: DeviceKeyInfo,
    pub doc_type: String,
    pub validity_info: ValidityInfo,
    #[serde_as(as = "DefaultOnError")]
    #[serde(default)]
    pub status: Option<Status>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    StatusList(StatusList),
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StatusList {
    #[serde(rename = "idx")]
    pub index: usize,
    pub uri: String,
    pub certificate: Option<Bstr>,
}

/// Part of CWT-encoded status list, under payload field 65533
/// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-12#name-status-list-in-cbor-format
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusListEncoded {
    pub bits: u8,
    #[serde(rename = "lst")]
    pub list: Bstr,
    pub aggregation_uri: Option<String>,
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
    type Error = FormatterError;

    fn try_from(value: ciborium::Value) -> Result<Self, Self::Error> {
        Ok(Self(value.into_bytes().map_err(|_| {
            FormatterError::CouldNotExtractCredentials("Not a Bstr".to_string())
        })?))
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

/// Extracts the issuer signing certificate referenced by the COSE headers. The
/// certificate may be carried inline via `x5chain` or referenced via `x5u` (both
/// IETF RFC 9360); ETSI TS 119 472-1 (QEAA-6.6.2-02) allows QEAA/PuB-EAA to reference
/// it by `x5u` + `x5t` only, so the chain is fetched from `x5u` when `x5chain` is absent.
pub(crate) async fn extract_certificate_from_x5chain_header(
    certificate_validator: &dyn CertificateValidator,
    http_client: &dyn HttpClient,
    CoseSign1(cose_sign1): &CoseSign1,
    verify: bool,
) -> Result<CertificateDetails, FormatterError> {
    let x5chain = cose_header(cose_sign1, iana::HeaderParameter::X5Chain);
    let x5u = cose_header(cose_sign1, iana::HeaderParameter::X5U);
    let x5t = cose_header(cose_sign1, iana::HeaderParameter::X5T);

    let chain = match x5chain {
        Some(Value::Bytes(cert)) => der_chain_into_pem_chain(vec![cert.clone()]),
        Some(Value::Array(certs)) => der_chain_into_pem_chain(
            certs
                .iter()
                .flat_map(|cert| cert.as_bytes().into_iter().cloned())
                .collect(),
        ),
        Some(other) => {
            return Err(FormatterError::CouldNotExtractCredentials(format!(
                "Unexpected value in x5chain header: {other:?}"
            )));
        }
        None => {
            let url =
                x5u.and_then(Value::as_text)
                    .ok_or(FormatterError::CouldNotExtractCredentials(
                        "Missing x5chain/x5u header".to_string(),
                    ))?;
            resolve_x5u(url, http_client).await?
        }
    };

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
        .error_while("parsing PEM chain")?;

    // `x5t` (RFC 9360 COSE_CertHash) binds the referenced certificate to the signature;
    // enforce it only when verifying, alongside the other integrity checks. When present
    // it must match the resolved leaf, whether the certificate was inlined via `x5chain`
    // or fetched via `x5u`.
    if verify && let Some(x5t) = x5t {
        verify_x5t(x5t, &attributes.fingerprint)?;
    }

    Ok(CertificateDetails {
        chain,
        fingerprint: attributes.fingerprint,
        expiry: attributes.not_after,
        subject_common_name,
        x5_references: X5References {
            x5c: x5chain.is_some(),
            x5u: x5u.is_some(),
            x5t_s256: x5t.is_some(),
        },
    })
}

pub(crate) fn cose_header(
    cose_sign1: &coset::CoseSign1,
    param: iana::HeaderParameter,
) -> Option<&Value> {
    let label = Label::Int(param.to_i64());
    cose_sign1
        .protected
        .header
        .rest
        .iter()
        .chain(cose_sign1.unprotected.rest.iter())
        .find(|(l, _)| l == &label)
        .map(|(_, value)| value)
}

/// Verifies the `x5t` header (RFC 9360 `COSE_CertHash` = `[hashAlg, hashValue]`) against
/// the resolved leaf. ETSI TS 119 472-1 QEAA-6.6.2-03 requires the digest to be SHA-256.
fn verify_x5t(x5t: &Value, leaf_fingerprint: &str) -> Result<(), FormatterError> {
    let Some([alg, hash]) = x5t.as_array().map(Vec::as_slice) else {
        return Err(FormatterError::CouldNotExtractCredentials(
            "x5t is not a COSE_CertHash [hashAlg, hashValue]".to_string(),
        ));
    };

    if alg.as_integer().map(i128::from) != Some(iana::Algorithm::SHA_256.to_i64() as i128) {
        return Err(FormatterError::CouldNotExtractCredentials(
            "x5t digest algorithm must be SHA-256".to_string(),
        ));
    }

    let hash = hash
        .as_bytes()
        .ok_or(FormatterError::CouldNotExtractCredentials(
            "x5t hash value must be a byte string".to_string(),
        ))?;
    let expected = hex::decode(leaf_fingerprint).map_err(|e| {
        FormatterError::CouldNotExtractCredentials(format!("invalid certificate fingerprint: {e}"))
    })?;

    if hash != &expected {
        return Err(FormatterError::CouldNotExtractCredentials(
            "x5t does not match the referenced certificate".to_string(),
        ));
    }
    Ok(())
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

pub(crate) fn build_algorithm_header_value(
    algorithm: KeyAlgorithmType,
) -> Result<iana::Algorithm, FormatterError> {
    let algorithm = match algorithm {
        KeyAlgorithmType::Ecdsa => iana::Algorithm::ES256,
        KeyAlgorithmType::Eddsa => iana::Algorithm::EdDSA,
        _ => {
            return Err(FormatterError::CouldNotFormat(format!(
                "Failed mapping algorithm `{algorithm}` to name compatible with allowed COSE Algorithms"
            )));
        }
    };
    Ok(algorithm)
}

pub(crate) fn try_extract_mobile_security_object(
    CoseSign1(cose_sign1): &CoseSign1,
) -> Result<MobileSecurityObject, FormatterError> {
    let Some(payload) = &cose_sign1.payload else {
        return Err(FormatterError::CouldNotExtractCredentials(
            "IssuerAuth doesn't contain payload".to_owned(),
        ));
    };

    let mso: EmbeddedCbor<MobileSecurityObject> = ciborium::from_reader(&payload[..])?;

    Ok(mso.into_inner())
}

pub(crate) fn try_extract_holder_public_key(
    CoseSign1(issuer_auth): &CoseSign1,
) -> Result<PublicJwk, FormatterError> {
    let mso = issuer_auth.payload.as_ref().ok_or_else(|| {
        FormatterError::CouldNotExtractCredentials("Issuer auth missing mso object".to_owned())
    })?;

    let mso: EmbeddedCbor<MobileSecurityObject> = ciborium::from_reader(&mso[..])?;

    let DeviceKey(cose_key) = mso.into_inner().device_key_info.device_key;

    let get_param_value = |key| {
        cose_key
            .params
            .iter()
            .find_map(|(k, v)| (k == &key).then_some(v))
            .ok_or_else(|| {
                FormatterError::CouldNotExtractCredentials(format!(
                    "Missing CoseKey param: {key:?}"
                ))
            })
    };

    Ok(match cose_key.kty {
        coset::RegisteredLabel::Assigned(iana::KeyType::EC2) => {
            let crv = get_param_value(Label::Int(iana::Ec2KeyParameter::Crv.to_i64()))?
                .as_integer()
                .ok_or(FormatterError::JsonMapping("Invalid EC2 CRV".to_string()))?;
            if crv != iana::EllipticCurve::P_256.to_i64().into() {
                return Err(FormatterError::CouldNotExtractCredentials(format!(
                    "Unsupported EC2 CRV: {crv:?}"
                )));
            }

            let x = get_param_value(Label::Int(iana::Ec2KeyParameter::X.to_i64()))?
                .as_bytes()
                .ok_or(FormatterError::JsonMapping("Invalid X".to_string()))?;
            let x = Base64UrlSafeNoPadding::encode_to_string(x)?;

            let y = get_param_value(Label::Int(iana::Ec2KeyParameter::Y.to_i64()))?
                .as_bytes()
                .ok_or(FormatterError::JsonMapping("Invalid Y".to_string()))?;
            let y = Base64UrlSafeNoPadding::encode_to_string(y)?;

            PublicJwk::Ec(PublicJwkEc {
                alg: None,
                r#use: None,
                kid: None,
                crv: "P-256".to_owned(),
                x,
                y: Some(y),
            })
        }

        coset::RegisteredLabel::Assigned(iana::KeyType::OKP) => {
            let crv = get_param_value(Label::Int(iana::OkpKeyParameter::Crv.to_i64()))?
                .as_integer()
                .ok_or(FormatterError::JsonMapping("Invalid OKP CRV".to_string()))?;
            if crv != iana::EllipticCurve::Ed25519.to_i64().into() {
                return Err(FormatterError::CouldNotExtractCredentials(format!(
                    "Unsupported OKP CRV: {crv:?}"
                )));
            }

            let x = get_param_value(Label::Int(iana::OkpKeyParameter::X.to_i64()))?
                .as_bytes()
                .ok_or(FormatterError::JsonMapping("Invalid X".to_string()))?;
            let x = Base64UrlSafeNoPadding::encode_to_string(x)?;

            PublicJwk::Okp(PublicJwkEc {
                alg: None,
                r#use: None,
                kid: None,
                crv: "Ed25519".to_owned(),
                x,
                y: None,
            })
        }

        other => {
            return Err(FormatterError::CouldNotExtractCredentials(format!(
                "CoseKey contains invalid kty `{other:?}`, only EC2 and OKP keys are supported"
            )));
        }
    })
}

pub(super) fn create_status(
    credential_status: Vec<CredentialStatus>,
) -> Result<Option<Status>, FormatterError> {
    use crate::provider::revocation::token_status_list::{INDEX_KEY, URI_KEY};

    let Some(status) = credential_status.first() else {
        return Ok(None);
    };

    let uri = status
        .additional_fields
        .get(URI_KEY)
        .and_then(|url| url.as_str())
        .ok_or(FormatterError::CouldNotFormat(
            "Missing status list url".to_string(),
        ))?
        .to_string();

    let list_index = status
        .additional_fields
        .get(INDEX_KEY)
        .and_then(|index| index.as_str())
        .ok_or(FormatterError::CouldNotFormat(
            "Missing status list index".to_string(),
        ))?;
    let index = list_index
        .parse()
        .map_err(|_| FormatterError::CouldNotFormat("Invalid list index".to_string()))?;

    Ok(Some(Status::StatusList(StatusList {
        uri,
        index,
        certificate: None,
    })))
}

pub(super) fn parse_status(status: Option<Status>) -> Vec<CredentialStatus> {
    use crate::provider::revocation::token_status_list::{CERTIFICATE_KEY, INDEX_KEY, URI_KEY};

    match status {
        None => vec![],
        Some(Status::StatusList(value)) => {
            let mut additional_fields = HashMap::from([
                (URI_KEY.to_string(), serde_json::Value::String(value.uri)),
                (
                    INDEX_KEY.to_string(),
                    serde_json::Value::String(value.index.to_string()),
                ),
            ]);

            if let Some(certificate) = value.certificate {
                additional_fields.insert(
                    CERTIFICATE_KEY.to_string(),
                    serde_json::Value::String(der_chain_into_pem_chain(vec![certificate.0])),
                );
            }

            vec![CredentialStatus {
                id: None,
                r#type: "TokenStatusListEntry".to_string(),
                status_purpose: Some("revocation".to_string()),
                additional_fields,
            }]
        }
    }
}

/// Automatic parser of ISO mDL versions
///
/// Also checks for supported major version during deserialization
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MDLVersion<const MAJOR_SUPPORTED: usize, const MINOR_IMPLEMENTED: usize> {
    pub major: usize,
    pub minor: usize,
}

impl<const MAJOR_SUPPORTED: usize, const MINOR_IMPLEMENTED: usize> Default
    for MDLVersion<MAJOR_SUPPORTED, MINOR_IMPLEMENTED>
{
    fn default() -> Self {
        Self {
            major: MAJOR_SUPPORTED,
            minor: MINOR_IMPLEMENTED,
        }
    }
}

impl<const MAJOR_SUPPORTED: usize, const MINOR_IMPLEMENTED: usize> Serialize
    for MDLVersion<MAJOR_SUPPORTED, MINOR_IMPLEMENTED>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let version_str = format!("{}.{}", self.major, self.minor);
        version_str.serialize(serializer)
    }
}

impl<'de, const MAJOR_SUPPORTED: usize, const MINOR_IMPLEMENTED: usize> Deserialize<'de>
    for MDLVersion<MAJOR_SUPPORTED, MINOR_IMPLEMENTED>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let version = String::deserialize(deserializer)?;
        let (major, minor) = version
            .split_once('.')
            .ok_or(serde::de::Error::custom(format!(
                "expected version string, got: `{version}`"
            )))?;

        let major = major.parse().map_err(|_| {
            serde::de::Error::custom(format!("expected major version, got: `{major}`"))
        })?;
        let minor = minor.parse().map_err(|_| {
            serde::de::Error::custom(format!("expected minor version, got: `{minor}`"))
        })?;

        if major > MAJOR_SUPPORTED {
            return Err(serde::de::Error::custom(format!(
                "Unsupported MDL version: {version}"
            )));
        }

        Ok(Self { major, minor })
    }
}

#[cfg(test)]
mod tests {
    use ciborium::Value;
    use coset::iana::{self, EnumI64};

    use super::verify_x5t;

    fn cose_cert_hash(algorithm: i64, hash: Vec<u8>) -> Value {
        Value::Array(vec![Value::from(algorithm), Value::Bytes(hash)])
    }

    #[test]
    fn verify_x5t_accepts_matching_sha256_hash() {
        let fingerprint = "0102030405060708090a0b0c0d0e0f10";
        let x5t = cose_cert_hash(
            iana::Algorithm::SHA_256.to_i64(),
            hex::decode(fingerprint).unwrap(),
        );

        assert!(verify_x5t(&x5t, fingerprint).is_ok());
    }

    #[test]
    fn verify_x5t_rejects_mismatching_hash() {
        let fingerprint = "0102030405060708090a0b0c0d0e0f10";
        let x5t = cose_cert_hash(iana::Algorithm::SHA_256.to_i64(), vec![0xaa; 16]);

        assert!(verify_x5t(&x5t, fingerprint).is_err());
    }

    #[test]
    fn verify_x5t_rejects_non_sha256_algorithm() {
        let fingerprint = "0102030405060708090a0b0c0d0e0f10";
        let x5t = cose_cert_hash(
            iana::Algorithm::SHA_1.to_i64(),
            hex::decode(fingerprint).unwrap(),
        );

        assert!(verify_x5t(&x5t, fingerprint).is_err());
    }
}
