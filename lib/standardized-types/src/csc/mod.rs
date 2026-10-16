//! Cloud Signature Consortium (CSC) API v2.

pub mod data_model;
pub mod transaction_data;

use one_dto_mapper::Into;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use strum::{Display, IntoEnumIterator};

pub enum SignatureType {
    Json(String),
    PAdES(String),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Display)]
pub enum SignatureQualifier {
    #[serde(rename = "eu_eidas_aes")]
    #[strum(to_string = "eu_eidas_aes")]
    EuEidasAes,
    #[default]
    #[serde(rename = "eu_eidas_qes")]
    #[strum(to_string = "eu_eidas_qes")]
    EuEidasQes,
    #[serde(rename = "eu_eidas_aeseal")]
    #[strum(to_string = "eu_eidas_aeseal")]
    EuEidasAesEal,
    #[serde(rename = "eu_eidas_qeseal")]
    #[strum(to_string = "eu_eidas_qeseal")]
    EuEidasQesEal,
    #[serde(rename = "eu_eidas_aesqc")]
    #[strum(to_string = "eu_eidas_aesqc")]
    EuEidasAesQc,
    #[serde(rename = "eu_eidas_aesealqc")]
    #[strum(to_string = "eu_eidas_aesealqc")]
    EuEidasAesEalQc,
    #[serde(rename = "za_ecta_aes")]
    #[strum(to_string = "za_ecta_aes")]
    ZaEctaAes,
    #[serde(rename = "za_ecta_oes")]
    #[strum(to_string = "za_ecta_oes")]
    ZaEctaOes,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Display)]
pub enum SignatureFormat {
    #[serde(rename = "C")]
    #[strum(to_string = "C")]
    CAdES,
    #[serde(rename = "X")]
    #[strum(to_string = "X")]
    XAdES,
    #[default]
    #[serde(rename = "P")]
    #[strum(to_string = "P")]
    PAdES,
    #[serde(rename = "J")]
    #[strum(to_string = "J")]
    JAdES,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Display)]
pub enum ConformanceLevel {
    #[default]
    #[serde(rename = "Ades-B-B")]
    #[strum(to_string = "Ades-B-B")]
    AdESBB,
    #[serde(rename = "Ades-B-T")]
    #[strum(to_string = "Ades-B-T")]
    AdESBT,
    #[serde(rename = "Ades-B-LT")]
    #[strum(to_string = "Ades-B-LT")]
    AdESBLT,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, strum::EnumIter, Into)]
#[into(crate::iana::HashAlgorithm)]
pub enum HashAlgorithm {
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub const fn oid(self) -> &'static str {
        match self {
            Self::Sha256 => "2.16.840.1.101.3.4.2.1",
            Self::Sha384 => "2.16.840.1.101.3.4.2.2",
            Self::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    pub fn from_oid(oid: &str) -> Option<Self> {
        Self::iter().find(|alg| alg.oid() == oid)
    }

    pub const fn output_length(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

impl Serialize for HashAlgorithm {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.oid())
    }
}

impl<'de> Deserialize<'de> for HashAlgorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let oid = String::deserialize(deserializer)?;
        Self::from_oid(&oid)
            .ok_or_else(|| D::Error::custom(format!("unknown hashAlgorithmOID `{oid}`")))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, strum::EnumIter)]
pub enum SignatureAlgorithm {
    Rsa,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
}

impl SignatureAlgorithm {
    pub const fn oid(self) -> &'static str {
        match self {
            Self::Rsa => "1.2.840.113549.1.1.1",
            Self::EcdsaSha256 => "1.2.840.10045.4.3.2",
            Self::EcdsaSha384 => "1.2.840.10045.4.3.3",
            Self::EcdsaSha512 => "1.2.840.10045.4.3.4",
        }
    }

    pub fn from_oid(oid: &str) -> Option<Self> {
        Self::iter().find(|alg| alg.oid() == oid)
    }

    pub const fn digest(self) -> Option<HashAlgorithm> {
        match self {
            Self::Rsa => None,
            Self::EcdsaSha256 => Some(HashAlgorithm::Sha256),
            Self::EcdsaSha384 => Some(HashAlgorithm::Sha384),
            Self::EcdsaSha512 => Some(HashAlgorithm::Sha512),
        }
    }
}

impl Serialize for SignatureAlgorithm {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.oid())
    }
}

impl<'de> Deserialize<'de> for SignatureAlgorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let oid = String::deserialize(deserializer)?;
        Self::from_oid(&oid)
            .ok_or_else(|| D::Error::custom(format!("unknown signAlgo OID `{oid}`")))
    }
}

#[derive(Serialize)]
pub struct AuthorizeRequest<'a> {
    pub response_type: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    #[serde(rename = "signatureQualifier")]
    pub signature_qualifier: SignatureQualifier,
    #[serde(rename = "numSignatures")]
    pub num_signatures: u32,
    pub hashes: &'a str,
    #[serde(rename = "hashAlgorithmOID")]
    pub hash_algorithm: HashAlgorithm,
    pub account_token: &'a str,
}

#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
}

#[derive(Serialize)]
pub struct CredentialInfoRequest {
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    pub certificates: String,
    #[serde(rename = "certInfo")]
    pub cert_info: bool,
}

#[derive(Deserialize)]
pub struct CredentialInfoResponse {
    pub key: CredentialKey,
    pub cert: Option<CredentialCertificate>,
}

impl CredentialInfoResponse {
    pub fn signing_algorithm(&self, preferred_hash: HashAlgorithm) -> Option<SignatureAlgorithm> {
        let supported: Vec<SignatureAlgorithm> = self
            .key
            .algo
            .iter()
            .filter_map(|oid| SignatureAlgorithm::from_oid(oid))
            .collect();

        supported
            .iter()
            .copied()
            .find(|alg| alg.digest() == Some(preferred_hash))
            .or_else(|| supported.iter().copied().find(|alg| alg.digest().is_none()))
            .or_else(|| supported.first().copied())
    }
}

#[derive(Serialize)]
pub struct CredentialListRequest {
    #[serde(rename = "credentialInfo")]
    pub credential_info: bool,
    pub certificates: String,
    #[serde(rename = "certInfo")]
    pub cert_info: bool,
}

#[derive(Deserialize)]
pub struct CredentialListResponse {
    #[serde(rename = "credentialInfos", default)]
    pub credential_infos: Vec<CredentialListInfo>,
}

#[derive(Deserialize)]
pub struct CredentialListInfo {
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    #[serde(flatten)]
    pub info: CredentialInfoResponse,
}

#[derive(Deserialize)]
pub struct CredentialKey {
    pub algo: Vec<String>,
}

/// RFC 9396 authorization details of type `credential` (CSC v2)
#[derive(Serialize)]
pub struct CredentialAuthorizationDetails {
    pub r#type: String,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    #[serde(rename = "hashAlgorithmOID")]
    pub hash_algorithm: HashAlgorithm,
    #[serde(rename = "documentDigests")]
    pub document_digests: Vec<DocumentDigest>,
}

#[derive(Serialize)]
pub struct DocumentDigest {
    pub hash: String,
    pub label: String,
}

#[derive(Deserialize)]
pub struct CredentialCertificate {
    pub certificates: Vec<String>,
}

#[derive(Serialize)]
pub struct SignDocRequest {
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    #[serde(rename = "operationMode")]
    pub operation_mode: OperationMode,
    #[serde(rename = "returnValidationInfo")]
    pub return_validation_info: bool,
    pub documents: Vec<SignDocDocument>,
}

#[derive(Serialize)]
pub struct SignDocDocument {
    pub document: String,
    #[serde(rename = "signAlgo")]
    pub sign_algo: String,
    pub signature_format: SignatureFormat,
    pub conformance_level: ConformanceLevel,
}

#[derive(Deserialize)]
pub struct SignDocResponse {
    #[serde(rename = "DocumentWithSignatures", alias = "DocumentWithSignature")]
    pub document_with_signatures: Vec<String>,
}

#[derive(Serialize)]
pub struct SignHashRequest {
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    #[serde(rename = "operationMode")]
    pub operation_mode: OperationMode,
    pub hashes: Vec<String>,
    #[serde(rename = "signAlgo")]
    pub sign_algo: SignatureAlgorithm,
    #[serde(rename = "hashAlgorithmOID")]
    pub hash_algorithm: HashAlgorithm,
}

#[derive(Deserialize)]
pub struct SignHashResponse {
    pub signatures: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Display)]
pub enum OperationMode {
    #[default]
    #[serde(rename = "S")]
    #[strum(to_string = "S")]
    Synchronous,
    #[serde(rename = "A")]
    #[strum(to_string = "A")]
    Asynchronous,
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;
    use strum::IntoEnumIterator;

    use super::*;

    #[test]
    fn hash_algorithm_oids_are_canonical_consistent_and_strict() {
        assert_eq!(HashAlgorithm::Sha256.oid(), "2.16.840.1.101.3.4.2.1");
        assert_eq!(HashAlgorithm::Sha384.oid(), "2.16.840.1.101.3.4.2.2");
        assert_eq!(HashAlgorithm::Sha512.oid(), "2.16.840.1.101.3.4.2.3");

        for alg in HashAlgorithm::iter() {
            assert_eq!(json!(alg), json!(alg.oid()));
            assert_eq!(HashAlgorithm::from_oid(alg.oid()), Some(alg));
            assert_eq!(
                serde_json::from_value::<HashAlgorithm>(json!(alg.oid())).unwrap(),
                alg
            );
        }

        assert_eq!(HashAlgorithm::from_oid("1.3.14.3.2.26"), None);
        assert!(serde_json::from_value::<HashAlgorithm>(json!("1.3.14.3.2.26")).is_err());
    }

    #[test]
    fn signature_algorithm_oids_are_canonical_consistent_and_strict() {
        assert_eq!(SignatureAlgorithm::Rsa.oid(), "1.2.840.113549.1.1.1");
        assert_eq!(SignatureAlgorithm::EcdsaSha256.oid(), "1.2.840.10045.4.3.2");
        assert_eq!(SignatureAlgorithm::EcdsaSha384.oid(), "1.2.840.10045.4.3.3");
        assert_eq!(SignatureAlgorithm::EcdsaSha512.oid(), "1.2.840.10045.4.3.4");

        for alg in SignatureAlgorithm::iter() {
            assert_eq!(json!(alg), json!(alg.oid()));
            assert_eq!(SignatureAlgorithm::from_oid(alg.oid()), Some(alg));
            assert_eq!(
                serde_json::from_value::<SignatureAlgorithm>(json!(alg.oid())).unwrap(),
                alg
            );
        }

        assert_eq!(SignatureAlgorithm::from_oid("1.2.3.4"), None);
        assert!(serde_json::from_value::<SignatureAlgorithm>(json!("1.2.3.4")).is_err());
    }

    #[test]
    fn ecdsa_signature_algorithms_pin_their_digest() {
        assert_eq!(SignatureAlgorithm::Rsa.digest(), None);
        assert_eq!(
            SignatureAlgorithm::EcdsaSha256.digest(),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            SignatureAlgorithm::EcdsaSha384.digest(),
            Some(HashAlgorithm::Sha384)
        );
        assert_eq!(
            SignatureAlgorithm::EcdsaSha512.digest(),
            Some(HashAlgorithm::Sha512)
        );

        for alg in SignatureAlgorithm::iter() {
            if let Some(digest) = alg.digest() {
                assert_eq!(HashAlgorithm::from_oid(digest.oid()), Some(digest));
            }
        }
    }

    #[test]
    fn conformance_level_serialization() {
        assert_eq!(json!(ConformanceLevel::AdESBB), json!("Ades-B-B"));
        assert_eq!(json!(ConformanceLevel::AdESBT), json!("Ades-B-T"));
        assert_eq!(json!(ConformanceLevel::AdESBLT), json!("Ades-B-LT"));
    }

    #[test]
    fn operation_mode_serialization() {
        assert_eq!(json!(OperationMode::Synchronous), json!("S"));
        assert_eq!(json!(OperationMode::Asynchronous), json!("A"));
        assert_eq!(OperationMode::default(), OperationMode::Synchronous);
    }

    #[test]
    fn hash_algorithm_output_lengths_match_the_digest_size() {
        assert_eq!(HashAlgorithm::Sha256.output_length(), 32);
        assert_eq!(HashAlgorithm::Sha384.output_length(), 48);
        assert_eq!(HashAlgorithm::Sha512.output_length(), 64);
    }

    fn info_with_algos(algos: &[&str]) -> CredentialInfoResponse {
        CredentialInfoResponse {
            key: CredentialKey {
                algo: algos.iter().map(|s| s.to_string()).collect(),
            },
            cert: None,
        }
    }

    #[test]
    fn signing_algorithm_prefers_digest_matching_the_configured_hash() {
        let chosen =
            info_with_algos(&["1.2.840.10045.4.3.2"]).signing_algorithm(HashAlgorithm::Sha256);
        assert_eq!(chosen, Some(SignatureAlgorithm::EcdsaSha256));
    }

    #[test]
    fn signing_algorithm_picks_the_ecdsa_variant_matching_the_hash() {
        let chosen = info_with_algos(&["1.2.840.10045.4.3.2", "1.2.840.10045.4.3.4"])
            .signing_algorithm(HashAlgorithm::Sha512);
        assert_eq!(chosen, Some(SignatureAlgorithm::EcdsaSha512));
    }

    #[test]
    fn signing_algorithm_falls_back_to_rsa_when_no_digest_matches() {
        let chosen =
            info_with_algos(&["1.2.840.113549.1.1.1"]).signing_algorithm(HashAlgorithm::Sha256);
        assert_eq!(chosen, Some(SignatureAlgorithm::Rsa));
    }

    #[test]
    fn signing_algorithm_ignores_unmodeled_oids() {
        let chosen = info_with_algos(&["1.3.6.1.4.1.99999", "1.2.840.10045.4.3.3"])
            .signing_algorithm(HashAlgorithm::Sha384);
        assert_eq!(chosen, Some(SignatureAlgorithm::EcdsaSha384));
    }

    #[test]
    fn signing_algorithm_returns_none_when_nothing_recognized() {
        let chosen =
            info_with_algos(&["1.3.6.1.4.1.99999"]).signing_algorithm(HashAlgorithm::Sha256);
        assert_eq!(chosen, None);
    }
}
