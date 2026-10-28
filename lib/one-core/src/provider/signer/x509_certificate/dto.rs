use one_dto_mapper::{From, Into, convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, serde_as};
use shared_types::RevocationMethodId;
use time::Duration;

use crate::proto::csr_creator::CsrRequestSubject;
use crate::service::identifier::dto::{
    CreateSelfSignedCertificateAuthorityContentRequestDTO,
    CreateSelfSignedCertificateAuthorityIssuerAlternativeNameRequest,
    CreateSelfSignedCertificateAuthorityIssuerAlternativeNameType,
};
use crate::service::key::dto::KeyGenerateCSRRequestSubjectDTO;

/// Configuration of an `X509_CERTIFICATE` signer, read from the signer's
/// `params`.
#[serde_as]
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    /// Signer-specific settings for the certificates this signer issues.
    pub payload: PayloadParams,
    #[serde_as(as = "DurationSeconds<i64>")]
    /// Maximum validity period of certificates issued by this signer.
    /// Also applied when a request sets no `validityEnd`.
    pub max_validity_duration_seconds: Duration,
    /// Revocation method for issued certificates. Must reference an
    /// enabled revocation method of type `CRL`, or initialization
    /// fails.
    pub revocation_method: Option<RevocationMethodId>,
}

/// `payload` settings of an `X509_CERTIFICATE` signer.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadParams {
    /// Allow issuing CA certificates. Defaults to `false`.
    ///
    /// When `true`, a CSR requesting the `keyCertSign` key usage
    /// produces a CA certificate, and the signer can create self-signed
    /// certificate authorities. When `false`, such CSRs are rejected
    /// and the signer issues only leaf certificates.
    #[serde(default)]
    pub allow_ca_signing: bool,
    /// Path length constraint set on CA certificates issued by this
    /// signer, including self-signed certificate authorities: the maximum
    /// number of CA certificates allowed below them in a chain. When
    /// unset, CA certificates are unconstrained.
    pub path_len_constraint: Option<u8>,
    /// Hash algorithm used to derive the subject key identifier of issued
    /// certificates. When set, leaf certificates also carry a basic
    /// constraints extension marking them as not a CA, and a subject key
    /// identifier. When unset, leaf certificates have no subject key
    /// identifier.
    ///
    /// ISO 18013-5 mdoc certificates use `sha-1`.
    pub key_id_derivation: Option<KeyIdDerivation>,
}

/// Hash algorithm for deriving key identifiers. Values follow the
/// IANA Named Information Hash Algorithm Registry:
/// <https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg>
#[derive(Debug, Clone, Deserialize)]
pub enum KeyIdDerivation {
    #[serde(rename = "sha-1")]
    Sha1,
    #[serde(rename = "sha-256")]
    Sha256,
    #[serde(rename = "sha-384")]
    Sha384,
    #[serde(rename = "sha-512")]
    Sha512,
}

/// Request data for an `X509_CERTIFICATE` signer, deserialized from the
/// `data` field of a signature request. Externally tagged:
/// `{"csr": "<PEM>"}` or `{"selfSigned": {...}}`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum RequestData {
    /// Sign a CSR in PEM format with a certificate authority identifier.
    /// The subject is copied from the CSR; extensions are copied only if
    /// allowed, and any other extension rejects the request.
    Csr(String),
    /// Create a self-signed certificate authority with a key issuer.
    /// Requires `allowCaSigning`.
    ///
    /// Not reachable from the signature API, which only accepts identifier
    /// issuers. Used internally when creating a self-signed certificate
    /// authority through the identifiers API.
    SelfSigned(SelfSignedRequest),
}

/// Content of a self-signed certificate authority. The certificate is
/// issued with the `keyCertSign` and `cRLSign` key usages.
#[derive(Debug, Serialize, Deserialize, From)]
#[from(CreateSelfSignedCertificateAuthorityContentRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SelfSignedRequest {
    /// Subject distinguished name of the certificate authority.
    pub subject: SubjectRequest,
    /// Optional issuer alternative name. Copied into certificates this
    /// certificate authority issues.
    #[from(with_fn = convert_inner)]
    pub issuer_alternative_name: Option<IssuerAlternativeNameRequest>,
}

/// Subject distinguished name attributes. Each attribute is optional;
/// set at least one. Shared with CSR generation.
#[derive(Debug, Clone, Serialize, Deserialize, From, Into)]
#[into(CsrRequestSubject)]
#[from(KeyGenerateCSRRequestSubjectDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubjectRequest {
    /// Country (`C`), as a two-letter country code.
    pub country_name: Option<String>,
    /// Common name (`CN`).
    pub common_name: Option<String>,
    /// State or province (`ST`).
    pub state_or_province_name: Option<String>,
    /// Organization (`O`).
    pub organisation_name: Option<String>,
    /// Locality (`L`).
    pub locality_name: Option<String>,
    /// Serial number (`serialNumber`) attribute of the subject. Not the
    /// certificate serial number.
    pub serial_number: Option<String>,
}

/// Issuer alternative name of a certificate authority.
#[derive(Debug, Serialize, Deserialize, From)]
#[from(CreateSelfSignedCertificateAuthorityIssuerAlternativeNameRequest)]
#[serde(rename_all = "camelCase")]
pub struct IssuerAlternativeNameRequest {
    /// Kind of name: an email address or a URI.
    pub r#type: IssuerAlternativeNameType,
    /// The email address or URI.
    pub name: String,
}

/// Kind of issuer alternative name.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, From)]
#[from(CreateSelfSignedCertificateAuthorityIssuerAlternativeNameType)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IssuerAlternativeNameType {
    /// Email address. Serialized as `EMAIL`.
    Email,
    /// URI. Serialized as `URI`.
    Uri,
}
