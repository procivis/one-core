//! W3C XML Digital Signature types.

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::qualifying_properties::QualifyingProperties;
use super::serde_bridge;

pub const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// Inclusive XML Canonicalization 1.0 (W3C REC-xml-c14n-20010315).
pub const INC_C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const XPATH_FILTER2: &str = "http://www.w3.org/2002/06/xmldsig-filter2";
pub const SHA256_DIGEST_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const SHA512_DIGEST_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

fn default_xmldsig_ns() -> String {
    XMLDSIG_NS.to_string()
}

// Only suites with a supported hasher are listed.
// ES384/RSA omitted: no SHA-384 hasher or RSA key type available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureSuite {
    ES256,
    EdDSA,
    RsaSha256,
}

impl SignatureSuite {
    pub fn signature_alg_uri(&self) -> &'static str {
        match self {
            Self::ES256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            Self::EdDSA => "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519",
            Self::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        }
    }

    pub fn try_from_sig_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => Some(Self::ES256),
            "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519" => Some(Self::EdDSA),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Some(Self::RsaSha256),
            _ => None,
        }
    }

    pub fn hash_alg_uri(&self) -> &'static str {
        match self {
            Self::ES256 | Self::EdDSA | Self::RsaSha256 => SHA256_DIGEST_URI,
        }
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename = "ds:Signature")]
pub struct Signature {
    #[serde(rename = "@xmlns:ds", default = "default_xmldsig_ns")]
    pub xmlns_ds: String,
    #[serde(rename = "@Id")]
    pub id: Option<String>,
    #[serde(rename = "ds:SignedInfo", alias = "SignedInfo")]
    pub signed_info: SignedInfo,
    #[serde(rename = "ds:SignatureValue", alias = "SignatureValue")]
    pub signature_value: SignatureValue,
    #[serde(rename = "ds:KeyInfo", alias = "KeyInfo")]
    pub key_info: KeyInfo,
    #[serde(rename = "ds:Object", alias = "Object")]
    pub object: Object,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename = "ds:SignedInfo")]
pub struct SignedInfo {
    #[serde(rename = "@xmlns:ds", default = "default_xmldsig_ns")]
    pub xmlns_ds: String,
    #[serde(rename = "ds:CanonicalizationMethod", alias = "CanonicalizationMethod")]
    pub canonicalization_method: AlgorithmIdentifier,
    #[serde(rename = "ds:SignatureMethod", alias = "SignatureMethod")]
    pub signature_method: AlgorithmIdentifier,
    #[serde(rename = "ds:Reference", alias = "Reference")]
    pub references: Vec<Reference>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reference {
    #[serde(rename = "@Id")]
    pub id: Option<String>,
    #[serde(rename = "@URI")]
    pub uri: String,
    #[serde(rename = "@Type")]
    pub r#type: Option<String>,
    #[serde(rename = "ds:Transforms", alias = "Transforms", default)]
    pub transforms: Option<Transforms>,
    #[serde(rename = "ds:DigestMethod", alias = "DigestMethod")]
    pub digest_method: AlgorithmIdentifier,
    #[serde(rename = "ds:DigestValue", alias = "DigestValue")]
    pub digest_value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Transforms {
    #[serde(rename = "ds:Transform", alias = "Transform")]
    pub transforms: Vec<Transform>,
}

/// Supported `<ds:Transform>` algorithms (EN 319 132-1 §6.3 (f,g)).
/// Unsupported transforms cause a deserialization error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "serde_bridge::TransformRaw",
    into = "serde_bridge::TransformRaw"
)]
pub enum Transform {
    EnvelopedSignature,
    ExcC14n,
    InclC14n,
    XPathFilter2(Vec<XPathFilter2Op>),
}

/// XPath Filter 2.0 set operation (W3C `xmldsig-filter2`).
#[derive(Debug, Clone, PartialEq)]
pub enum XPathFilter2Op {
    Subtract(String),
    Union(String),
    Intersect(String),
}

impl XPathFilter2Op {
    pub fn xpath(&self) -> &str {
        match self {
            Self::Subtract(x) | Self::Union(x) | Self::Intersect(x) => x,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlgorithmIdentifier {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureValue {
    #[serde(rename = "@Id")]
    pub id: Option<String>,
    #[serde(rename = "$text")]
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyInfo {
    #[serde(rename = "ds:X509Data", alias = "X509Data")]
    pub x509_data: Vec<X509Data>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct X509Data {
    #[serde(rename = "ds:X509Certificate", alias = "X509Certificate")]
    pub x509_certificates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Object {
    #[serde(rename = "xades:QualifyingProperties", alias = "QualifyingProperties")]
    pub qualifying_properties: QualifyingProperties,
}
