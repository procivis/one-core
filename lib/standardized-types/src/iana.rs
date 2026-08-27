//! Values from IANA registries.

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

/// "Named Information Hash Algorithm" registry.
///
/// <https://www.iana.org/assignments/named-information/named-information.xhtml>
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Display, EnumString)]
pub enum HashAlgorithm {
    #[serde(rename = "sha-256")]
    #[strum(to_string = "sha-256")]
    Sha256,
    #[serde(rename = "sha-384")]
    #[strum(to_string = "sha-384")]
    Sha384,
    #[serde(rename = "sha-512")]
    #[strum(to_string = "sha-512")]
    Sha512,
}

/// "JSON Web Signature and Encryption Algorithms" registry, established by RFC 7518.
///
/// <https://www.iana.org/assignments/jose/jose.xhtml>
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Display)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum EncryptionAlgorithm {
    A128GCM,
    // AES GCM using 256-bit key
    A256GCM,
    #[serde(rename = "A128CBC-HS256")]
    #[strum(to_string = "A128CBC-HS256")]
    A128CBCHS256,
    #[serde(rename = "A256CBC-HS512")]
    #[strum(to_string = "A256CBC-HS512")]
    A256CBCHS512,
}

/// Algorithm to derive / encrypt / select the encryption key
/// https://datatracker.ietf.org/doc/html/rfc7518#section-4.1
#[derive(Clone, Copy, Serialize, Deserialize, Debug, Eq, PartialEq, Display)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum EncryptionKeyManagementAlgorithm {
    // Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
    #[serde(rename = "ECDH-ES")]
    #[strum(serialize = "ECDH-ES")]
    EcdhEs,
}
