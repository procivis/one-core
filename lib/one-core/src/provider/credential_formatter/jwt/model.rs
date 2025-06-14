use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as, skip_serializing_none};
use time::OffsetDateTime;

use crate::service::key::dto::PublicKeyJwkDTO;

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTHeader {
    #[serde(rename = "alg")]
    pub algorithm: String,

    #[serde(rename = "kid", default)]
    pub key_id: Option<String>,

    #[serde(rename = "typ", default)]
    pub r#type: Option<String>,

    #[serde(rename = "jwk", default)]
    pub jwk: Option<PublicKeyJwkDTO>,

    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-verifier-attestation-jwt
    #[serde(rename = "jwt", default)]
    pub jwt: Option<String>,

    // https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6
    #[serde(rename = "x5c", default)]
    pub x5c: Option<Vec<String>>,
}

#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JWTPayload<CustomPayload> {
    #[serde(rename = "iat", default, with = "crate::util::timestamp::option")]
    pub issued_at: Option<OffsetDateTime>,

    #[serde(rename = "exp", default, with = "crate::util::timestamp::option")]
    pub expires_at: Option<OffsetDateTime>,

    #[serde(rename = "nbf", default, with = "crate::util::timestamp::option")]
    pub invalid_before: Option<OffsetDateTime>,

    #[serde(rename = "iss", default)]
    pub issuer: Option<String>,

    #[serde(rename = "sub", default)]
    pub subject: Option<String>,

    /// <https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3>
    #[serde(rename = "aud", default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub audience: Option<Vec<String>>,

    #[serde(rename = "jti", default)]
    pub jwt_id: Option<String>,

    /// <https://www.rfc-editor.org/rfc/rfc7800.html#section-3>
    #[serde(rename = "cnf", default)]
    pub proof_of_possession_key: Option<ProofOfPossessionKey>,

    #[serde(flatten)]
    pub custom: CustomPayload,
}

#[derive(Debug)]
pub struct DecomposedToken<Payload> {
    pub header: JWTHeader,
    pub payload: JWTPayload<Payload>,
    pub signature: Vec<u8>,
    pub unverified_jwt: String,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ProofOfPossessionKey {
    #[serde(rename = "kid", default)]
    pub key_id: Option<String>,

    #[serde(flatten)]
    pub jwk: ProofOfPossessionJwk,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum ProofOfPossessionJwk {
    Jwk {
        jwk: PublicKeyJwkDTO,
    },
    /// Swiyu SD-JWT is incorrectly formatting the `cnf` claim
    Swiyu(PublicKeyJwkDTO),
}

impl ProofOfPossessionJwk {
    pub fn jwk(&self) -> &PublicKeyJwkDTO {
        match self {
            ProofOfPossessionJwk::Jwk { jwk } => jwk,
            ProofOfPossessionJwk::Swiyu(jwk) => jwk,
        }
    }
}
