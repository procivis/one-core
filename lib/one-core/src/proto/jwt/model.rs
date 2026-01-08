use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as, skip_serializing_none};
use time::OffsetDateTime;

use crate::provider::credential_formatter::MetadataClaimSchema;
use crate::service::key::dto::PublicKeyJwkDTO;

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTHeader {
    // https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1
    #[serde(rename = "alg")]
    pub algorithm: String,

    // https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4
    #[serde(rename = "kid", default)]
    pub key_id: Option<String>,

    // https://www.rfc-editor.org/rfc/rfc7519.html#section-5.1
    // https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9
    #[serde(rename = "typ", default)]
    pub r#type: Option<String>,

    // https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.3
    #[serde(rename = "jwk", default)]
    pub jwk: Option<PublicKeyJwkDTO>,

    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-verifier-attestation-jwt
    #[serde(rename = "jwt", default)]
    pub jwt: Option<String>,

    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.1
    #[serde(rename = "key_attestation", default)]
    pub key_attestation: Option<String>,

    // https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6
    #[serde(rename = "x5c", default)]
    pub x5c: Option<Vec<String>>,
}

pub type JWTPayload<CustomPayload> = Payload<Option<String>, CustomPayload>;

/// <https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1>
#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Payload<Subject: SerdeSkippable, CustomPayload> {
    #[serde(rename = "iat", default, with = "crate::mapper::timestamp::option")]
    pub issued_at: Option<OffsetDateTime>,

    #[serde(rename = "exp", default, with = "crate::mapper::timestamp::option")]
    pub expires_at: Option<OffsetDateTime>,

    #[serde(rename = "nbf", default, with = "crate::mapper::timestamp::option")]
    pub invalid_before: Option<OffsetDateTime>,

    #[serde(rename = "iss", default)]
    pub issuer: Option<String>,

    // This is generic to account for ETSI wallet relying party registration certificate subject
    // (see ETSI TS 119 475, https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.01.01_60/ts_119475v010101p.pdf)
    // which is in violation of the JWT spec and defines the sub claim as an object.
    #[serde(rename = "sub", skip_serializing_if = "SerdeSkippable::skip")]
    pub subject: Subject,

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

pub trait SerdeSkippable {
    fn skip(&self) -> bool;
}
impl<T> SerdeSkippable for Option<T> {
    fn skip(&self) -> bool {
        self.is_none()
    }
}

pub type DecomposedJwt<CustomPayload> = DecomposedToken<Option<String>, CustomPayload>;

#[derive(Debug)]
pub struct DecomposedToken<Subject: SerdeSkippable, CustomPayload> {
    pub header: JWTHeader,
    pub payload: Payload<Subject, CustomPayload>,
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

pub(crate) fn jwt_metadata_claims() -> Vec<MetadataClaimSchema> {
    vec![
        // selected registered JWT claims
        // https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1
        MetadataClaimSchema {
            key: "iss".to_string(),
            data_type: "STRING".to_string(),
            array: false,
            required: false,
        },
        MetadataClaimSchema {
            key: "sub".to_string(),
            data_type: "STRING".to_string(),
            array: false,
            required: false,
        },
        MetadataClaimSchema {
            key: "aud".to_string(),
            data_type: "STRING".to_string(),
            array: true,
            required: false,
        },
        MetadataClaimSchema {
            key: "exp".to_string(),
            data_type: "NUMBER".to_string(),
            array: false,
            required: false,
        },
        MetadataClaimSchema {
            key: "nbf".to_string(),
            data_type: "NUMBER".to_string(),
            array: false,
            required: false,
        },
        MetadataClaimSchema {
            key: "iat".to_string(),
            data_type: "NUMBER".to_string(),
            array: false,
            required: false,
        },
        MetadataClaimSchema {
            key: "jti".to_string(),
            data_type: "STRING".to_string(),
            array: false,
            required: false,
        },
    ]
}
