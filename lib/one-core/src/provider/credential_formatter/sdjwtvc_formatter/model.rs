use std::collections::HashMap;

use maplit::hashmap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{serde_as, skip_serializing_none};
use time::OffsetDateTime;
use url::Url;

use crate::proto::jwt::WithMetadata;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialClaim, CredentialClaimValue, IssuedClaims, SettableClaims, TokenStatus,
};

#[derive(Debug)]
pub struct SdJwtVcCredential {
    pub vct: String,
    pub issuer: Url,
    pub valid_until: Option<OffsetDateTime>,
    pub credential_status: Option<TokenStatus>,
    pub claims: IssuedClaims,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdJwtVc {
    #[serde(rename = "vct")]
    pub vc_type: String,

    #[serde(rename = "vct#integrity", default)]
    pub vct_integrity: Option<String>,

    #[serde(rename = "_sd", default, skip_serializing_if = "Vec::is_empty")]
    pub digests: Vec<String>,

    /// Hash algorithm
    /// https://www.iana.org/assignments/named-information/named-information.xhtml
    #[serde(rename = "_sd_alg", default)]
    pub hash_alg: Option<String>,

    #[serde(default)]
    pub status: Option<SdJwtVcStatus>,

    #[serde(flatten)]
    pub public_claims: HashMap<String, CredentialClaim>,

    /// Registered JWT claims (see [`DISCLOSABLE_METADATA_CLAIMS`]) received as disclosures.
    /// They keep the semantics of their plain counterparts, so they are handled as metadata
    /// claims, not as public claims.
    #[serde(skip)]
    pub disclosed_metadata_claims: HashMap<String, CredentialClaim>,
}

impl WithMetadata for SdJwtVc {
    fn get_metadata_claims(&self) -> Result<HashMap<String, CredentialClaim>, FormatterError> {
        let mut metadata_claims = hashmap! {
            "vct".to_string() => CredentialClaim {
                selectively_disclosable: false,
                metadata: true,
                value: CredentialClaimValue::String(self.vc_type.clone()),
            }
        };
        metadata_claims.extend(self.disclosed_metadata_claims.clone());
        Ok(metadata_claims)
    }
}

/// Root-level claims that must not be selectively disclosed.
///
/// SD-JWT VC, section "Registered JWT Claims" (https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-26.html#name-registered-jwt-claims):
/// `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity` and `status` MUST NOT be selectively
/// disclosed. All other claims (e.g. `sub`, `iat`, `aud`, `jti`) may be selectively disclosed.
const NON_DISCLOSABLE_CLAIMS: [&str; 7] =
    ["iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status"];

/// Registered JWT claims that may be selectively disclosed, but are still metadata claims.
///
/// `sub` is deliberately not included: in SD-JWT VC it is never a metadata claim (see
/// `split_claims` in the formatter), so a disclosed `sub` stays a regular claim.
const DISCLOSABLE_METADATA_CLAIMS: [&str; 3] = ["iat", "aud", "jti"];

impl SettableClaims for SdJwtVc {
    fn set_claims(&mut self, claims: CredentialClaim) -> Result<(), FormatterError> {
        let mut claims = match claims.value {
            CredentialClaimValue::Object(claims) => claims,
            _ => Err(FormatterError::JsonMapping(
                "Expected claims to be object".to_string(),
            ))?,
        };
        if let Some(key) = NON_DISCLOSABLE_CLAIMS
            .iter()
            .find(|key| claims.get(**key).is_some_and(|c| c.selectively_disclosable))
        {
            return Err(FormatterError::CouldNotExtractCredentials(format!(
                "Claim `{key}` must not be selectively disclosed"
            )));
        }
        // don't override reserved claims
        claims.remove("vct");
        claims.remove("vct#integrity");
        claims.remove("_sd");
        claims.remove("_sd_alg");
        claims.remove("status");
        // plain registered claims are not part of `claims`, so these can only be disclosures
        self.disclosed_metadata_claims = DISCLOSABLE_METADATA_CLAIMS
            .iter()
            .filter_map(|key| claims.remove_entry(*key))
            .map(|(key, mut claim)| {
                claim.set_metadata(true);
                (key, claim)
            })
            .collect();
        self.public_claims = claims;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct SdJwtVcStatus {
    pub status_list: SdJwtVcStatusList,
    #[serde(flatten)]
    pub custom_claims: HashMap<String, Value>,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SdJwtVcStatusList {
    #[serde(rename = "idx", deserialize_with = "deserialize_string_or_number")]
    pub index: usize,
    pub uri: Url,
}

fn deserialize_string_or_number<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Value::deserialize(deserializer)?;

    match v {
        Value::String(s) => s.parse().map_err(serde::de::Error::custom),
        Value::Number(n) => n
            .as_u64()
            .map(|n| n as usize)
            .ok_or(serde::de::Error::custom(
                "failed to deserialize status list index",
            )),
        _ => Err(serde::de::Error::custom(
            "failed to deserialize status list index",
        )),
    }
}
