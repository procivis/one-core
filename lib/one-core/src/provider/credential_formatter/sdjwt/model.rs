use std::collections::HashMap;

use indexmap::IndexMap;
use maplit::hashmap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{OneOrMany, serde_as, skip_serializing_none};
use time::OffsetDateTime;
use url::Url;

use crate::model::certificate::Certificate;
use crate::model::identifier::Identifier;
use crate::proto::jwt::WithMetadata;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialClaim, CredentialClaimValue, CredentialSchema, CredentialStatus, Issuer,
    SettableClaims,
};
use crate::provider::credential_formatter::vcdm::{ContextType, JwtVcdmCredential};

#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCContent {
    #[serde(rename = "@context")]
    pub context: Vec<ContextType>,
    pub id: Option<String>,
    pub r#type: Vec<String>,
    pub credential_subject: SDCredentialSubject,
    #[serde(default)]
    #[serde_as(as = "OneOrMany<_>")]
    pub credential_status: Vec<CredentialStatus>,
    pub credential_schema: Option<CredentialSchema>,
    #[serde(default)]
    pub issuer: Option<Issuer>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default)]
    pub valid_from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default)]
    pub valid_until: Option<OffsetDateTime>,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VcClaim {
    #[serde(rename = "_sd", default, skip_serializing_if = "Vec::is_empty")]
    pub digests: Vec<String>,

    pub vc: JwtVcdmCredential,
    /// Hash algorithm
    /// https://www.iana.org/assignments/named-information/named-information.xhtml
    #[serde(rename = "_sd_alg", default)]
    pub hash_alg: Option<String>,

    /// Copy of all the claims to retain selective disclosability info.
    /// Used later to retrieve metadata claims.
    #[serde(skip)]
    pub all_claims: Option<CredentialClaim>,
}

impl WithMetadata for VcClaim {
    fn get_metadata_claims(&self) -> Result<HashMap<String, CredentialClaim>, FormatterError> {
        let Some(claims) = &self.all_claims else {
            return Ok(HashMap::new());
        };
        let Some(vc) = claims.value.as_object().and_then(|o| o.get("vc")) else {
            return Ok(HashMap::new());
        };
        let mut vc_claim = vc.clone();
        if let Some(obj) = vc_claim.value.as_object_mut() {
            obj.retain(|k, _| k == "type" || k == "id");
        }
        vc_claim.set_metadata(true);

        Ok(hashmap! {
            "vc".to_string() => vc_claim,
        })
    }
}

impl SettableClaims for VcClaim {
    fn set_claims(&mut self, mut claims: CredentialClaim) -> Result<(), FormatterError> {
        // store all claims for later use
        self.all_claims = Some(claims.clone());
        let Some(subject) = self.vc.credential_subject.first_mut() else {
            return Err(FormatterError::Failed(
                "Missing vc.credential_subject".to_string(),
            ));
        };
        let first_level = claims.value.as_object_mut().ok_or(FormatterError::Failed(
            "Expected claims to be an object".to_string(),
        ))?;
        let vc = first_level
            .get_mut("vc")
            .ok_or(FormatterError::Failed("vc not found".to_string()))?
            .value
            .as_object_mut()
            .ok_or(FormatterError::Failed("vc is not an object".to_string()))?;
        let credential_subject = vc
            .get_mut("credentialSubject")
            .ok_or(FormatterError::Failed(
                "Missing credentialSubject".to_string(),
            ))?;

        let subject_claims = match &mut credential_subject.value {
            CredentialClaimValue::Array(arr) => {
                let first = arr.first_mut().ok_or(FormatterError::Failed(
                    "Empty credentialSubject".to_string(),
                ))?;
                first.value.as_object_mut().ok_or(FormatterError::Failed(
                    "credentialSubject must be an object or array of objects".to_string(),
                ))?
            }
            CredentialClaimValue::Object(obj) => obj,
            _ => {
                return Err(FormatterError::Failed(
                    "credentialSubject must be array or object".to_string(),
                ));
            }
        };

        let id = subject_claims.remove("id");
        if let Some(id) = id {
            subject.id = Some(
                Url::parse(
                    id.value
                        .as_str()
                        .ok_or(FormatterError::Failed("id must be string".to_string()))?,
                )
                .map_err(|e| FormatterError::Failed(format!("failed to parse id as URL: {e}")))?,
            );
        };
        subject.claims = IndexMap::from_iter(subject_claims.drain());
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Disclosure {
    pub salt: String,
    pub key: Option<String>,
    pub value: Value,
    pub disclosure_array: String,
    pub disclosure: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SDCredentialSubject {
    #[serde(rename = "_sd", default, skip_serializing_if = "Vec::is_empty")]
    pub digests: Vec<String>,
    #[serde(flatten)]
    pub public_claims: HashMap<String, Value>,
}

pub struct DecomposedToken<'a> {
    pub jwt: &'a str,
    pub disclosures: Vec<Disclosure>,
    pub key_binding_token: Option<&'a str>,
}

pub struct SdJwtFormattingInputs {
    pub holder_identifier: Option<Identifier>,
    pub holder_key_id: Option<String>,
    pub leeway: u64,
    pub token_type: String,
    // Toggles the malformed `cnf` claim required for SWIYU interop
    pub swiyu_proof_of_possession: bool,
    pub issuer_certificate: Option<Certificate>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KeyBindingPayload {
    pub nonce: String,
    pub sd_hash: String,
}
