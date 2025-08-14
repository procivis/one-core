use std::collections::HashMap;

use bon::bon;
use indexmap::{IndexMap, IndexSet, indexset};
use one_dto_mapper::try_convert_inner;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{OneOrMany, serde_as, skip_serializing_none};
use shared_types::DidValue;
use time::OffsetDateTime;
use url::Url;

use super::error::FormatterError;
use super::model::{CredentialSubject, DetailCredential, IdentifierDetails};
use crate::provider::credential_formatter::model::{
    CredentialSchema, CredentialStatus, Description, Issuer, Name,
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(untagged)]
pub enum ContextType {
    Url(Url),
    Object(serde_json::Map<String, serde_json::Value>),
}

impl From<Url> for ContextType {
    fn from(value: Url) -> Self {
        Self::Url(value)
    }
}

#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
// https://www.w3.org/TR/vc-data-model-2.0/#verifiable-credentials
pub struct VcdmCredential {
    #[serde(rename = "@context")]
    pub context: IndexSet<ContextType>,

    #[serde(default, deserialize_with = "some_or_error")]
    pub id: Option<Url>,

    pub r#type: Vec<String>,

    pub issuer: Issuer,

    #[serde(default, with = "time::serde::rfc3339::option")]
    pub valid_from: Option<OffsetDateTime>,

    // VCDM v1.1, for VCDM 2.0 use valid_from
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default)]
    pub issuance_date: Option<OffsetDateTime>,

    #[serde(default, with = "time::serde::rfc3339::option")]
    pub valid_until: Option<OffsetDateTime>,

    // VCDM v1.1, for VCDM 2.0 use valid_until
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default)]
    pub expiration_date: Option<OffsetDateTime>,

    #[serde_as(as = "OneOrMany<_>")]
    pub credential_subject: Vec<VcdmCredentialSubject>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "OneOrMany<_>")]
    pub credential_status: Vec<CredentialStatus>,

    pub proof: Option<VcdmProof>,

    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub credential_schema: Option<Vec<CredentialSchema>>,

    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub refresh_service: Option<Vec<RefreshService>>,

    #[serde(default)]
    pub name: Option<Name>,

    #[serde(default)]
    pub description: Option<Description>,

    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub terms_of_use: Option<Vec<VcdmTermsOfUse>>,

    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub evidence: Option<Vec<VcdmEvidence>>,

    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub related_resource: Option<Vec<VcdmRelatedResource>>,
}

impl VcdmCredential {
    /// Creates new V2.0 VC setting type as VerifiableCredential and v2 context.
    #[must_use]
    pub fn new_v2(issuer: Issuer, credential_subject: VcdmCredentialSubject) -> Self {
        let context = ContextType::from(super::model::Context::CredentialsV2.to_url());
        let vc_type = "VerifiableCredential".to_string();

        VcdmCredential {
            context: indexset![context],
            id: None,
            r#type: vec![vc_type],
            issuer,
            valid_from: None,
            issuance_date: None,
            valid_until: None,
            expiration_date: None,
            credential_subject: vec![credential_subject],
            credential_status: vec![],
            proof: None,
            credential_schema: None,
            refresh_service: None,
            name: None,
            description: None,
            terms_of_use: None,
            evidence: None,
            related_resource: None,
        }
    }
    /// Adds additional context to the VC. Note that it already contains v2 context.
    #[must_use]
    pub fn add_context(mut self, context: impl Into<Option<ContextType>>) -> Self {
        if let Some(c) = context.into() {
            self.context.insert(c);
        }

        self
    }
    /// Adds additional type to the VC. Note that it already contains "VerifiableCredential" type.
    #[must_use]
    pub fn add_type(mut self, r#type: impl Into<String>) -> Self {
        self.r#type.push(r#type.into());
        self
    }

    #[must_use]
    pub fn with_proof(mut self, proof: VcdmProof) -> Self {
        self.proof = Some(proof);
        self
    }

    #[must_use]
    pub fn with_id(mut self, id: impl Into<Url>) -> Self {
        self.id = Some(id.into());
        self
    }

    #[must_use]
    pub fn with_valid_from(mut self, valid_from: OffsetDateTime) -> Self {
        self.valid_from = Some(valid_from);
        self
    }

    #[must_use]
    pub fn with_valid_until(mut self, valid_until: OffsetDateTime) -> Self {
        self.valid_until = Some(valid_until);
        self
    }

    pub fn add_credential_status(mut self, credential_status: CredentialStatus) -> Self {
        self.credential_status.push(credential_status);
        self
    }

    #[must_use]
    pub fn add_credential_schema(mut self, credential_schema: CredentialSchema) -> Self {
        self.credential_schema
            .get_or_insert(vec![])
            .push(credential_schema);

        self
    }

    pub fn remove_layout_properties(&mut self) {
        if let Some(credential_schema) = self.credential_schema.as_mut() {
            credential_schema
                .iter_mut()
                .for_each(|schema| schema.metadata = None)
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshService {
    #[serde_as(as = "OneOrMany<_>")]
    r#type: Vec<String>,
    // Which fields will be present depends on the `type`
    #[serde(flatten)]
    fields: serde_json::Map<String, serde_json::Value>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VcdmCredentialSubject {
    pub id: Option<Url>,
    #[serde(flatten)]
    pub claims: IndexMap<String, serde_json::Value>,
}

impl VcdmCredentialSubject {
    pub fn new(
        claims: impl IntoIterator<Item = (impl Into<String>, impl Into<serde_json::Value>)>,
    ) -> Self {
        Self {
            id: None,
            claims: claims
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    pub fn with_id(mut self, id: impl Into<Url>) -> Self {
        self.id = Some(id.into());
        self
    }
}

pub type Claims = HashMap<String, String>;

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VcdmProof {
    #[serde(rename = "@context")]
    pub context: Option<IndexSet<ContextType>>,
    pub r#type: String,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub created: Option<OffsetDateTime>,
    pub cryptosuite: String,
    pub verification_method: String,
    pub proof_purpose: String,
    pub proof_value: Option<String>,
    pub nonce: Option<String>,
    pub challenge: Option<String>,
    pub domain: Option<String>,
}

#[bon]
impl VcdmProof {
    // todo: once we have custom types for cryptosuite, verification_method and proof_purpose remove builder dependency
    #[builder]
    pub fn new(
        context: Option<IndexSet<ContextType>>,
        created: Option<OffsetDateTime>,
        #[builder(into)] cryptosuite: String,
        #[builder(into)] verification_method: String,
        #[builder(into)] proof_purpose: String,
        proof_value: Option<String>,
        nonce: Option<String>,
        challenge: Option<String>,
        domain: Option<String>,
    ) -> Self {
        Self {
            context,
            r#type: "DataIntegrityProof".to_string(),
            created,
            cryptosuite,
            verification_method,
            proof_purpose,
            proof_value,
            nonce,
            challenge,
            domain,
        }
    }
}

#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VcdmTermsOfUse {
    #[serde_as(as = "OneOrMany<_>")]
    r#type: Vec<String>,

    #[serde(default, deserialize_with = "some_or_error")]
    id: Option<Url>,
}

#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, bon::Builder)]
#[serde(rename_all = "camelCase")]
pub struct VcdmEvidence {
    #[serde_as(as = "OneOrMany<_>")]
    r#type: Vec<String>,

    #[serde(default, deserialize_with = "some_or_error")]
    id: Option<Url>,
}

#[derive(Debug, Serialize, Deserialize, Clone, bon::Builder)]
#[serde(rename_all = "camelCase")]
pub struct VcdmRelatedResource {
    pub id: Url,
    pub media_type: Option<String>,
    #[serde(rename = "digestSRI")]
    pub digest_sri: Option<String>,
    pub digest_multibase: Option<String>,
}

#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
// useful for parsing JWT/SD-JWT formats what may contain some of the values outside the "vc" claim
pub struct JwtVcdmCredential {
    pub(super) issuer: Option<Issuer>,

    #[serde(default, with = "time::serde::rfc3339::option")]
    pub(super) valid_from: Option<OffsetDateTime>,

    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default)]
    pub(super) issuance_date: Option<OffsetDateTime>,

    #[serde(default, with = "time::serde::rfc3339::option")]
    pub(super) valid_until: Option<OffsetDateTime>,

    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default)]
    pub(super) expiration_date: Option<OffsetDateTime>,

    #[serde(rename = "@context")]
    pub(super) context: IndexSet<ContextType>,

    #[serde(default, deserialize_with = "some_or_error")]
    id: Option<Url>,

    pub(super) r#type: Vec<String>,

    #[serde_as(as = "OneOrMany<_>")]
    pub(super) credential_subject: Vec<VcdmCredentialSubject>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "OneOrMany<_>")]
    pub(super) credential_status: Vec<CredentialStatus>,

    proof: Option<VcdmProof>,

    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub(super) credential_schema: Option<Vec<CredentialSchema>>,

    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    refresh_service: Option<Vec<RefreshService>>,

    #[serde(default)]
    name: Option<Name>,

    #[serde(default)]
    description: Option<Description>,

    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    terms_of_use: Option<Vec<VcdmTermsOfUse>>,

    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    evidence: Option<Vec<VcdmEvidence>>,

    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    related_resource: Option<Vec<VcdmRelatedResource>>,
}

impl From<VcdmCredential> for JwtVcdmCredential {
    fn from(value: VcdmCredential) -> Self {
        Self {
            context: value.context,
            id: value.id,
            r#type: value.r#type,
            issuer: Some(value.issuer),
            valid_from: value.valid_from,
            issuance_date: value.issuance_date,
            valid_until: value.valid_until,
            expiration_date: value.expiration_date,
            credential_subject: value.credential_subject,
            credential_status: value.credential_status,
            proof: value.proof,
            credential_schema: value.credential_schema,
            refresh_service: value.refresh_service,
            name: value.name,
            description: value.description,
            terms_of_use: value.terms_of_use,
            evidence: value.evidence,
            related_resource: value.related_resource,
        }
    }
}

impl TryFrom<VcdmCredential> for DetailCredential {
    type Error = FormatterError;

    fn try_from(mut vcdm: VcdmCredential) -> Result<Self, Self::Error> {
        let Some(credential_subject) = vcdm.credential_subject.pop() else {
            return Err(FormatterError::Failed(
                "Missing credential subject".to_string(),
            ));
        };

        if !vcdm.credential_subject.is_empty() {
            return Err(FormatterError::Failed(
                "We currently don't support multiple credential subjects".to_string(),
            ));
        }

        let credential_schema = vcdm
            .credential_schema
            .map(|mut schemas| {
                let Some(credential_schema) = schemas.pop() else {
                    return Err(FormatterError::Failed(
                        "Missing credential schema".to_string(),
                    ));
                };

                if !schemas.is_empty() {
                    return Err(FormatterError::Failed(
                        "We currently don't support multiple credential schemas".to_string(),
                    ));
                }

                Ok(credential_schema)
            })
            .transpose()?;

        let claims = CredentialSubject {
            id: credential_subject.id.clone(),
            claims: try_convert_inner(HashMap::from_iter(credential_subject.claims))?,
        };

        // this is not always DID, for example LVVC credentials use URN schema as and id
        let subject = credential_subject
            .id
            .and_then(|id| DidValue::from_did_url(id).ok())
            .map(IdentifierDetails::Did);

        Ok(Self {
            id: vcdm.id.map(|url| url.to_string()),
            issuance_date: vcdm.proof.and_then(|proof| proof.created),
            valid_from: vcdm.valid_from.or(vcdm.issuance_date),
            valid_until: vcdm.valid_until.or(vcdm.expiration_date),
            update_at: None,
            invalid_before: None,
            issuer: IdentifierDetails::Did(vcdm.issuer.to_did_value()?),
            subject,
            claims,
            status: vcdm.credential_status,
            credential_schema,
        })
    }
}

fn some_or_error<'de, D, R>(deserializer: D) -> Result<Option<R>, D::Error>
where
    D: Deserializer<'de>,
    R: Deserialize<'de>,
{
    match Option::<R>::deserialize(deserializer)? {
        Some(v) => Ok(Some(v)),
        None => Err(serde::de::Error::custom(
            "Deserializer forbids deserializing `null`",
        )),
    }
}

#[cfg(test)]
mod test {
    use serde::Deserialize;
    use similar_asserts::assert_eq;

    use super::*;

    #[derive(Debug, Deserialize, Clone)]
    struct Foo {
        #[serde(default, deserialize_with = "some_or_error")]
        x: Option<String>,
    }

    #[test]
    fn test_some_or_error_deserialization_fails_for_null_value() {
        let error = serde_json::from_str::<Foo>(r#"{"x": null}"#).err().unwrap();

        assert!(
            error
                .to_string()
                .starts_with("Deserializer forbids deserializing `null`")
        );
    }

    #[test]
    fn test_some_or_error_ok() {
        let foo = serde_json::from_str::<Foo>(r#"{"x": "test"}"#).unwrap();
        assert_eq!(foo.x.unwrap(), "test");

        let foo = serde_json::from_str::<Foo>(r#"{}"#).unwrap();
        assert!(foo.x.is_none());
    }
}
