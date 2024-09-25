//! Implementation of JSON-LD credential format.

use std::collections::HashMap;

use context::caching_loader::ContextCache;
use convert_case::{Case, Casing};
use indexmap::IndexSet;
use model::ContextType;
use serde::Serialize;
use shared_types::DidValue;
use sophia_api::quad::Spog;
use sophia_api::source::QuadSource;
use sophia_api::term::SimpleTerm;
use sophia_c14n::rdfc10;
use sophia_jsonld::loader::NoLoader;
use sophia_jsonld::loader_factory::DefaultLoaderFactory;
use sophia_jsonld::{JsonLdOptions, JsonLdParser};
use time::OffsetDateTime;
use url::Url;

use self::model::{LdCredential, LdCredentialSubject, LdProof};
use super::common::nest_claims;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchema, PublishedClaim,
};

pub mod context;
pub mod model;

#[cfg(test)]
mod test;
#[cfg(test)]
pub mod test_utilities;

type LdDataset = std::collections::HashSet<Spog<SimpleTerm<'static>>>;

pub fn prepare_credential(
    credential: CredentialData,
    holder_did: Option<&DidValue>,
    additional_context: Vec<ContextType>,
    additional_types: Vec<String>,
    json_ld_context_url: Option<Url>,
    custom_subject_name: Option<String>,
    embed_layout_properties: bool,
) -> Result<LdCredential, FormatterError> {
    let credential_schema = &credential.schema;

    let mut context: IndexSet<ContextType> = additional_context.into_iter().collect();
    if let Some(json_ld_context_url) = json_ld_context_url {
        context.insert(ContextType::Url(json_ld_context_url));
    }

    if let Some(credential_schema_context) = &credential_schema.context {
        let credential_schema_context: Url = credential_schema_context.parse().map_err(|_| {
            FormatterError::CouldNotFormat("Credential schema context must be a URL".to_string())
        })?;
        context.insert(credential_schema_context.into());
    }

    let ld_type = prepare_credential_type(&credential_schema.name, additional_types);

    let credential_subject = prepare_credential_subject(
        &credential_schema.name,
        credential.claims,
        holder_did,
        custom_subject_name,
    )?;

    // Strip layout (whole metadata as it only contains layout)
    let mut credential_schema: Option<CredentialSchema> = credential.schema.into();
    if let Some(schema) = &mut credential_schema {
        if !embed_layout_properties {
            schema.metadata = None;
        }
    }

    // TODO: this needs pushed out to upper layers, formatters MUST accept only valid VCs
    let id = credential
        .id
        .map(|s| s.parse())
        .transpose()
        .map_err(|_err| {
            FormatterError::CouldNotFormat(
                "Provided JsonLD context needs to be a valid URL".to_string(),
            )
        })?;

    Ok(LdCredential {
        context,
        id,
        r#type: ld_type,
        issuer: credential.issuer_did,
        valid_from: Some(OffsetDateTime::now_utc()),
        valid_until: None,
        credential_subject: vec![credential_subject],
        credential_status: credential.status,
        proof: None,
        credential_schema: credential_schema.map(|v| vec![v]),
        // we use `valid_from` for newly issued credentials
        issuance_date: None,
        name: credential.name,
        description: credential.description,
        terms_of_use: credential.terms_of_use,
        evidence: credential.evidence,
        refresh_service: None,
        related_resource: credential.related_resource,
    })
}

pub fn get_crypto_suite(json_ld_str: &str) -> Option<String> {
    match serde_json::from_str::<LdCredential>(json_ld_str) {
        Ok(json_ld) => json_ld.proof.map(|proof| proof.cryptosuite),
        Err(_) => None,
    }
}

pub async fn prepare_proof_config(
    proof_purpose: &str,
    cryptosuite: &str,
    key_id: String,
    context: IndexSet<ContextType>,
) -> Result<LdProof, FormatterError> {
    let r#type = "DataIntegrityProof".to_owned();

    Ok(LdProof {
        context: Some(context),
        r#type,
        created: Some(OffsetDateTime::now_utc()),
        cryptosuite: cryptosuite.to_owned(),
        verification_method: key_id,
        proof_purpose: proof_purpose.to_owned(),
        proof_value: None,
        nonce: None,
        challenge: None,
        domain: None,
    })
}

pub fn prepare_credential_type(
    credential_schema_name: &str,
    additional_types: Vec<String>,
) -> Vec<String> {
    let credential_schema_name = credential_schema_name.to_case(Case::Pascal);

    let mut types = vec![
        "VerifiableCredential".to_string(),
        format!("{}Subject", credential_schema_name),
    ];

    types.extend(additional_types);

    types
}

pub fn prepare_credential_subject(
    credential_schema_name: &str,
    claims: Vec<PublishedClaim>,
    holder_did: Option<&DidValue>,
    custom_subject_name: Option<String>,
) -> Result<LdCredentialSubject, FormatterError> {
    let credential_schema_name = credential_schema_name.to_case(Case::Pascal);

    let subject_name_base = custom_subject_name.unwrap_or(credential_schema_name);

    Ok(LdCredentialSubject {
        id: holder_did.cloned(),
        subject: HashMap::from([(
            format!("{subject_name_base}Subject"),
            serde_json::to_value(nest_claims(claims)?)
                .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?,
        )]),
    })
}

pub async fn canonize_any<T>(
    json_ld: &T,
    caching_loader: ContextCache,
) -> Result<String, FormatterError>
where
    T: Serialize,
{
    let content_str = serde_json::to_string(&json_ld)
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

    let options = JsonLdOptions::<DefaultLoaderFactory<NoLoader>>::default()
        .with_document_loader(caching_loader);

    let parser = JsonLdParser::new_with_options(options);

    // This will actually fetch context
    let parsed = parser.async_parse_str(&content_str).await;

    let dataset: LdDataset = parsed
        .collect_quads()
        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

    canonize_dataset(dataset).await
}

pub async fn canonize_dataset(dataset: LdDataset) -> Result<String, FormatterError> {
    let mut buf = Vec::<u8>::new();
    rdfc10::normalize(&dataset, &mut buf)
        .map_err(|e| FormatterError::CouldNotFormat(format!("Normalization error: `{}`", e)))?;

    let str = String::from_utf8_lossy(buf.as_slice());

    Ok(str.into_owned())
}

pub fn jsonld_forbidden_claim_names() -> Vec<String> {
    [
        "confidenceMethod",
        "credentialSchema",
        "credentialStatus",
        "credentialSubject",
        "description",
        "digestMultibase",
        "digestSRI",
        "evidence",
        "id",
        "issuer",
        "mediaType",
        "name",
        "proof",
        "refreshService",
        "relatedResource",
        "renderMethod",
        "termsOfUse",
        "type",
        "validFrom",
        "validUntil",
    ]
    .map(str::to_string)
    .to_vec()
}

pub fn is_context_list_valid(
    context_list: &IndexSet<ContextType>,
    allowed_contexts: Option<&Vec<Url>>,
    default_allowed_contexts: &[&str],
    credential_schemas: Option<&Vec<CredentialSchema>>,
    credential_id: Option<&Url>,
) -> bool {
    for context in context_list {
        match context {
            ContextType::Url(url) => {
                // Phase one - match against context list
                match allowed_contexts {
                    Some(provided) => {
                        if provided.contains(url) {
                            continue;
                        }
                    }
                    // Check defaults if required are not provided
                    None => {
                        if default_allowed_contexts.contains(&url.as_str()) {
                            continue;
                        }
                    }
                }

                // Phase two - match with available credential schemas
                if let Some(schemas) = credential_schemas {
                    if schemas.iter().any(|schema| {
                        let jsonld_context =
                            schema.id.replace("/ssi/schema/v1/", "/ssi/context/v1/");

                        // Workaround for lvvc context
                        let (base_url, _) =
                            schema.id.split_once("/ssi/schema/v1/").unwrap_or_default();
                        let lvvc_context = format!("{base_url}/ssi/context/v1/lvvc.json");

                        jsonld_context == url.as_str() || lvvc_context == url.as_str()
                    }) {
                        continue;
                    }
                }

                // Phase three - workaround for lvvc. When LVVC context
                // is hosted somewhere this can be removed.
                if let Some(id) = credential_id {
                    let (base_url, _) = id.as_str().split_once("/ssi/lvvc/v1/").unwrap_or_default();
                    let lvvc_context = format!("{base_url}/ssi/context/v1/lvvc.json");
                    if lvvc_context == url.as_str() {
                        continue;
                    }
                }
            }
            ContextType::Object(_) => continue, // Nothing to do
        }

        // If we could not match it with any allowed context bail here
        return false;
    }

    // All contexts whitelisted
    true
}
