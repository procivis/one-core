//! Implementation of JSON-LD credential format.

use indexmap::IndexSet;
use json_ld::Loader;
use serde::Serialize;
use url::Url;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::CredentialSchema;
use crate::provider::credential_formatter::vcdm::{ContextType, VcdmCredential};

pub mod canonization;
pub mod context;
pub mod model;

#[cfg(test)]
mod test;

pub fn get_crypto_suite(json_ld_str: &str) -> Option<String> {
    match serde_json::from_str::<VcdmCredential>(json_ld_str) {
        Ok(json_ld) => json_ld.proof.map(|proof| proof.cryptosuite),
        Err(_) => None,
    }
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

pub async fn rdf_canonize(
    document: impl Serialize,
    loader: &impl Loader,
    options: json_ld::Options,
) -> Result<String, FormatterError> {
    canonization::canonize(&document, loader, options)
        .await
        .map_err(|err| FormatterError::Failed(format!("Canonization failed: {err}")))
}

pub fn json_ld_processor_options() -> json_ld::Options {
    json_ld::Options {
        expansion_policy: json_ld::expansion::Policy {
            invalid: json_ld::expansion::Action::Reject,
            allow_undefined: false,
            ..Default::default()
        },
        ..Default::default()
    }
}
