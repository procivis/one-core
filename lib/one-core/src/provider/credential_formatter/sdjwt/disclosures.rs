use std::collections::{HashMap, HashSet};

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_crypto::Hasher;
use serde::{Deserialize, Serialize};

use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::mapper::string_to_b64url_string;
use crate::provider::credential_formatter::sdjwt::model::{DecomposedToken, Disclosure};

pub(crate) const SELECTIVE_DISCLOSURE_MARKER: &str = "_sd";

// Reconstructs digests from disclosures
pub(crate) fn compute_digests(
    disclosures: Vec<Disclosure>,
    hasher: &dyn Hasher,
) -> Result<HashMap<String, Disclosure>, FormatterError> {
    let capacity = 2 * disclosures.len();

    disclosures.into_iter().try_fold(
        HashMap::with_capacity(capacity),
        |mut digests, disclosure| {
            // keep them for backwards compatibility with already issued vc
            let old = disclosure.hash_disclosure_array(hasher)?;
            let current = disclosure.hash_disclosure(hasher)?;

            digests.insert(old, disclosure.clone());
            digests.insert(current, disclosure);

            Ok(digests)
        },
    )
}

pub(crate) fn select_disclosures(
    disclosed_keys: Vec<String>,
    disclosures: Vec<Disclosure>,
) -> Result<Vec<String>, FormatterError> {
    let mut selected_disclosures = HashSet::new();
    let key_disclosure: HashMap<String, String> = disclosures
        .into_iter()
        .map(|disclosure| (disclosure.key, disclosure.disclosure))
        .collect();

    for key in disclosed_keys {
        for key_part in key.split(NESTED_CLAIM_MARKER) {
            match key_disclosure.get(key_part) {
                None => {
                    return Err(FormatterError::Failed(format!(
                        "Cannot find `{key_part}` from key `{key}` in disclosures"
                    )))
                }
                Some(disclosure) => selected_disclosures.insert(disclosure.to_owned()),
            };
        }
    }

    Ok(Vec::from_iter(selected_disclosures))
}

impl Disclosure {
    // We keep this is for backwards compatibility where by mistake we were using the disclosure array string `[salt,key,value]` as disclosure
    pub fn hash_disclosure_array(&self, hasher: &dyn Hasher) -> Result<String, FormatterError> {
        hasher
            .hash_base64(self.disclosure_array.as_bytes())
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))
    }

    pub fn hash_disclosure(&self, hasher: &dyn Hasher) -> Result<String, FormatterError> {
        hasher
            .hash_base64(self.disclosure.as_bytes())
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))
    }
}

pub(crate) fn to_hashmap(
    value: serde_json::Value,
) -> Result<HashMap<String, serde_json::Value>, FormatterError> {
    Ok(value
        .as_object()
        .ok_or(FormatterError::JsonMapping(
            "value is not an Object".to_string(),
        ))?
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect())
}

// The algorithm follows: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-14#section-4.2.1
pub(crate) fn compute_object_disclosures(
    value: &serde_json::Value,
    hasher: &dyn Hasher,
) -> Result<(Vec<String>, Vec<String>), FormatterError> {
    let object = value.as_object().ok_or(FormatterError::JsonMapping(
        "value is not an Object".to_string(),
    ))?;
    let mut disclosures = vec![];
    let mut digests = vec![];

    for (key, value) in object {
        match value {
            serde_json::Value::Object(_) => {
                let (nested_disclosures, nested_sd_hashes) =
                    compute_object_disclosures(value, hasher)?;
                disclosures.extend(nested_disclosures);

                let nested_sd = serde_json::json!({
                    SELECTIVE_DISCLOSURE_MARKER: nested_sd_hashes
                });

                let disclosure = compute_disclosure_for(key, &nested_sd)?;

                let hashed_disclosure = hasher
                    .hash_base64(disclosure.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(disclosure);
                digests.push(hashed_disclosure);
            }

            _ => {
                let disclosure = compute_disclosure_for(key, value)?;

                let hashed_disclosure = hasher
                    .hash_base64(disclosure.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(disclosure);
                digests.push(hashed_disclosure);
            }
        }
    }

    Ok((disclosures, digests))
}

fn compute_disclosure_for(key: &str, value: &serde_json::Value) -> Result<String, FormatterError> {
    let salt = one_crypto::utilities::generate_salt_base64_16();

    let array = serde_json::json!([salt, key, value]).to_string();

    string_to_b64url_string(&array)
}

// Note that currently we only pass digests coming from `credentialSubject`(digests parameter)
pub(crate) fn extract_claims_from_disclosures(
    digests: Vec<String>,
    disclosures: Vec<Disclosure>,
    hasher: &dyn Hasher,
) -> Result<serde_json::Value, FormatterError> {
    let digest_by_disclosure = compute_digests(disclosures, hasher)?;

    extract_claims(digests, digest_by_disclosure)
}

fn extract_claims(
    digests: Vec<String>,
    mut digest_by_disclosure: HashMap<String, Disclosure>,
) -> Result<serde_json::Value, FormatterError> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DisclosureValueKind {
        NestedDigests {
            #[serde(rename = "_sd")]
            digests: Vec<String>,
        },
        JsonValue(serde_json::Value),
    }

    fn extract_inner(
        digests: Vec<String>,
        digest_by_disclosure: &mut HashMap<String, Disclosure>,
    ) -> Result<serde_json::Value, FormatterError> {
        let mut object: serde_json::Map<String, serde_json::Value> = serde_json::Map::default();

        for digest in digests {
            let Some(disclosure) = digest_by_disclosure.remove(&digest) else {
                continue;
            };

            let key = disclosure.key;
            if key == "_sd" || key == "..." {
                return Err(FormatterError::Failed(format!("Invalid claim name: {key}")));
            }

            let disclosure_value_kind: DisclosureValueKind =
                serde_json::from_value(disclosure.value)
                    .map_err(|err| FormatterError::Failed(err.to_string()))?;
            let value = match disclosure_value_kind {
                DisclosureValueKind::NestedDigests { digests } => {
                    extract_inner(digests, digest_by_disclosure)?
                }
                DisclosureValueKind::JsonValue(value) => value,
            };

            match object.entry(key) {
                serde_json::map::Entry::Occupied(entry) => {
                    return Err(FormatterError::Failed(format!(
                        "Duplicate claim name: `{}`",
                        entry.key()
                    )))
                }
                serde_json::map::Entry::Vacant(entry) => {
                    entry.insert(value);
                }
            }
        }

        Ok(serde_json::Value::Object(object))
    }

    extract_inner(digests, &mut digest_by_disclosure)
}

pub(crate) fn parse_token(token: &str) -> Result<DecomposedToken, FormatterError> {
    let mut token_parts = token.trim_end_matches('~').split("~");
    let jwt = token_parts.next().ok_or(FormatterError::MissingPart)?;

    let disclosures: Vec<Disclosure> = token_parts
        .filter_map(|disclosure| {
            let bytes = Base64UrlSafeNoPadding::decode_to_vec(disclosure, None).ok()?;
            let disclosure_array = String::from_utf8(bytes).ok()?;

            parse_disclosure(disclosure_array, disclosure.to_string()).ok()
        })
        .collect();

    Ok(DecomposedToken { jwt, disclosures })
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(expecting = "expecting [<salt>, <key>, <value>] array")]
pub(crate) struct DisclosureArray {
    pub salt: String,
    pub key: String,
    pub value: serde_json::Value,
}

pub(crate) fn parse_disclosure(
    disclosure_array: String,
    disclosure: String,
) -> Result<Disclosure, FormatterError> {
    let parsed: DisclosureArray = serde_json::from_str(&disclosure_array)
        .map_err(|e| FormatterError::Failed(e.to_string()))?;

    Ok(Disclosure {
        salt: parsed.salt,
        key: parsed.key,
        value: parsed.value,
        disclosure_array,
        disclosure,
    })
}
