use std::collections::{HashMap, HashSet};

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_crypto::Hasher;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{CredentialClaim, CredentialClaimValue};
use crate::provider::credential_formatter::sdjwt::model::{DecomposedToken, Disclosure};
use crate::util::jwt::mapper::string_to_b64url_string;

pub(crate) const SELECTIVE_DISCLOSURE_MARKER: &str = "_sd";
pub(crate) const SELECTIVE_DISCLOSURE_ARRAY_MARKER: &str = "...";

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

/// Pick disclosures that need to be shared with verifier
///
/// In case of a nested claim structure, if a node is about to be disclosed,
/// all parent claim disclosures need to be shared as well (so that the link to root digest inside the JWT is kept)
/// as well as all child claims of a selected node if a whole object is being shared
pub(crate) fn select_disclosures(
    disclosed_keys: &[String],
    token_payload: &Value,
    all_disclosures: Vec<Disclosure>,
    hasher: &dyn Hasher,
) -> Result<Vec<String>, FormatterError> {
    let all_digests = compute_digests(all_disclosures, hasher)?;

    let mut result = HashSet::new();
    for disclosed_key in disclosed_keys {
        let mut current_node = token_payload;
        let mut collect_subdisclosures = true;
        for key_part in disclosed_key.split(NESTED_CLAIM_MARKER) {
            match current_node {
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                    return Err(FormatterError::Failed(format!(
                        "Invalid nesting: child claim `{key_part}` from key `{disclosed_key}` does not exist"
                    )));
                }
                Value::Array(claims) => {
                    let index: usize = key_part.parse().map_err(|err| {
                        FormatterError::Failed(format!(
                            "Key `{key_part}` is not a valid array index: {err}"
                        ))
                    })?;
                    let Some(child) = claims.get(index) else {
                        return Err(FormatterError::Failed(format!(
                            "Index `{index}` from key `{disclosed_key}` is out of bounds: array length is {}",
                            claims.len()
                        )));
                    };

                    // Check if this element is an array element disclosure, e.g. {"...":"w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"}
                    if let Some(disclosure) = array_element_disclosure(child, &all_digests) {
                        // disclose array element
                        result.insert(disclosure.disclosure.clone());
                        // step into disclosed element
                        current_node = &disclosure.value
                    } else {
                        // plain child
                        current_node = child
                    }
                }
                Value::Object(claims) => {
                    // check if the claim is present as plain value
                    if let Some(child) = claims.get(key_part) {
                        // it is, step into child and continue
                        current_node = child;
                        continue;
                    }

                    // check if the claim is present as a disclosure
                    let sd_hashes = sd_hashes(claims);
                    let disclosure = sd_hashes
                        .iter()
                        .filter_map(|hash| all_digests.get(hash))
                        .find(|disclosure| {
                            disclosure.key.as_ref().is_some_and(|key| key == key_part)
                        });

                    if let Some(disclosure) = disclosure {
                        result.insert(disclosure.disclosure.clone());
                        current_node = &disclosure.value;
                        continue;
                    }
                    // The child claim does not exist. It could be a metadata claim, so we don't
                    // treat this as a failure (existence of claims has already been checked at this
                    // point). Hence, we simply stop processing this disclosed_key.
                    collect_subdisclosures = false;
                    break;
                }
            }
        }
        if collect_subdisclosures {
            result.extend(collect_all_subdisclosures(current_node, &all_digests))
        }
    }
    Ok(Vec::from_iter(result))
}

/// Check if this element is an array element disclosure, e.g. {"...":"w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"}
/// and if it is, return the matching disclosure.
fn array_element_disclosure<'a>(
    element: &Value,
    all_digests: &'a HashMap<String, Disclosure>,
) -> Option<&'a Disclosure> {
    if let Some(child_object) = element.as_object()
        && child_object.len() == 1
        && let Some(sd_hash) = child_object
            .get(SELECTIVE_DISCLOSURE_ARRAY_MARKER)
            .and_then(|value| value.as_str())
        && let Some(disclosure) = all_digests.get(sd_hash)
    {
        Some(disclosure)
    } else {
        None
    }
}

/// Transitively collects all disclosure strings from the whole subtree
fn collect_all_subdisclosures(
    claim: &Value,
    all_digests: &HashMap<String, Disclosure>,
) -> Vec<String> {
    match claim {
        // no child disclosures for flat values
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => vec![],
        Value::Array(elements) => {
            let mut result = vec![];
            for element in elements {
                let Some(disclosure) = array_element_disclosure(element, all_digests) else {
                    continue;
                };
                result.push(disclosure.disclosure.clone());
                result.extend(collect_all_subdisclosures(&disclosure.value, all_digests));
            }
            result
        }
        Value::Object(claims) => sd_hashes(claims)
            .iter()
            .filter_map(|hash| all_digests.get(hash))
            .flat_map(|disclosure| {
                let mut result = collect_all_subdisclosures(&disclosure.value, all_digests);
                result.push(disclosure.disclosure.clone());
                result
            })
            .collect(),
    }
}

impl Disclosure {
    // We keep this is for backwards compatibility where by mistake we were using the disclosure array string `[salt,key,value]` as disclosure
    pub fn hash_disclosure_array(&self, hasher: &dyn Hasher) -> Result<String, FormatterError> {
        hasher
            .hash_base64_url(self.disclosure_array.as_bytes())
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))
    }

    pub fn hash_disclosure(&self, hasher: &dyn Hasher) -> Result<String, FormatterError> {
        hasher
            .hash_base64_url(self.disclosure.as_bytes())
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))
    }
}

// The algorithm follows: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-14#section-4.2.1
pub(crate) fn compute_object_disclosures(
    value: &Value,
    hasher: &dyn Hasher,
    sd_array_elements: bool,
) -> Result<(Vec<String>, Vec<String>), FormatterError> {
    let object = value.as_object().ok_or(FormatterError::JsonMapping(
        "value is not an Object".to_string(),
    ))?;
    let mut disclosures = vec![];
    let mut digests = vec![];

    for (key, value) in object {
        match (sd_array_elements, value) {
            (_, Value::Object(_)) => {
                let (nested_disclosures, nested_sd_hashes) =
                    compute_object_disclosures(value, hasher, sd_array_elements)?;
                disclosures.extend(nested_disclosures);

                let nested_sd = json!({
                    SELECTIVE_DISCLOSURE_MARKER: nested_sd_hashes
                });

                let disclosure = compute_disclosure_for(key, &nested_sd)?;

                let hashed_disclosure = hasher
                    .hash_base64_url(disclosure.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(disclosure);
                digests.push(hashed_disclosure);
            }
            (true, Value::Array(_)) => {
                let (nested_disclosures, nested_sd_hashes) =
                    compute_array_disclosures(value, hasher)?;
                disclosures.extend(nested_disclosures);

                let sd_elements = nested_sd_hashes
                    .into_iter()
                    .map(|sd_hash| json!({SELECTIVE_DISCLOSURE_ARRAY_MARKER: sd_hash}))
                    .collect::<Vec<_>>();

                let disclosure = compute_disclosure_for(key, &Value::Array(sd_elements))?;
                let hashed_disclosure = hasher
                    .hash_base64_url(disclosure.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(disclosure);
                digests.push(hashed_disclosure);
            }
            _ => {
                let disclosure = compute_disclosure_for(key, value)?;

                let hashed_disclosure = hasher
                    .hash_base64_url(disclosure.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(disclosure);
                digests.push(hashed_disclosure);
            }
        }
    }

    Ok((disclosures, digests))
}
fn compute_disclosure_for(key: &str, value: &Value) -> Result<String, FormatterError> {
    let salt = one_crypto::utilities::generate_salt_base64_16();

    let array = json!([salt, key, value]).to_string();

    string_to_b64url_string(&array)
}

pub(crate) fn compute_array_disclosures(
    value: &Value,
    hasher: &dyn Hasher,
) -> Result<(Vec<String>, Vec<String>), FormatterError> {
    let array = value.as_array().ok_or(FormatterError::JsonMapping(
        "value is not an array".to_string(),
    ))?;
    let mut disclosures = vec![];
    let mut digests = vec![];

    for value in array {
        match value {
            Value::Object(_) => {
                let (nested_disclosures, nested_sd_hashes) =
                // array flag mut be true at this point, otherwise we would not deal with array disclosures at all
                    compute_object_disclosures(value, hasher, true)?;
                disclosures.extend(nested_disclosures);

                let nested_sd = json!({
                    SELECTIVE_DISCLOSURE_MARKER: nested_sd_hashes
                });

                let disclosure = compute_disclosure_for_array_element(&nested_sd)?;

                let hashed_disclosure = hasher
                    .hash_base64_url(disclosure.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(disclosure);
                digests.push(hashed_disclosure);
            }
            Value::Array(_) => {
                let (nested_disclosures, nested_sd_hashes) =
                    compute_array_disclosures(value, hasher)?;
                disclosures.extend(nested_disclosures);

                let sd_elements = nested_sd_hashes
                    .into_iter()
                    .map(|sd_hash| json!({SELECTIVE_DISCLOSURE_ARRAY_MARKER: sd_hash}))
                    .collect::<Vec<_>>();

                let disclosure = compute_disclosure_for_array_element(&Value::Array(sd_elements))?;
                let hashed_disclosure = hasher
                    .hash_base64_url(disclosure.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(disclosure);
                digests.push(hashed_disclosure);
            }
            _ => {
                let disclosure = compute_disclosure_for_array_element(value)?;

                let hashed_disclosure = hasher
                    .hash_base64_url(disclosure.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(disclosure);
                digests.push(hashed_disclosure);
            }
        }
    }

    Ok((disclosures, digests))
}

fn compute_disclosure_for_array_element(value: &Value) -> Result<String, FormatterError> {
    let salt = one_crypto::utilities::generate_salt_base64_16();
    let array = json!([salt, value]).to_string();
    string_to_b64url_string(&array)
}

pub(crate) fn parse_token(token: &str) -> Result<DecomposedToken, FormatterError> {
    let (token_with_disclosures, key_binding_token) = token
        .rsplit_once('~')
        .map(|(token, kb_token)| (token, (!kb_token.is_empty()).then_some(kb_token)))
        .unwrap_or((token, None));

    // ONE-6254: Legacy SD-JWT tokens do not have the mandatory '~' character at the end
    // -> Check if the last element is _really_ a KB token or just a disclosure of a badly formatted credential
    // Remove this block when compatibility with legacy SD-JWT credentials is no longer needed
    let (token_with_disclosures, key_binding_token) = match key_binding_token {
        // A properly formatted KB token must contain . in it
        Some(kb_token) if kb_token.contains('.') => (token_with_disclosures, Some(kb_token)),
        _ => (token.strip_suffix('~').unwrap_or(token), None),
    };

    let mut token_parts = token_with_disclosures.split("~");
    let jwt = token_parts.next().ok_or(FormatterError::MissingPart)?;

    let disclosures = token_parts
        .map(|disclosure| {
            let bytes = Base64UrlSafeNoPadding::decode_to_vec(disclosure, None).map_err(|err| {
                FormatterError::Failed(format!("failed to decode base64 disclosure: {err}"))
            })?;
            let disclosure_array = String::from_utf8(bytes).map_err(|err| {
                FormatterError::Failed(format!(
                    "failed to parse UTF-8 disclosure array from bytes: {err}"
                ))
            })?;

            parse_disclosure(disclosure_array, disclosure.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(DecomposedToken {
        jwt,
        disclosures,
        key_binding_token,
    })
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(expecting = "expecting [<salt>, <key>, <value>] array")]
pub(crate) struct DisclosureArray {
    pub salt: String,
    pub key: String,
    pub value: Value,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(expecting = "expecting [<salt>, <value>] array")]
pub(crate) struct DisclosureArrayElement {
    pub salt: String,
    pub value: Value,
}

pub(crate) fn parse_disclosure(
    disclosure_array: String,
    disclosure: String,
) -> Result<Disclosure, FormatterError> {
    let parsed = match serde_json::from_str::<DisclosureArray>(&disclosure_array) {
        Ok(DisclosureArray { salt, key, value }) => Disclosure {
            salt,
            key: Some(key),
            value,
            disclosure_array,
            disclosure,
        },
        Err(_) => {
            let array_element_disclosure =
                serde_json::from_str::<DisclosureArrayElement>(&disclosure_array)
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;
            Disclosure {
                salt: array_element_disclosure.salt,
                key: None,
                value: array_element_disclosure.value,
                disclosure_array,
                disclosure,
            }
        }
    };
    Ok(parsed)
}

fn gather_disclosures_from_sd(
    disclosures: &[(&Disclosure, (String, String))],
    sd_hashes: &[String],
) -> Result<HashMap<String, CredentialClaim>, FormatterError> {
    let mut result = HashMap::new();

    sd_hashes.iter().try_for_each(|hash| {
        if let Some((disclosure, _)) = disclosures
            .iter()
            .find(|(_, disclosure_hash)| *hash == *disclosure_hash.0 || *hash == *disclosure_hash.1)
        {
            let credential_claim = CredentialClaim {
                selectively_disclosable: true,
                metadata: false,
                value: CredentialClaimValue::try_from(disclosure.value.clone())?,
            };
            // skip over array disclosures
            if let Some(key) = &disclosure.key {
                result.insert(key.clone(), credential_claim);
            }
        }
        Ok::<_, FormatterError>(())
    })?;

    Ok(result)
}

fn sd_hashes(claims: &Map<String, Value>) -> Vec<String> {
    if let Some(sd) = claims.get(SELECTIVE_DISCLOSURE_MARKER) {
        return sd
            .as_array()
            .iter()
            .flat_map(|array| {
                array
                    .iter()
                    .filter_map(|hash| hash.as_str().map(str::to_string))
            })
            .collect();
    }
    vec![]
}

pub(crate) fn gather_object_sd_hashes(claims: &HashMap<String, CredentialClaim>) -> Vec<String> {
    if let Some(sd) = claims.get(SELECTIVE_DISCLOSURE_MARKER) {
        return sd
            .value
            .as_array()
            .iter()
            .flat_map(|array| {
                array
                    .iter()
                    .filter_map(|hash| hash.value.as_str().map(str::to_string))
            })
            .collect();
    }
    vec![]
}

fn gather_insertables_from_object(
    disclosures: &[(&Disclosure, (String, String))],
    map: &HashMap<String, CredentialClaim>,
) -> Result<HashMap<String, CredentialClaim>, FormatterError> {
    let sd_hashes = gather_object_sd_hashes(map);
    if !sd_hashes.is_empty() {
        return gather_disclosures_from_sd(disclosures, &sd_hashes);
    }

    Ok(HashMap::new())
}

fn expand_array_elements_in_place(
    disclosures: &[(&Disclosure, (String, String))],
    array: &mut [CredentialClaim],
) -> Result<(), FormatterError> {
    for claim in array.iter_mut() {
        if let Some(obj) = claim.value.as_object()
            && obj.len() == 1
            && let Some(sd_hash) = obj
                .get(SELECTIVE_DISCLOSURE_ARRAY_MARKER)
                .and_then(|value| value.value.as_str())
            && let Some((disclosure, _)) = disclosures.iter().find(|(_, disclosure_hash)| {
                *sd_hash == *disclosure_hash.0 || *sd_hash == *disclosure_hash.1
            })
        {
            *claim = CredentialClaim {
                selectively_disclosable: true,
                metadata: false,
                value: CredentialClaimValue::try_from(disclosure.value.clone())?,
            };
        }
    }
    Ok(())
}

pub fn recursively_expand_disclosures(
    disclosures: &[(&Disclosure, (String, String))],
    claims: &mut CredentialClaim,
) -> Result<(), FormatterError> {
    if let Some(map) = claims.value.as_object_mut() {
        let values: HashMap<String, CredentialClaim> =
            gather_insertables_from_object(disclosures, map)?;

        map.remove(SELECTIVE_DISCLOSURE_MARKER);
        map.extend(values);

        map.iter_mut()
            .try_for_each(|(_, v)| recursively_expand_disclosures(disclosures, v))?;
    } else if let Some(array) = claims.value.as_array_mut() {
        expand_array_elements_in_place(disclosures, array)?;
        for v in array.iter_mut() {
            recursively_expand_disclosures(disclosures, v)?;
        }
    }
    Ok(())
}
