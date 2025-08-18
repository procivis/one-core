use std::collections::{HashMap, HashSet};

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_crypto::Hasher;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{CredentialClaim, CredentialClaimValue};
use crate::provider::credential_formatter::sdjwt::model::{DecomposedToken, Disclosure};
use crate::util::jwt::mapper::string_to_b64url_string;

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

/// Pick disclosures that need to be shared with verifier
///
/// In case of a nested claim structure, if a node is about to be disclosed,
/// all parent claim disclosures need to be shared as well (so that the link to root digest inside the JWT is kept)
/// as well as all child claims of a selected node if a whole object is being shared
pub(crate) fn select_disclosures(
    disclosed_keys: Vec<String>,
    all_disclosures: Vec<Disclosure>,
    hasher: &dyn Hasher,
) -> Result<Vec<String>, FormatterError> {
    // tree of all disclosures, so that we can traverse the nodes and disclose proper entries, following the claim key path
    let whole_tree = construct_tree(&all_disclosures, hasher)?;

    let mut result = HashSet::new();
    for disclosed_key in disclosed_keys {
        let mut current_node = &whole_tree;
        for key_part in disclosed_key.split(NESTED_CLAIM_MARKER) {
            match current_node
                .iter()
                .find(|node| node.disclosure.key == key_part)
            {
                None => {
                    return Err(FormatterError::Failed(format!(
                        "Cannot find `{key_part}` from key `{disclosed_key}` in disclosures"
                    )));
                }
                Some(node) => {
                    current_node = &node.subdisclosures;

                    // disclose node on the path from root
                    result.insert(node.disclosure.disclosure.to_owned());

                    // if desired node reached, add all transitive subdisclosures (sharing entire object claim)
                    if disclosed_key == node.key_path {
                        result.extend(collect_all_subdisclosures(node));
                    }
                }
            };
        }
    }

    Ok(Vec::from_iter(result))
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

fn compute_disclosure_for(key: &str, value: &serde_json::Value) -> Result<String, FormatterError> {
    let salt = one_crypto::utilities::generate_salt_base64_16();

    let array = serde_json::json!([salt, key, value]).to_string();

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

#[derive(Debug, Eq, PartialEq)]
struct DisclosureTree {
    pub key_path: String,
    pub disclosure: Disclosure,
    pub subdisclosures: Vec<DisclosureTree>,
}

fn construct_tree(
    all_disclosures: &[Disclosure],
    hasher: &dyn Hasher,
) -> Result<Vec<DisclosureTree>, FormatterError> {
    let all_digests = compute_digests(all_disclosures.to_vec(), hasher)?;

    // mapping disclosure -> parent disclosure (in object claim tree)
    let mut parent_map = HashMap::new();
    for disclosure in all_disclosures {
        if let serde_json::Value::Object(obj) = &disclosure.value {
            if let Some(serde_json::Value::Array(linked_digests)) =
                obj.get(SELECTIVE_DISCLOSURE_MARKER)
            {
                for linked_digest in linked_digests {
                    if let serde_json::Value::String(digest) = linked_digest {
                        match all_digests.get(digest) {
                            None => {
                                // this might be a decoy disclosure digest, skipping
                                tracing::debug!("Decoy digest: {digest}");
                            }
                            Some(linked_disclosure) => {
                                parent_map.insert(
                                    linked_disclosure.disclosure.to_owned(),
                                    disclosure.disclosure.to_owned(),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    fn construct_node(
        disclosure: Disclosure,
        all_disclosures: &[Disclosure],
        parent_map: &HashMap<String, String>,
        parent_key_path: Option<&str>,
    ) -> DisclosureTree {
        let key_path = match parent_key_path {
            Some(parent_key_path) => {
                format!("{parent_key_path}{NESTED_CLAIM_MARKER}{}", disclosure.key)
            }
            None => disclosure.key.to_owned(),
        };

        let subdisclosures = all_disclosures
            .iter()
            .filter(|d| parent_map.get(&d.disclosure) == Some(&disclosure.disclosure))
            .map(|subdisclosure| {
                construct_node(
                    subdisclosure.to_owned(),
                    all_disclosures,
                    parent_map,
                    Some(&key_path),
                )
            })
            .collect();

        DisclosureTree {
            key_path,
            disclosure,
            subdisclosures,
        }
    }

    Ok(all_disclosures
        .iter()
        // level 0 disclosures
        .filter(|disclosure| !parent_map.contains_key(&disclosure.disclosure))
        .map(|disclosure| construct_node(disclosure.to_owned(), all_disclosures, &parent_map, None))
        .collect())
}

/// transitively collects all disclosure strings from the whole subtree
fn collect_all_subdisclosures(disclosure: &DisclosureTree) -> Vec<String> {
    disclosure
        .subdisclosures
        .iter()
        .flat_map(|node| {
            let mut res = collect_all_subdisclosures(node);
            res.push(node.disclosure.disclosure.to_owned());
            res
        })
        .collect()
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
                value: CredentialClaimValue::try_from(disclosure.value.clone())?,
            };
            result.insert(disclosure.key.clone(), credential_claim);
        }
        Ok::<_, FormatterError>(())
    })?;

    Ok(result)
}

fn gather_hashes_from_sd(sd: &CredentialClaimValue) -> Option<Vec<String>> {
    sd.as_array().map(|array| {
        array
            .iter()
            .filter_map(|hash| hash.value.as_str().map(str::to_string))
            .collect()
    })
}

fn gather_insertables_from_value(
    disclosures: &[(&Disclosure, (String, String))],
    map: &HashMap<String, CredentialClaim>,
) -> Result<HashMap<String, CredentialClaim>, FormatterError> {
    if let Some(sd) = map.get(SELECTIVE_DISCLOSURE_MARKER) {
        if let Some(hashes) = gather_hashes_from_sd(&sd.value) {
            return gather_disclosures_from_sd(disclosures, &hashes);
        }
    }

    Ok(HashMap::new())
}

pub fn recursively_expand_disclosures(
    disclosures: &[(&Disclosure, (String, String))],
    claims: &mut CredentialClaim,
) -> Result<(), FormatterError> {
    if let Some(map) = claims.value.as_object_mut() {
        let values: HashMap<String, CredentialClaim> =
            gather_insertables_from_value(disclosures, map)?;

        map.remove(SELECTIVE_DISCLOSURE_MARKER);
        map.extend(values);

        map.iter_mut()
            .try_for_each(|(_, v)| recursively_expand_disclosures(disclosures, v))?;
    } else if let Some(array) = claims.value.as_array_mut() {
        for v in array.iter_mut() {
            recursively_expand_disclosures(disclosures, v)?;
        }
    }
    Ok(())
}
