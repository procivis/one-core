use std::cmp::Ordering;
use std::collections::HashMap;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_crypto::{CryptoProvider, Hasher};
use serde::{Deserialize, Serialize};

use crate::common_mapper::{remove_first_nesting_layer, NESTED_CLAIM_MARKER};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::mapper::string_to_b64url_string;
use crate::provider::credential_formatter::model::PublishedClaim;
use crate::provider::credential_formatter::sdjwt::model::{DecomposedToken, Disclosure};

pub(crate) const SELECTIVE_DISCLOSURE_MARKER: &str = "_sd";

pub(crate) fn gather_hashes_from_original_disclosures(
    disclosures: &[Disclosure],
    hasher: &dyn Hasher,
) -> Result<Vec<String>, FormatterError> {
    disclosures
        .iter()
        .map(|disclosure| disclosure.hash_original_disclosure(hasher))
        .collect::<Result<Vec<String>, FormatterError>>()
}

#[derive(Debug, Deserialize)]
struct SelectiveDisclosureArray {
    #[serde(rename = "_sd")]
    pub sd: Vec<String>,
}

fn gather_hash(
    disclosure: &Disclosure,
    hasher: &dyn Hasher,
) -> Result<Vec<String>, FormatterError> {
    match serde_json::from_value::<SelectiveDisclosureArray>(disclosure.value.to_owned()) {
        Ok(mut value) => {
            value.sd.push(disclosure.hash_original_disclosure(hasher)?);
            Ok(value.sd)
        }
        Err(_) => Ok(vec![disclosure.hash_original_disclosure(hasher)?]),
    }
}

pub(crate) fn gather_hashes_from_hashed_claims(
    hashed_claims: &[String],
    disclosures: &[Disclosure],
    hasher: &dyn Hasher,
) -> Result<Vec<String>, FormatterError> {
    let mut used_hashes = vec![];

    hashed_claims.iter().try_for_each(|hashed_claim| {
        let matching_disclosure = disclosures.iter().find(|disclosure| {
            match disclosure.hash_original_disclosure(hasher) {
                Ok(hash) => hash == *hashed_claim,
                _ => false,
            }
        });
        if let Some(disclosure) = matching_disclosure {
            used_hashes.extend(gather_hash(disclosure, hasher)?);
        }
        Ok::<(), FormatterError>(())
    })?;

    Ok(used_hashes)
}

pub(crate) fn get_disclosures_by_claim_name(
    claim_name: &str,
    disclosures: &[Disclosure],
    hasher: &dyn Hasher,
) -> Result<Vec<Disclosure>, FormatterError> {
    let mut result = vec![];
    let hashes = gather_hashes_from_original_disclosures(disclosures, hasher)?;

    if let Some(index) = claim_name.find(NESTED_CLAIM_MARKER) {
        let prefix = &claim_name[0..index];
        let rest = remove_first_nesting_layer(claim_name);

        let disclosure = disclosures
            .iter()
            .find(|d| d.key == prefix)
            .ok_or(FormatterError::MissingClaim)?;
        if !disclosure.has_subdisclosures() {
            return Err(FormatterError::Failed(
                "asked for subdisclosure of non-nested claim".to_string(),
            ));
        }

        for sd_hash in disclosure.get_subdisclosure_hashes()? {
            let subdisclosures = resolve_disclosure_by_hash(&sd_hash, disclosures, &hashes)?;

            if let Ok(disclosures) = get_disclosures_by_claim_name(&rest, &subdisclosures, hasher) {
                result.extend(disclosures);
                result.push(disclosure.to_owned());
                return Ok(result);
            }
        }

        return Err(FormatterError::MissingClaim);
    } else if let Some(disclosure) = disclosures
        .iter()
        .find(|disclosure| disclosure.key == claim_name)
    {
        if disclosure.has_subdisclosures() {
            for subdisclosure in disclosure.get_subdisclosure_hashes()? {
                result.extend(resolve_disclosure_by_hash(
                    &subdisclosure,
                    disclosures,
                    &hashes,
                )?);
            }
        }

        result.push(disclosure.to_owned());
        return Ok(result);
    }

    Err(FormatterError::MissingClaim)
}

fn resolve_disclosure_by_hash(
    hash: &str,
    disclosures: &[Disclosure],
    hashes: &[String],
) -> Result<Vec<Disclosure>, FormatterError> {
    let mut result = vec![];

    let (disclosure, _hash) = disclosures
        .iter()
        .zip(hashes)
        .find(|(_disclosure, disclosure_hash)| hash == **disclosure_hash)
        .ok_or(FormatterError::MissingClaim)?;

    if disclosure.has_subdisclosures() {
        for subdisclosure in disclosure.get_subdisclosure_hashes()? {
            result.extend(resolve_disclosure_by_hash(
                &subdisclosure,
                disclosures,
                hashes,
            )?);
        }
    }

    result.push(disclosure.to_owned());
    Ok(result)
}

impl Disclosure {
    pub fn get_subdisclosure_hashes(&self) -> Result<Vec<String>, FormatterError> {
        if !self.has_subdisclosures() {
            Err(FormatterError::Failed(
                "current disclosure has no subdisclosures".to_string(),
            ))
        } else {
            let obj = serde_json::from_value::<SelectiveDisclosureArray>(self.value.to_owned())
                .map_err(|e| FormatterError::JsonMapping(e.to_string()))?;
            Ok(obj.sd)
        }
    }

    pub fn has_subdisclosures(&self) -> bool {
        self.value
            .as_object()
            .is_some_and(|obj| obj.contains_key(SELECTIVE_DISCLOSURE_MARKER))
    }

    pub fn hash_original_disclosure(&self, hasher: &dyn Hasher) -> Result<String, FormatterError> {
        hasher
            .hash_base64(self.original_disclosure.as_bytes())
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))
    }

    pub fn hash_b64_disclosure(&self, hasher: &dyn Hasher) -> Result<String, FormatterError> {
        hasher
            .hash_base64(self.base64_encoded_disclosure.as_bytes())
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

pub(crate) fn gather_disclosures(
    value: &serde_json::Value,
    algorithm: &str,
    crypto: &dyn CryptoProvider,
) -> Result<(Vec<String>, Vec<String>), FormatterError> {
    let hasher = crypto.get_hasher(algorithm)?;

    let value_as_object = value.as_object().ok_or(FormatterError::JsonMapping(
        "value is not an Object".to_string(),
    ))?;
    let mut disclosures = vec![];
    let mut hashed_disclosures = vec![];

    value_as_object.iter().try_for_each(|(k, v)| {
        match v {
            serde_json::Value::Array(array) => {
                let salt = one_crypto::utilities::generate_salt_base64_16();

                let value = serde_json::to_string(array)
                    .map_err(|e| FormatterError::JsonMapping(e.to_string()))?;

                let result = serde_json::to_string(&[&salt, k, &value])
                    .map_err(|e| FormatterError::JsonMapping(e.to_string()))?;

                let b64_encoded = string_to_b64url_string(&result)?;

                let hashed_disclosure = hasher
                    .hash_base64(result.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(b64_encoded);
                hashed_disclosures.push(hashed_disclosure);
            }
            serde_json::Value::Object(_object) => {
                let (subdisclosures, sd_hashes) = gather_disclosures(v, algorithm, crypto)?;
                disclosures.extend(subdisclosures);

                let salt = one_crypto::utilities::generate_salt_base64_16();

                let sd_hashes_json = serde_json::json!({
                    SELECTIVE_DISCLOSURE_MARKER: sd_hashes
                });
                let sd_disclosure = format!(
                    r#"["{salt}","{k}",{}]"#,
                    serde_json::to_string(&sd_hashes_json)
                        .map_err(|e| FormatterError::JsonMapping(e.to_string()))?
                );

                let sd_disclosure_as_b64 = string_to_b64url_string(&sd_disclosure)?;

                let hashed_subdisclosure = hasher
                    .hash_base64(sd_disclosure.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(sd_disclosure_as_b64);
                hashed_disclosures.push(hashed_subdisclosure);
            }
            serde_json::Value::String(value) => {
                let salt = one_crypto::utilities::generate_salt_base64_16();

                let result = serde_json::to_string(&[&salt, k, value])
                    .map_err(|e| FormatterError::JsonMapping(e.to_string()))?;

                let b64_encoded = string_to_b64url_string(&result)?;

                let hashed_disclosure: String = hasher
                    .hash_base64(result.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(b64_encoded);
                hashed_disclosures.push(hashed_disclosure);
            }
            serde_json::Value::Number(number) => {
                let salt = one_crypto::utilities::generate_salt_base64_16();

                let value = serde_json::to_string(number)
                    .map_err(|e| FormatterError::JsonMapping(e.to_string()))?;

                let result = serde_json::to_string(&[&salt, k, &value])
                    .map_err(|e| FormatterError::JsonMapping(e.to_string()))?;

                let b64_encoded = string_to_b64url_string(&result)?;

                let hashed_disclosure = hasher
                    .hash_base64(result.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(b64_encoded);
                hashed_disclosures.push(hashed_disclosure);
            }
            serde_json::Value::Bool(bool) => {
                let salt = one_crypto::utilities::generate_salt_base64_16();

                let value = serde_json::to_string(bool)
                    .map_err(|e| FormatterError::JsonMapping(e.to_string()))?;

                let result = serde_json::to_string(&[&salt, k, &value])
                    .map_err(|e| FormatterError::JsonMapping(e.to_string()))?;

                let b64_encoded = string_to_b64url_string(&result)?;

                let hashed_disclosure = hasher
                    .hash_base64(result.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(b64_encoded);
                hashed_disclosures.push(hashed_disclosure);
            }
            _ => {
                return Err(FormatterError::Failed(
                    "unsupported JSON variant".to_string(),
                ))
            }
        }

        Ok::<(), FormatterError>(())
    })?;

    Ok((disclosures, hashed_disclosures))
}

#[derive(Debug)]
struct DisclosureWithHash {
    pub disclosure: Disclosure,
    pub hash: String,
}

pub(crate) fn extract_claims_from_disclosures(
    disclosures: &[Disclosure],
    hasher: &dyn Hasher,
) -> Result<serde_json::Value, FormatterError> {
    let hashes_used_by_disclosures = gather_hashes_from_original_disclosures(disclosures, hasher)?;

    let all_disclosures: Vec<_> = hashes_used_by_disclosures
        .into_iter()
        .zip(disclosures)
        .map(|(hash, disclosure)| DisclosureWithHash {
            hash,
            disclosure: disclosure.to_owned(),
        })
        .collect();

    let root_disclosures: Vec<_> = all_disclosures
        .iter()
        .filter(|DisclosureWithHash { hash, .. }| {
            // root disclosures are those whose hash is not mentioned by any other disclosure
            !all_disclosures
                .iter()
                .any(|DisclosureWithHash { disclosure, .. }| {
                    disclosure.has_subdisclosures()
                        && disclosure
                            .get_subdisclosure_hashes()
                            .is_ok_and(|subdisclosures| subdisclosures.contains(hash))
                })
        })
        .collect();

    let mut object: serde_json::Map<String, serde_json::Value> = Default::default();
    for DisclosureWithHash { disclosure, .. } in root_disclosures {
        let value = extract_claim_value_from_disclosure(disclosure, &all_disclosures)?;
        object.insert(disclosure.key.to_owned(), value);
    }
    Ok(serde_json::Value::Object(object))
}

fn extract_claim_value_from_disclosure(
    disclosure: &Disclosure,
    all_disclosures: &[DisclosureWithHash],
) -> Result<serde_json::Value, FormatterError> {
    if disclosure.has_subdisclosures() {
        let subdisclosures = disclosure.get_subdisclosure_hashes()?;
        let mut object: serde_json::Map<String, serde_json::Value> = Default::default();
        for DisclosureWithHash { disclosure, .. } in all_disclosures
            .iter()
            .filter(|DisclosureWithHash { hash, .. }| subdisclosures.contains(hash))
        {
            let value = extract_claim_value_from_disclosure(disclosure, all_disclosures)?;
            object.insert(disclosure.key.to_owned(), value);
        }
        Ok(serde_json::Value::Object(object))
    } else {
        Ok(disclosure.value.to_owned())
    }
}

pub(crate) fn extract_disclosures(token: &str) -> Result<DecomposedToken, FormatterError> {
    let mut token_parts = token.split('~');
    let jwt = token_parts.next().ok_or(FormatterError::MissingPart)?;

    let disclosures_decoded_encoded: Vec<(String, String)> = token_parts
        .filter_map(|encoded| {
            let bytes = Base64UrlSafeNoPadding::decode_to_vec(encoded, None).ok()?;
            let decoded = String::from_utf8(bytes).ok()?;
            Some((decoded, encoded.to_owned()))
        })
        .collect();

    let deserialized_claims: Vec<Disclosure> = disclosures_decoded_encoded
        .into_iter()
        .filter_map(|(decoded, encoded)| parse_disclosure(&decoded, &encoded).ok())
        .collect();

    Ok(DecomposedToken {
        jwt,
        deserialized_disclosures: deserialized_claims,
    })
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(expecting = "expecting [<salt>, <key>, <value>] array")]
pub(crate) struct DisclosureArray {
    pub salt: String,
    pub key: String,
    pub value: serde_json::Value,
}

pub(crate) fn parse_disclosure(
    disclosure: &str,
    base64_encoded_disclosure: &str,
) -> Result<Disclosure, FormatterError> {
    let parsed: DisclosureArray =
        serde_json::from_str(disclosure).map_err(|e| FormatterError::Failed(e.to_string()))?;

    Ok(Disclosure {
        salt: parsed.salt,
        key: parsed.key,
        value: parsed.value,
        original_disclosure: disclosure.to_string(),
        base64_encoded_disclosure: base64_encoded_disclosure.to_string(),
    })
}

pub(crate) fn sort_published_claims_by_indices(claims: &[PublishedClaim]) -> Vec<PublishedClaim> {
    let mut claims = claims.to_owned();

    claims.sort_by(|a, b| {
        let splits_a = a.key.split(NESTED_CLAIM_MARKER);
        let splits_b = b.key.split(NESTED_CLAIM_MARKER);

        splits_a
            .zip(splits_b)
            .find_map(|(a, b)| {
                // Non equal segments means we don't care about anything that's after that
                if a == b {
                    return None;
                }

                let a_u64 = a.parse::<u64>();
                let b_u64 = b.parse::<u64>();
                if a_u64.is_err() || b_u64.is_err() {
                    return Some(Ordering::Equal);
                }

                let a_u64 = a_u64.unwrap();
                let b_u64 = b_u64.unwrap();

                // Equal indexes mean that we need to continue further
                if a_u64 == b_u64 {
                    return None;
                }

                Some(a_u64.cmp(&b_u64))
            })
            .unwrap_or(Ordering::Equal)
    });

    claims
}
