use std::collections::HashMap;

use one_crypto::Hasher;
use serde_json::Value;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::mapper::string_to_b64url_string;
use crate::provider::credential_formatter::sdjwt::disclosures::SELECTIVE_DISCLOSURE_MARKER;
use crate::provider::credential_formatter::sdjwt::model::Disclosure;

pub(super) fn extract_claims_from_disclosures(
    disclosures: &[Disclosure],
    mut public_claims: HashMap<String, Value>,
    selective_disclosure_hashes: &[String],
    hasher: &dyn Hasher,
) -> Result<Value, FormatterError> {
    let disclosures = disclosures
        .iter()
        .map(|disclosure| Ok((disclosure, disclosure.hash_b64_disclosure(hasher)?)))
        .collect::<Result<Vec<(&Disclosure, String)>, FormatterError>>()?;

    selective_disclosure_hashes.iter().for_each(|hash| {
        if let Some((disclosure, _)) = disclosures
            .iter()
            .find(|(_, disclosure_hash)| *hash == *disclosure_hash)
        {
            public_claims.insert(disclosure.key.clone(), disclosure.value.clone());
        }
    });

    let mut result = public_claims.into_iter().collect();
    recursively_expand_disclosures(&disclosures, &mut result);

    Ok(result)
}

fn recursively_expand_disclosures(disclosures: &[(&Disclosure, String)], claims: &mut Value) {
    if let Some(map) = claims.as_object_mut() {
        let values = gather_insertables_from_value(disclosures, map);

        map.remove(SELECTIVE_DISCLOSURE_MARKER);
        map.extend(values);

        map.iter_mut().for_each(|(_, v)| {
            recursively_expand_disclosures(disclosures, v);
        });
    }
}

fn gather_hashes_from_sd(sd: &Value) -> Option<Vec<String>> {
    sd.as_array().map(|array| {
        array
            .iter()
            .filter_map(|hash| hash.as_str().map(str::to_string))
            .collect()
    })
}

fn gather_disclosures_from_sd(
    disclosures: &[(&Disclosure, String)],
    sd_hashes: &[String],
) -> serde_json::Map<String, Value> {
    let mut result = serde_json::Map::new();

    sd_hashes.iter().for_each(|hash| {
        if let Some((disclosure, _)) = disclosures
            .iter()
            .find(|(_, disclosure_hash)| *hash == *disclosure_hash)
        {
            result.insert(disclosure.key.clone(), disclosure.value.clone());
        }
    });

    result
}

fn gather_insertables_from_value(
    disclosures: &[(&Disclosure, String)],
    map: &serde_json::Map<String, Value>,
) -> serde_json::Map<String, Value> {
    if let Some(sd) = map.get(SELECTIVE_DISCLOSURE_MARKER) {
        if let Some(hashes) = gather_hashes_from_sd(sd) {
            return gather_disclosures_from_sd(disclosures, &hashes);
        }
    }

    Default::default()
}

/*
 * This function is almost direct copy of SD-JWT's gather_disclosures,
 * but it uses base64 encoded disclosures for hashing, SD-JWT uses
 * non-encoded disclosures. Reason for this is that our SD-JWT implementation
 * is based on Draft 5, while SD-JWT VC is based on newer draft of SD-JWT
 */
pub(crate) fn gather_disclosures(
    value: &serde_json::Value,
    hasher: &dyn Hasher,
) -> Result<(Vec<String>, Vec<String>), FormatterError> {
    let object = value.as_object().ok_or(FormatterError::JsonMapping(
        "value is not an Object".to_string(),
    ))?;
    let mut disclosures = vec![];
    let mut hashed_disclosures = vec![];

    for (key, value) in object {
        match value {
            serde_json::Value::Object(_) => {
                let (nested_disclosures, nested_sd_hashes) = gather_disclosures(value, hasher)?;
                disclosures.extend(nested_disclosures);

                let nested_sd = serde_json::json!({
                    SELECTIVE_DISCLOSURE_MARKER: nested_sd_hashes
                });
                let disclosure = compute_disclosure(key, &nested_sd)?;

                let hashed_disclosure = hasher
                    .hash_base64(disclosure.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(disclosure);
                hashed_disclosures.push(hashed_disclosure);
            }

            _ => {
                let disclosure = compute_disclosure(key, value)?;

                let hashed_disclosure = hasher
                    .hash_base64(disclosure.as_bytes())
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                disclosures.push(disclosure);
                hashed_disclosures.push(hashed_disclosure);
            }
        }
    }

    Ok((disclosures, hashed_disclosures))
}

fn compute_disclosure(key: &str, value: &Value) -> Result<String, FormatterError> {
    let salt = one_crypto::utilities::generate_salt_base64_16();

    let array = serde_json::json!([salt, key, value]).to_string();

    string_to_b64url_string(&array)
}
