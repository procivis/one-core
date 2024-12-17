use std::collections::HashMap;

use one_crypto::Hasher;
use serde_json::Value;

use crate::provider::credential_formatter::error::FormatterError;
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
        .map(|disclosure| Ok((disclosure, disclosure.hash_disclosure(hasher)?)))
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
