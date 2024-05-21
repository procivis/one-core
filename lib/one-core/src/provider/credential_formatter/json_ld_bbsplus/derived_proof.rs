use std::collections::{HashMap, HashSet};

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use itertools::Itertools;

use super::super::json_ld::model::LdCredential;
use super::super::model::CredentialPresentation;
use super::model::{GroupEntry, TransformedEntry};
use super::JsonLdBbsplus;
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::crypto::signer::bbs::{BBSSigner, BbsDeriveInput};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld;
use crate::provider::credential_formatter::json_ld_bbsplus::model::{
    BbsDerivedProofComponents, BbsProofComponents, CBOR_PREFIX_BASE, CBOR_PREFIX_DERIVED,
};
use crate::provider::credential_formatter::json_ld_bbsplus::remove_undisclosed_keys::remove_undisclosed_keys;

impl JsonLdBbsplus {
    pub(super) async fn derive_proof(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        let mut ld_credential: LdCredential =
            serde_json::from_str(&credential.token).map_err(|e| {
                FormatterError::CouldNotFormat(format!("Could not deserialize base proof: {e}"))
            })?;

        let Some(mut ld_proof) = ld_credential.proof.clone() else {
            return Err(FormatterError::CouldNotFormat("Missing proof".to_string()));
        };

        let Some(ld_proof_value) = &ld_proof.proof_value else {
            return Err(FormatterError::CouldNotFormat(
                "Missing proof value".to_string(),
            ));
        };

        if ld_proof.cryptosuite != "bbs-2023" {
            return Err(FormatterError::CouldNotFormat(
                "Incorrect cryptosuite".to_string(),
            ));
        }

        ld_credential.proof = None;

        let proof_components = extract_proof_value_components(ld_proof_value)?;

        let hmac_key = proof_components.hmac_key;

        // We are getting a string from normalization so we operate on it.
        let canonical =
            json_ld::canonize_any(&ld_credential, self.caching_loader.to_owned()).await?;

        let identifier_map = self.create_blank_node_identifier_map(&canonical, &hmac_key)?;

        let transformed = self.transform_canonical(&identifier_map, &canonical)?;

        let grouped = self.create_grouped_transformation(&transformed)?;

        let mandatory_indices: Vec<usize> = grouped
            .mandatory
            .value
            .iter()
            .map(|item| item.index)
            .collect();

        let non_mandatory_indices: Vec<usize> = grouped
            .non_mandatory
            .value
            .iter()
            .map(|item| item.index)
            .collect();

        let selective_indices =
            find_selective_indices(&grouped.non_mandatory, &credential.disclosed_keys)?;

        let mut combined_indices = mandatory_indices.clone();

        combined_indices.extend(&selective_indices);
        combined_indices.sort();

        let adjusted_mandatory_indices = adjust_indices(&mandatory_indices, &combined_indices)?;
        let adjusted_selective_indices =
            adjust_indices(&selective_indices, &non_mandatory_indices)?;

        let bbs_messages: Vec<(Vec<u8>, bool)> = grouped
            .non_mandatory
            .value
            .iter()
            .map(|entry| {
                (
                    entry.entry.as_bytes().to_vec(),
                    selective_indices.contains(&(entry.index)),
                )
            })
            .collect();

        let derive_input = BbsDeriveInput {
            header: proof_components.bbs_header,
            messages: bbs_messages,
            signature: proof_components.bbs_signature,
        };

        let bbs_proof = BBSSigner::derive_proof(&derive_input, &proof_components.public_key)
            .map_err(|e| {
                FormatterError::CouldNotExtractCredentials(format!("Could not derive proof: {e}"))
            })?;

        let mut revealed_document = ld_credential;

        // selectJsonLd - we just removed what's not disclosed. In our case
        // we can only disclose claims. The rest of the json is mandatory.
        remove_undisclosed_keys(&mut revealed_document, &credential.disclosed_keys)?;

        let revealed_transformed =
            json_ld::canonize_any(&revealed_document, self.caching_loader.to_owned()).await?;

        let compressed_verifier_label_map =
            create_compressed_verifier_label_map(&revealed_transformed, &identifier_map)?;

        let derived_proof_value = serialize_derived_proof_value(
            &bbs_proof,
            &compressed_verifier_label_map,
            &adjusted_mandatory_indices,
            &adjusted_selective_indices,
            &[],
        )?;

        ld_proof.proof_value = Some(derived_proof_value);

        revealed_document.proof = Some(ld_proof);

        let resp = serde_json::to_string(&revealed_document)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        Ok(resp)
    }
}

fn adjust_indices(
    indices: &[usize],
    adjustment_base: &[usize],
) -> Result<Vec<usize>, FormatterError> {
    indices
        .iter()
        .map(|index| {
            adjustment_base.iter().position(|i| i == index).ok_or(
                FormatterError::CouldNotExtractCredentials(
                    "Missing mandatory index in combined indices".to_owned(),
                ),
            )
        })
        .collect::<Result<_, _>>()
}

pub(super) fn serialize_derived_proof_value(
    bbs_proof: &[u8],
    compressed_verifier_label_map: &HashMap<usize, usize>,
    mandatory_indices: &[usize],
    selective_indices: &[usize],
    presentation_header: &[u8],
) -> Result<String, FormatterError> {
    let mut proof_value: Vec<u8> = CBOR_PREFIX_DERIVED.to_vec();

    let bbs_derive_components = BbsDerivedProofComponents {
        bbs_proof: bbs_proof.to_owned(),
        compressed_label_map: compressed_verifier_label_map.to_owned(),
        mandatory_indices: mandatory_indices.to_vec(),
        selective_indices: selective_indices.to_vec(),
        presentation_header: presentation_header.to_owned(),
    };

    let mut cbor_components = Vec::new();
    ciborium::ser::into_writer(&bbs_derive_components, &mut cbor_components)
        .map_err(|e| FormatterError::CouldNotFormat(format!("CBOR serialization failed: {}", e)))?;

    proof_value.append(&mut cbor_components);

    // For multibase output
    let b64proof = Base64UrlSafeNoPadding::encode_to_string(proof_value).map_err(|e| {
        FormatterError::CouldNotExtractCredentials(format!("To base64url serialization error: {e}"))
    })?;
    Ok(format!("u{}", b64proof))
}

fn create_compressed_verifier_label_map(
    revealed_transformed: &str,
    identifier_map: &HashMap<String, String>,
) -> Result<HashMap<usize, usize>, FormatterError> {
    let mut verifier_label_map: HashMap<usize, usize> = HashMap::new();

    for line in revealed_transformed.lines() {
        let mut split = line.split(' ');
        let subject = split
            .next()
            .ok_or(FormatterError::CouldNotExtractCredentials(
                "Missing triple subject".to_owned(),
            ))?;
        if subject.starts_with("_:") {
            let original_key = subject;
            let key = original_key
                .strip_prefix("_:c14n")
                .ok_or(FormatterError::CouldNotExtractCredentials(
                    "Invalid label identifier".to_owned(),
                ))?
                .parse::<usize>()
                .map_err(|_| {
                    FormatterError::CouldNotExtractCredentials(
                        "Could not parse label number".to_owned(),
                    )
                })?;
            let original_value = identifier_map.get(original_key).ok_or(
                FormatterError::CouldNotExtractCredentials(
                    "Missing mapped label identifier".to_string(),
                ),
            )?;
            let value = original_value
                .strip_prefix("_:b")
                .ok_or(FormatterError::CouldNotExtractCredentials(
                    "Incorrect label identifier".to_owned(),
                ))?
                .parse::<usize>()
                .map_err(|_| {
                    FormatterError::CouldNotExtractCredentials(
                        "Could not parse label number".to_owned(),
                    )
                })?;
            verifier_label_map.insert(key, value);
        }
    }
    Ok(verifier_label_map)
}

//It's all linear search but that should be ok for the expected sets of data
pub(super) fn find_selective_indices(
    non_mandatory: &TransformedEntry,
    disclosed_keys: &[String],
) -> Result<Vec<usize>, FormatterError> {
    if non_mandatory.value.is_empty() {
        // Nothing to disclose
        return Ok(vec![]);
    }

    let entries = non_mandatory.value.as_ref();

    // Parent object is child subject
    let (root_object, root_index) = find_root_object(entries)?;

    let mut indices: HashSet<usize> = HashSet::from_iter(vec![root_index]);

    for disclosed_key in disclosed_keys {
        let disclosed_indices = traverse_and_collect(Some(disclosed_key), root_object, entries)?;
        indices.extend(disclosed_indices)
    }

    Ok(indices.into_iter().collect_vec())
}

fn traverse_and_collect(
    key: Option<&str>,
    subject: &str,
    entries: &[GroupEntry],
) -> Result<HashSet<usize>, FormatterError> {
    match key {
        Some(key) => {
            if key.contains(NESTED_CLAIM_MARKER) {
                let (key, carry_over_key) = key
                    .split_once(NESTED_CLAIM_MARKER)
                    .ok_or(FormatterError::Failed("Invalid key format".to_string()))?;

                let this_entry = find_with_predicate(key, subject, entries)?;
                let this_triple = to_triple(this_entry.entry.as_ref())?;

                let mut indices =
                    traverse_and_collect(Some(carry_over_key), this_triple.object, entries)?;

                indices.insert(this_entry.index);

                Ok(indices)
            } else {
                let last_entry = find_with_predicate(key, subject, entries)?;
                let last_triple = to_triple(last_entry.entry.as_ref())?;

                //No collect all children because it may by an object
                let mut indices = traverse_and_collect(None, last_triple.object, entries)?;

                indices.insert(last_entry.index);
                Ok(indices)
            }
        }
        None => {
            // In case we asked for an object we need to collect all it's chidren and their children.
            let children = find_all_children(subject, entries)?;

            let mut collected_indices = HashSet::new();

            for child in &children {
                let entry_triple = to_triple(child.entry.as_ref())?;
                let child_indices = traverse_and_collect(None, entry_triple.object, entries)?;
                collected_indices.extend(child_indices);
            }

            collected_indices.extend(children.into_iter().map(|entry| entry.index));

            Ok(collected_indices)
        }
    }
}

fn find_all_children<'a>(
    subject: &'a str,
    entries: &'a [GroupEntry],
) -> Result<Vec<&'a GroupEntry>, FormatterError> {
    let result = entries
        .iter()
        .filter(|entry| {
            if let Ok(triple) = to_triple(entry.entry.as_ref()) {
                triple.subject == subject
            } else {
                false
            }
        })
        .collect();
    Ok(result)
}

fn find_with_predicate<'a>(
    key: &str,
    subject: &'a str,
    entries: &'a [GroupEntry],
) -> Result<&'a GroupEntry, FormatterError> {
    entries
        .iter()
        .find(|entry| {
            if let Ok(triple) = to_triple(entry.entry.as_ref()) {
                triple.subject == subject && triple.predicate.ends_with(&["#", key, ">"].concat())
            } else {
                false
            }
        })
        .ok_or(FormatterError::Failed(
            "Could not find credential subject".to_string(),
        ))
}

fn find_root_object(entries: &[GroupEntry]) -> Result<(&str, usize), FormatterError> {
    entries
        .iter()
        .find_map(|entry| {
            if let Ok(triple) = to_triple(entry.entry.as_ref()) {
                if triple.subject.starts_with("<did:") {
                    return Some((triple.object, entry.index));
                }
            }
            None
        })
        .ok_or(FormatterError::Failed(
            "Could not find credential subject".to_string(),
        ))
}

struct Triple<'a> {
    pub subject: &'a str,
    pub predicate: &'a str,
    pub object: &'a str,
}

fn to_triple(line: &str) -> Result<Triple, FormatterError> {
    let mut split = line.split(' ');
    let subject = split
        .next()
        .ok_or(FormatterError::CouldNotExtractCredentials(
            "Missing triple subject".to_owned(),
        ))?;
    let predicate = split
        .next()
        .ok_or(FormatterError::CouldNotExtractCredentials(
            "Missing triple predicate".to_owned(),
        ))?;
    let object = split
        .next()
        .ok_or(FormatterError::CouldNotExtractCredentials(
            "Missing triple object".to_owned(),
        ))?;
    Ok(Triple {
        subject,
        predicate,
        object,
    })
}

fn extract_proof_value_components(proof_value: &str) -> Result<BbsProofComponents, FormatterError> {
    if !proof_value.starts_with('u') {
        return Err(FormatterError::CouldNotExtractCredentials(
            "Only base64url multibase encoding is supported for proof".to_string(),
        ));
    }

    let proof_decoded = Base64UrlSafeNoPadding::decode_to_vec(
        proof_value.bytes().skip(1).collect::<Vec<u8>>(),
        None,
    )
    .map_err(|e| FormatterError::CouldNotFormat(format!("Base64url decoding failed: {}", e)))?;

    if proof_decoded.as_slice()[0..3] != CBOR_PREFIX_BASE {
        return Err(FormatterError::CouldNotExtractCredentials(
            "Expected base proof prefix".to_string(),
        ));
    }

    let components: BbsProofComponents = ciborium::de::from_reader(&proof_decoded.as_slice()[3..])
        .map_err(|e| {
            FormatterError::CouldNotExtractCredentials(format!(
                "CBOR deserialization failed: {}",
                e
            ))
        })?;

    verify_proof_components(&components)?;

    Ok(components)
}

fn verify_proof_components(components: &BbsProofComponents) -> Result<(), FormatterError> {
    if components.bbs_signature.len() != 80 {
        return Err(FormatterError::CouldNotFormat(
            "Incorrect signature length".to_string(),
        ));
    }

    if components.bbs_header.len() != 64 {
        return Err(FormatterError::CouldNotFormat(
            "Incorrect signature length".to_string(),
        ));
    }

    if components.public_key.len() != 96 {
        return Err(FormatterError::CouldNotFormat(
            "Incorrect signature length".to_string(),
        ));
    }

    Ok(())
}
