use std::collections::HashMap;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};

use super::super::json_ld::model::LdCredential;
use super::super::model::CredentialPresentation;
use super::model::TransformedEntry;
use super::JsonLdBbsplus;
use crate::crypto::signer::bbs::{BBSSigner, BbsDeriveInput};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld;
use crate::provider::credential_formatter::json_ld_bbsplus::model::{
    BbsDerivedProofComponents, BbsProofComponents, CBOR_PREFIX_BASE, CBOR_PREFIX_DERIVED,
};

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
        let canonical = json_ld::canonize_any(&ld_credential).await?;

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
        remove_undisclosed_keys(&mut revealed_document, &credential.disclosed_keys);

        let revealed_transformed = json_ld::canonize_any(&revealed_document).await?;

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

    let mut cbor_components = serde_cbor::to_vec(&bbs_derive_components).map_err(|e| {
        FormatterError::CouldNotExtractCredentials(format!("CBOR serialization failed: {}", e))
    })?;
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

// This is simplified implementation that only works with our jsonld format
fn find_selective_indices(
    non_mandatory: &TransformedEntry,
    disclosed_keys: &[String],
) -> Result<Vec<usize>, FormatterError> {
    let mut indices: Vec<usize> = Vec::new();

    // This is also a simplified implementation
    for entry in &non_mandatory.value {
        let mut parts = entry.entry.split(' ');

        let _subject: &str = parts
            .next()
            .ok_or(FormatterError::CouldNotExtractCredentials(
                "Missing triple subject".to_owned(),
            ))?;
        let predicate = parts
            .next()
            .ok_or(FormatterError::CouldNotExtractCredentials(
                "Missing triple predicate".to_owned(),
            ))?;
        let object = parts
            .next()
            .ok_or(FormatterError::CouldNotExtractCredentials(
                "Missing triple object".to_owned(),
            ))?;

        // Store root element
        if object.starts_with("_:") {
            indices.push(entry.index);
            continue;
        }

        // Find out if a key is disclosed.
        for key in disclosed_keys {
            if predicate.contains(&format!("#{}", key)) {
                indices.push(entry.index);
            }
        }
    }

    Ok(indices)
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

    let components: BbsProofComponents = serde_cbor::from_slice(&proof_decoded.as_slice()[3..])
        .map_err(|e| {
            FormatterError::CouldNotExtractCredentials(format!(
                "CBOR deserialization failed: {}",
                e
            ))
        })?;

    verify_proof_components(&components)?;

    Ok(components)
}

fn remove_undisclosed_keys(revealed_ld: &mut LdCredential, disclosed_keys: &[String]) {
    for values in revealed_ld.credential_subject.subject.values_mut() {
        values.retain(|k, _| disclosed_keys.contains(k));
    }
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
