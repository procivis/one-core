use std::collections::HashMap;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};

use super::super::json_ld::model::LdCredential;
use super::JsonLdBbsplus;
use crate::crypto::signer::bbs::{BBSSigner, BbsProofInput};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld;
use crate::provider::credential_formatter::json_ld_bbsplus::model::{
    BbsDerivedProofComponents, CBOR_PREFIX_DERIVED,
};
use crate::provider::credential_formatter::model::{DetailCredential, VerificationFn};

impl JsonLdBbsplus {
    pub(super) async fn verify(
        &self,
        credential: &str,
        _verification_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        let mut ld_credential: LdCredential = serde_json::from_str(credential).map_err(|e| {
            FormatterError::CouldNotVerify(format!("Could not deserialize base proof: {e}"))
        })?;

        let Some(mut ld_proof) = ld_credential.proof.clone() else {
            return Err(FormatterError::CouldNotVerify("Missing proof".to_string()));
        };

        let Some(ld_proof_value) = &ld_proof.proof_value.clone() else {
            return Err(FormatterError::CouldNotVerify(
                "Missing proof value".to_string(),
            ));
        };

        if ld_proof.cryptosuite != "bbs-2023" {
            return Err(FormatterError::CouldNotVerify(
                "Incorrect cryptosuite".to_string(),
            ));
        }

        ld_credential.proof = None;
        ld_proof.proof_value = None;

        let canonical_proof_config =
            json_ld::canonize_any(&ld_proof, self.caching_loader.to_owned()).await?;

        let hashing_function = "sha-256";
        let hasher = self.crypto.get_hasher(hashing_function).map_err(|_| {
            FormatterError::CouldNotVerify(format!("Hasher {} unavailable", hashing_function))
        })?;

        let transformed_proof_config_hash = hasher
            .hash(canonical_proof_config.as_bytes())
            .map_err(|e| FormatterError::CouldNotVerify(format!("Hasher error: `{}`", e)))?;

        let proof_components = extract_proof_value_components(ld_proof_value)?;

        let identifier_map: HashMap<String, String> =
            decompress_label_map(&proof_components.compressed_label_map);

        // We are getting a string from normalization so we operate on it.
        let canonical =
            json_ld::canonize_any(&ld_credential, self.caching_loader.to_owned()).await?;

        let transformed = self.transform_canonical(&identifier_map, &canonical)?;

        let mut mandatory_nquads: Vec<String> = Vec::new();
        let mut non_mandatory_nquads: Vec<String> = Vec::new();

        transformed
            .into_iter()
            .enumerate()
            .for_each(|(index, item)| {
                if proof_components.mandatory_indices.contains(&(index)) {
                    mandatory_nquads.push(item)
                } else {
                    non_mandatory_nquads.push(item)
                }
            });

        let joined_mandatory_nquads = mandatory_nquads.concat();

        let mandatory_nquads_hash = hasher
            .hash(joined_mandatory_nquads.as_bytes())
            .map_err(|e| FormatterError::CouldNotVerify(format!("Hasher error: `{}`", e)))?;

        let bbs_header = [transformed_proof_config_hash, mandatory_nquads_hash].concat();

        let public_key = self
            .get_public_key(&ld_credential, &ld_proof.verification_method)
            .await?;

        let verify_proof_input = BbsProofInput {
            header: bbs_header,
            presentation_header: None,
            proof: proof_components.bbs_proof,
            messages: non_mandatory_nquads
                .into_iter()
                .enumerate()
                .map(|(i, value)| {
                    (
                        proof_components.selective_indices[i],
                        value.as_bytes().to_vec(),
                    )
                })
                .collect(),
        };

        let _ = BBSSigner::verify_proof(&verify_proof_input, &public_key)
            .map_err(|e| FormatterError::CouldNotVerify(format!("Could not verify proof: {e}")));

        ld_credential.try_into()
    }

    async fn get_public_key(
        &self,
        ld_credential: &LdCredential,
        method_id: &str,
    ) -> Result<Vec<u8>, FormatterError> {
        let did_document = self
            .did_method_provider
            .resolve(&ld_credential.issuer.to_did_value())
            .await
            .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))?;
        let algo_provider = self
            .key_algorithm_provider
            .get_key_algorithm("BBS_PLUS")
            .ok_or(FormatterError::CouldNotVerify(
                "Missing BBS_PLUS algorithm".to_owned(),
            ))?;

        let verification_method = if let Some(multikey) = did_document
            .verification_method
            .iter()
            .find(|vm| vm.id == method_id)
        {
            multikey
        } else {
            did_document
                .verification_method
                .first()
                .ok_or(FormatterError::Failed("Missing issuer key".to_string()))?
        };

        let public_key = algo_provider
            .jwk_to_bytes(&verification_method.public_key_jwk)
            .map_err(|e| {
                FormatterError::CouldNotVerify(format!("Could not get public key from JWK: {e}"))
            })?;
        Ok(public_key)
    }
}

fn decompress_label_map(compressed_label_map: &HashMap<usize, usize>) -> HashMap<String, String> {
    compressed_label_map
        .iter()
        .map(|(k, v)| (format!("_:c14n{k}"), format!("_:b{v}")))
        .collect()
}

fn extract_proof_value_components(
    proof_value: &str,
) -> Result<BbsDerivedProofComponents, FormatterError> {
    if !proof_value.starts_with('u') {
        return Err(FormatterError::CouldNotVerify(
            "Only base64url multibase encoding is supported for proof".to_string(),
        ));
    }

    let proof_decoded = Base64UrlSafeNoPadding::decode_to_vec(
        proof_value.bytes().skip(1).collect::<Vec<u8>>(),
        None,
    )
    .map_err(|e| FormatterError::CouldNotVerify(format!("Base64url decoding failed: {}", e)))?;

    if proof_decoded.as_slice()[0..3] != CBOR_PREFIX_DERIVED {
        return Err(FormatterError::CouldNotVerify(
            "Expected base proof prefix".to_string(),
        ));
    }

    let components: BbsDerivedProofComponents =
        ciborium::de::from_reader(&proof_decoded.as_slice()[3..]).map_err(|e| {
            FormatterError::CouldNotVerify(format!("CBOR deserialization failed: {}", e))
        })?;

    Ok(components)
}
