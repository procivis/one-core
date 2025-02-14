use std::collections::HashMap;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use sha2::{Digest, Sha256};

use super::JsonLdBbsplus;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld;
use crate::provider::credential_formatter::json_ld::model::DEFAULT_ALLOWED_CONTEXTS;
use crate::provider::credential_formatter::json_ld_bbsplus::base_proof::prepare_signature_input;
use crate::provider::credential_formatter::json_ld_bbsplus::model::{
    BbsDerivedProofComponents, BbsProofComponents, BbsProofType, CBOR_PREFIX_BASE,
    CBOR_PREFIX_DERIVED,
};
use crate::provider::credential_formatter::model::{
    DetailCredential, TokenVerifier, VerificationFn,
};
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmProof};
use crate::provider::key_algorithm::key::MultiMessageSignatureKeyHandle;

impl JsonLdBbsplus {
    pub(super) async fn verify(
        &self,
        credential: &str,
        verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        let mut vcdm: VcdmCredential = serde_json::from_str(credential).map_err(|e| {
            FormatterError::CouldNotVerify(format!("Could not deserialize base proof: {e}"))
        })?;

        if !json_ld::is_context_list_valid(
            &vcdm.context,
            self.params.allowed_contexts.as_ref(),
            &DEFAULT_ALLOWED_CONTEXTS,
            vcdm.credential_schema.as_ref(),
            vcdm.id.as_ref(),
        ) {
            return Err(FormatterError::CouldNotVerify(
                "Used context is not allowed".to_string(),
            ));
        }

        let Some(mut proof) = vcdm.proof.take() else {
            return Err(FormatterError::CouldNotVerify("Missing proof".to_string()));
        };
        proof.context = Some(vcdm.context.clone());

        let Some(proof_value) = proof.proof_value.take() else {
            return Err(FormatterError::CouldNotVerify(
                "Missing proof value".to_string(),
            ));
        };

        if proof.cryptosuite != "bbs-2023" {
            return Err(FormatterError::CouldNotVerify(
                "Incorrect cryptosuite".to_string(),
            ));
        }

        let canonical_proof_config =
            json_ld::canonize_any(&proof, self.caching_loader.to_owned()).await?;
        let proof_components = extract_proof_value_components(&proof_value)?;

        match proof_components {
            BbsProofType::BaseProof(proof_components) => {
                self.verify_base_proof(
                    vcdm,
                    proof,
                    proof_components,
                    canonical_proof_config,
                    verification,
                )
                .await
            }
            BbsProofType::DerivedProof(proof_components) => {
                self.verify_derived_proof(vcdm, proof_components, &proof, canonical_proof_config)
                    .await
            }
        }
    }

    async fn verify_base_proof(
        &self,
        vcdm: VcdmCredential,
        proof: VcdmProof,
        proof_components: BbsProofComponents,
        canonical_proof_config: String,
        verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        let canonical = json_ld::canonize_any(&vcdm, self.caching_loader.to_owned()).await?;
        let identifier_map = self.create_label_map(&canonical, &proof_components.hmac_key)?;

        let transformed = self.transform_canonical(&identifier_map, &canonical)?;
        let grouped = self.create_grouped_transformation(&transformed)?;
        let hash_data = self.prepare_proof_hashes(&canonical_proof_config, &grouped)?;

        let bbs_header = [
            hash_data.proof_config_hash.as_slice(),
            hash_data.mandatory_hash.as_slice(),
        ]
        .concat();

        if proof_components.bbs_header != bbs_header {
            return Err(FormatterError::CouldNotVerify(
                "Invalid bbs header".to_string(),
            ));
        }

        let signature_input = prepare_signature_input(bbs_header, &hash_data)?;
        let credential: DetailCredential = vcdm.try_into()?;
        verification
            .verify(
                credential.issuer_did.clone(),
                Some(&proof.verification_method),
                "BBS",
                &signature_input,
                &proof_components.bbs_signature,
            )
            .await
            .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))?;
        Ok(credential)
    }

    async fn verify_derived_proof(
        &self,
        vcdm: VcdmCredential,
        proof_components: BbsDerivedProofComponents,
        proof: &VcdmProof,
        canonical_proof_config: String,
    ) -> Result<DetailCredential, FormatterError> {
        let hashing_function = "sha-256";
        let hasher = self.crypto.get_hasher(hashing_function).map_err(|_| {
            FormatterError::CouldNotVerify(format!("Hasher {} unavailable", hashing_function))
        })?;

        let transformed_proof_config_hash = hasher
            .hash(canonical_proof_config.as_bytes())
            .map_err(|e| FormatterError::CouldNotVerify(format!("Hasher error: `{}`", e)))?;

        let label_map: HashMap<String, String> =
            decompress_label_map(&proof_components.compressed_label_map);

        // We are getting a string from normalization so we operate on it.
        let canonical_vcdm = json_ld::canonize_any(&vcdm, self.caching_loader.to_owned()).await?;

        let transformed = self.transform_canonical(&label_map, &canonical_vcdm)?;

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

        let mandatory_nquads_hash = mandatory_nquads
            .iter()
            .fold(Sha256::new(), |hasher, nquad| hasher.chain_update(nquad))
            .finalize()
            .to_vec();

        let bbs_header = [transformed_proof_config_hash, mandatory_nquads_hash].concat();

        let handle = self
            .get_public_signature_handle(&vcdm, &proof.verification_method)
            .await?;
        if let Err(error) = handle.public().verify_proof(
            Some(bbs_header),
            Some(
                non_mandatory_nquads
                    .into_iter()
                    .enumerate()
                    .map(|(i, value)| (proof_components.selective_indices[i], value.into_bytes()))
                    .collect(),
            ),
            Some(proof_components.presentation_header),
            &proof_components.bbs_proof,
        ) {
            return Err(FormatterError::CouldNotVerify(format!(
                "Could not verify proof: {error}"
            )));
        }

        vcdm.try_into()
    }

    async fn get_public_signature_handle(
        &self,
        vcdm: &VcdmCredential,
        method_id: &str,
    ) -> Result<MultiMessageSignatureKeyHandle, FormatterError> {
        let did_document = self
            .did_method_provider
            .resolve(&vcdm.issuer.to_did_value()?)
            .await
            .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))?;
        let algo_provider = self
            .key_algorithm_provider
            .key_algorithm_from_name("BBS_PLUS")
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

        algo_provider
            .parse_jwk(&verification_method.public_key_jwk)
            .map_err(|e| {
                FormatterError::CouldNotVerify(format!("Could not get public key from JWK: {e}"))
            })?
            .multi_message_signature()
            .ok_or(FormatterError::CouldNotVerify(
                "Missing multi-message signature key handle".to_string(),
            ))
            .cloned()
    }
}

fn decompress_label_map(compressed_label_map: &HashMap<usize, usize>) -> HashMap<String, String> {
    compressed_label_map
        .iter()
        .map(|(k, v)| (format!("_:c14n{k}"), format!("_:b{v}")))
        .collect()
}

fn extract_proof_value_components(proof_value: &str) -> Result<BbsProofType, FormatterError> {
    let Some(proof_value) = proof_value.strip_prefix('u') else {
        return Err(FormatterError::CouldNotVerify(
            "Only base64url multibase encoding is supported for proof".to_string(),
        ));
    };

    let proof_decoded = Base64UrlSafeNoPadding::decode_to_vec(proof_value, None)
        .map_err(|e| FormatterError::CouldNotVerify(format!("Base64url decoding failed: {}", e)))?;

    if let Some(proof_decoded) = proof_decoded.strip_prefix(&CBOR_PREFIX_BASE) {
        let components = ciborium::de::from_reader(proof_decoded).map_err(|e| {
            FormatterError::CouldNotVerify(format!("CBOR deserialization failed: {e}"))
        })?;
        return Ok(BbsProofType::BaseProof(components));
    };

    if let Some(proof_decoded) = proof_decoded.strip_prefix(&CBOR_PREFIX_DERIVED) {
        let components = ciborium::de::from_reader(proof_decoded).map_err(|e| {
            FormatterError::CouldNotVerify(format!("CBOR deserialization failed: {e}"))
        })?;
        return Ok(BbsProofType::DerivedProof(components));
    };

    Err(FormatterError::CouldNotVerify(
        "Expected proof prefix".to_string(),
    ))
}
