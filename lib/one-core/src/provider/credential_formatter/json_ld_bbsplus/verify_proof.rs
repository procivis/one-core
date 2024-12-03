use std::collections::HashMap;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_crypto::signer::bbs::{BBSSigner, BbsProofInput};
use sha2::Sha256;

use super::super::json_ld::model::LdCredential;
use super::JsonLdBbsplus;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld;
use crate::provider::credential_formatter::json_ld::model::{LdProof, DEFAULT_ALLOWED_CONTEXTS};
use crate::provider::credential_formatter::json_ld_bbsplus::base_proof::prepare_signature_input;
use crate::provider::credential_formatter::json_ld_bbsplus::model::{
    BbsDerivedProofComponents, BbsProofComponents, BbsProofType, CBOR_PREFIX_BASE,
    CBOR_PREFIX_DERIVED,
};
use crate::provider::credential_formatter::model::{
    DetailCredential, TokenVerifier, VerificationFn,
};

impl JsonLdBbsplus {
    pub(super) async fn verify(
        &self,
        credential: &str,
        verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        let mut ld_credential: LdCredential = serde_json::from_str(credential).map_err(|e| {
            FormatterError::CouldNotVerify(format!("Could not deserialize base proof: {e}"))
        })?;

        if !json_ld::is_context_list_valid(
            &ld_credential.context,
            self.params.allowed_contexts.as_ref(),
            &DEFAULT_ALLOWED_CONTEXTS,
            ld_credential.credential_schema.as_ref(),
            ld_credential.id.as_ref(),
        ) {
            return Err(FormatterError::CouldNotVerify(
                "Used context is not allowed".to_string(),
            ));
        }

        let Some(mut ld_proof) = ld_credential.proof.take() else {
            return Err(FormatterError::CouldNotVerify("Missing proof".to_string()));
        };
        ld_proof.context = Some(ld_credential.context.clone());

        let Some(ld_proof_value) = ld_proof.proof_value.take() else {
            return Err(FormatterError::CouldNotVerify(
                "Missing proof value".to_string(),
            ));
        };

        if ld_proof.cryptosuite != "bbs-2023" {
            return Err(FormatterError::CouldNotVerify(
                "Incorrect cryptosuite".to_string(),
            ));
        }

        let canonical_proof_config =
            json_ld::canonize_any(&ld_proof, self.caching_loader.to_owned()).await?;
        let proof_components = extract_proof_value_components(&ld_proof_value)?;

        match proof_components {
            BbsProofType::BaseProof(proof_components) => {
                self.verify_base_proof(
                    ld_credential,
                    ld_proof,
                    proof_components,
                    canonical_proof_config,
                    verification,
                )
                .await
            }
            BbsProofType::DerivedProof(proof_components) => {
                self.verify_derived_proof(
                    ld_credential,
                    proof_components,
                    &ld_proof,
                    canonical_proof_config,
                )
                .await
            }
        }
    }

    async fn verify_base_proof(
        &self,
        ld_credential: LdCredential,
        ld_proof: LdProof,
        proof_components: BbsProofComponents,
        canonical_proof_config: String,
        verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        let canonical =
            json_ld::canonize_any(&ld_credential, self.caching_loader.to_owned()).await?;
        let identifier_map =
            self.create_blank_node_identifier_map(&canonical, &proof_components.hmac_key)?;

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
        let credential: DetailCredential = ld_credential.try_into()?;
        verification
            .verify(
                credential.issuer_did.clone(),
                Some(&ld_proof.verification_method),
                "BBS_PLUS",
                &signature_input,
                &proof_components.bbs_signature,
            )
            .await
            .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))?;
        Ok(credential)
    }

    async fn verify_derived_proof(
        &self,
        ld_credential: LdCredential,
        proof_components: BbsDerivedProofComponents,
        ld_proof: &LdProof,
        canonical_proof_config: String,
    ) -> Result<DetailCredential, FormatterError> {
        let hashing_function = "sha-256";
        let hasher = self.crypto.get_hasher(hashing_function).map_err(|_| {
            FormatterError::CouldNotVerify(format!("Hasher {} unavailable", hashing_function))
        })?;

        let transformed_proof_config_hash = hasher
            .hash(canonical_proof_config.as_bytes())
            .map_err(|e| FormatterError::CouldNotVerify(format!("Hasher error: `{}`", e)))?;

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

        use sha2::Digest;
        let mut h = Sha256::new();
        for quad in mandatory_nquads {
            h.update(quad.as_bytes());
        }
        let mandatory_nquads_hash = h.finalize().to_vec();

        let bbs_header = [transformed_proof_config_hash, mandatory_nquads_hash].concat();

        let public_key = self
            .get_public_key(&ld_credential, &ld_proof.verification_method)
            .await?;

        let verify_proof_input = BbsProofInput {
            header: bbs_header,
            presentation_header: Some(proof_components.presentation_header),
            proof: proof_components.bbs_proof,
            messages: non_mandatory_nquads
                .into_iter()
                .enumerate()
                .map(|(i, value)| (proof_components.selective_indices[i], value.into_bytes()))
                .collect(),
        };

        if let Err(error) = BBSSigner::verify_proof(&verify_proof_input, &public_key) {
            return Err(FormatterError::CouldNotVerify(format!(
                "Could not verify proof: {error}"
            )));
        }

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
