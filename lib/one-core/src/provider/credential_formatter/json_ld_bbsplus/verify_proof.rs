use super::{JsonLdBbsplus, data_integrity};
use crate::config::core_config::KeyAlgorithmType;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::VerificationFn;
use crate::provider::credential_formatter::vcdm::VcdmCredential;
use crate::provider::key_algorithm::key::MultiMessageSignatureKeyHandle;
use crate::util::rdf_canonization::json_ld_processor_options;
use crate::util::vcdm_jsonld_contexts::is_context_list_valid;

impl JsonLdBbsplus {
    /// Verifies the proof of the credential. To do so the proof must be removed from the
    /// credential. This function is given a mutable reference to avoid cloning the whole thing.
    /// Returns the list of mandatory pointers if the proof is valid.
    pub(super) async fn verify(
        &self,
        vcdm: &mut VcdmCredential,
        verification: VerificationFn,
    ) -> Result<Option<Vec<String>>, FormatterError> {
        is_context_list_valid(
            &vcdm.context,
            self.params.allowed_contexts.as_ref(),
            vcdm.credential_schema.as_ref(),
            vcdm.id.as_ref(),
        )?;

        let Some(mut proof) = vcdm.proof.take() else {
            return Err(FormatterError::CouldNotVerify("Missing proof".to_string()));
        };
        proof.context = Some(vcdm.context.clone());

        let Some(proof_value) = &proof.proof_value else {
            return Err(FormatterError::CouldNotVerify(
                "Missing proof value".to_string(),
            ));
        };

        if proof.cryptosuite != "bbs-2023" {
            return Err(FormatterError::CouldNotVerify(
                "Incorrect cryptosuite".to_string(),
            ));
        }

        let hasher = self
            .crypto
            .get_hasher("sha-256")
            .map_err(|_| FormatterError::CouldNotVerify("SHA256 hasher unavailable".to_string()))?;

        let mandatory_pointers = match proof_type(proof_value)? {
            ProofType::Base => {
                let mandatory_pointers = data_integrity::verify_base_proof(
                    vcdm,
                    proof,
                    &self.caching_loader,
                    &*hasher,
                    &*verification,
                    json_ld_processor_options(),
                )
                .await?
                .mandatory_pointers;
                Some(mandatory_pointers)
            }
            ProofType::Derived => {
                let handle = self
                    .get_public_signature_handle(vcdm, &proof.verification_method)
                    .await?;
                let public_key = handle.public().as_raw();

                data_integrity::verify_derived_proof(
                    vcdm,
                    proof,
                    &public_key,
                    &self.caching_loader,
                    &*hasher,
                    json_ld_processor_options(),
                )
                .await?;
                // mandatory pointers not easily visible on verifier side,
                // so skipping marking the disclosability of claims
                None
            }
        };
        Ok(mandatory_pointers)
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
            .key_algorithm_from_type(KeyAlgorithmType::BbsPlus)
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

enum ProofType {
    Base,
    Derived,
}

fn proof_type(proof_value: &str) -> Result<ProofType, FormatterError> {
    match proof_value {
        v if v.starts_with("u2V0C") => Ok(ProofType::Base),
        v if v.starts_with("u2V0D") => Ok(ProofType::Derived),
        _ => Err(FormatterError::CouldNotVerify(
            "Invalid proof value prefix or unsupported proof feature".to_string(),
        )),
    }
}

pub(super) fn extract_mandatory_pointers(
    vc: &VcdmCredential,
) -> Result<Option<Vec<String>>, FormatterError> {
    let Some(base_proof) = &vc.proof else {
        return Ok(None);
    };

    let Some(proof_value) = &base_proof.proof_value else {
        return Ok(None);
    };

    Ok(match proof_type(proof_value)? {
        ProofType::Base => {
            Some(data_integrity::parse_base_proof_value(proof_value)?.mandatory_pointers)
        }
        ProofType::Derived => None,
    })
}
