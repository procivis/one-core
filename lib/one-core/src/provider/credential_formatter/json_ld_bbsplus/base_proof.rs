use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::vec;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use shared_types::DidValue;

use crate::crypto::signer::bbs::BbsInput;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld_bbsplus::model::BbsProofComponents;
use crate::provider::credential_formatter::model::CredentialStatus;
use crate::provider::credential_formatter::{json_ld, CredentialData};
use crate::provider::did_method::dto::{DidDocumentDTO, PublicKeyJwkDTO};

use super::model::{GroupedFormatDataDocument, HashData, CBOR_PREFIX_BASE};

use super::{mapper, AuthenticationFn, JsonLdBbsplus};

#[allow(clippy::too_many_arguments)]
impl JsonLdBbsplus {
    pub(super) async fn format(
        &self,
        credential: CredentialData,
        holder_did: &DidValue,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
        json_ld_context_url: Option<String>,
        custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError> {
        if algorithm != "BBS_PLUS" {
            return Err(FormatterError::BBSOnly);
        }

        let issuer_did = &credential.issuer_did;

        // We only do that to get public key here.
        let did_document = self
            .did_method_provider
            .resolve(issuer_did)
            .await
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        let _ = allow_bbs_key_only(&did_document);

        // Those fields have to be presented by holder for verifier.
        // It's not the same as 'required claim' for issuance.
        // Here we add everything that is mandatory which is everything except CredentialSubject.
        let mandatory_pointers = prepare_mandatory_pointers(&credential.status);

        let mut ld_credential = json_ld::prepare_credential(
            credential,
            holder_did,
            additional_context,
            additional_types,
            json_ld_context_url,
            custom_subject_name,
        )?;

        let hmac_key = self.crypto.generate_bytes(32);

        // We are getting a string from normalization so we operate on it.
        let canonical = json_ld::canonize_any(&ld_credential).await?;

        let identifier_map = self.create_blank_node_identifier_map(&canonical, &hmac_key)?;

        let transformed = self.transform_canonical(&identifier_map, &canonical)?;

        let grouped = self.create_grouped_transformation(&transformed)?;

        let mut proof_config = json_ld::prepare_proof_config(
            "authentication",
            "bbs-2023",
            ld_credential.context.clone(),
            &did_document,
        )
        .await?;

        let canonical_proof_config = json_ld::canonize_any(&proof_config).await?;

        let hash_data = self.prepare_proof_hashes(&canonical_proof_config, &grouped)?;

        let algorithm = self
            .key_algorithm_provider
            .get_key_algorithm("BBS_PLUS")
            .ok_or(FormatterError::CouldNotFormat(
                "Missing BBS_PLUS key algorithm".to_owned(),
            ))?;

        // FIXME This could be safely done when when AuthenticationFn object is initialized. We could have a mismatch here.
        let public_key_bytes = algorithm
            .jwk_to_bytes(&did_document.verification_method[0].public_key_jwk)
            .map_err(|_| {
                FormatterError::CouldNotFormat("Failed to extract public key bytes".to_owned())
            })?;

        let proof_value = self
            .serialize_proof_value(
                &hash_data,
                &hmac_key,
                &public_key_bytes,
                &mandatory_pointers,
                auth_fn,
            )
            .await?;

        proof_config.proof_value = Some(proof_value);
        ld_credential.proof = Some(proof_config);

        let resp = serde_json::to_string(&ld_credential)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        Ok(resp)
    }

    pub(super) fn create_blank_node_identifier_map(
        &self,
        canon: &str,
        hmac_key: &[u8],
    ) -> Result<HashMap<String, String>, FormatterError> {
        let mut bnode_map = HashMap::new();

        // This is simplified approach where we mark claims as optional
        // and everything else as mandatory
        for line in canon.lines() {
            let first = line
                .split(' ')
                .next()
                .ok_or(FormatterError::CouldNotFormat(
                    "Canonical representation is broken.".to_string(),
                ))?;

            if first.starts_with("_:") {
                let identifier = first.strip_prefix("_:").ok_or(FormatterError::Failed(
                    "Strip must succeed after verification".to_owned(),
                ))?;

                match bnode_map.entry(first.to_owned()) {
                    Entry::Occupied(_) => {}
                    Entry::Vacant(entry) => {
                        let hmac_value =
                            self.crypto
                                .create_hmac(hmac_key, identifier.as_bytes())
                                .ok_or(FormatterError::CouldNotFormat("HMAC failed".to_owned()))?;
                        let base64url_value = Base64UrlSafeNoPadding::encode_to_string(hmac_value)
                            .map_err(|_| {
                                FormatterError::CouldNotFormat(
                                    "Could not create Base64url representation".to_owned(),
                                )
                            })?;

                        let value = format!("u{}", base64url_value);

                        entry.insert(value);
                    }
                }
            }
        }

        // Find out indices
        let mut hmac_ids: Vec<String> = bnode_map.values().cloned().collect();
        hmac_ids.sort_unstable();

        // Create mapping
        for (_, v) in bnode_map.iter_mut() {
            let index = hmac_ids.iter().position(|entry| entry == v).ok_or(
                FormatterError::CouldNotFormat("Missing bnode map entry".to_owned()),
            )?;
            *v = format!("_:b{}", index);
        }

        Ok(bnode_map)
    }

    pub(super) fn transform_canonical(
        &self,
        identifier_map: &HashMap<String, String>,
        canon: &str,
    ) -> Result<Vec<String>, FormatterError> {
        let lines: Result<Vec<String>, FormatterError> = canon
            .lines()
            .map(|line| {
                let mut parts: Vec<String> = line.split(' ').map(|s| s.to_owned()).collect();

                // Seems that the tokens to replace can only be in part 0 (subject) and 2 (object).
                let subject = parts.get_mut(0).ok_or(FormatterError::CouldNotFormat(
                    "Canonical transformation failed".to_owned(),
                ))?;

                if subject.starts_with("_:") {
                    identifier_map
                        .get(subject.as_str())
                        .ok_or(FormatterError::CouldNotFormat(
                            "Canonical transformation failed".to_owned(),
                        ))?
                        .clone_into(subject);
                }

                // Blank node will be detected here only if an entry contain any blank node.
                let object = parts.get_mut(2).ok_or(FormatterError::CouldNotFormat(
                    "Canonical transformation failed".to_owned(),
                ))?;
                if object.starts_with("_:") {
                    let replacement = identifier_map.get(object.as_str()).ok_or(
                        FormatterError::CouldNotFormat(
                            "Canonical transformation failed".to_owned(),
                        ),
                    )?;
                    replacement.clone_into(object);
                }
                Ok(parts.join(" "))
            })
            .collect();

        let mut lines = lines?;

        lines.sort();

        Ok(lines)
    }

    pub(super) fn create_grouped_transformation(
        &self,
        transformed: &[String],
    ) -> Result<GroupedFormatDataDocument, FormatterError> {
        // Create the mandatory and non-mandatory HashMaps
        let mut mandatory_map: Vec<(usize, String)> = Vec::new();
        let mut non_mandatory_map: Vec<(usize, String)> = Vec::new();

        // This is a simple implementation that makes everything mandatory except for credential
        // subject that holder is free to disclose what they need.
        for (index, triple) in transformed.iter().enumerate() {
            // Could probably be parsed to RDF
            let parts: Vec<String> = triple.split(' ').map(|s| s.to_owned()).collect();

            let subject = parts.first().ok_or(FormatterError::CouldNotFormat(
                "Grouping failed - missing first".to_owned(),
            ))?;
            let object = parts.get(2).ok_or(FormatterError::CouldNotFormat(
                "Grouping failed - missing 2nd element".to_owned(),
            ))?;

            let map = if subject.starts_with("_:") || object.starts_with("_:") {
                &mut non_mandatory_map
            } else {
                &mut mandatory_map
            };

            map.push((index, triple.to_owned()));
        }

        Ok(GroupedFormatDataDocument {
            mandatory: mapper::to_grouped_entry(mandatory_map),
            non_mandatory: mapper::to_grouped_entry(non_mandatory_map),
        })
    }

    pub(super) fn prepare_proof_hashes(
        &self,
        transformed_proof_config: &str,
        transformed_document: &GroupedFormatDataDocument,
    ) -> Result<HashData, FormatterError> {
        let hashing_function = "sha-256";
        let hasher = self.crypto.get_hasher(hashing_function).map_err(|_| {
            FormatterError::CouldNotFormat(format!("Hasher {} unavailable", hashing_function))
        })?;

        let transformed_proof_config_hash = hasher
            .hash(transformed_proof_config.as_bytes())
            .map_err(|e| FormatterError::CouldNotFormat(format!("Hasher error: `{}`", e)))?;

        let mandatory_triples: Vec<&str> = transformed_document
            .mandatory
            .value
            .iter()
            .map(|group_entry| group_entry.entry.as_str())
            .collect();

        let joined_mandatory_triples = mandatory_triples.concat();

        let mandatory_triples_hash = hasher
            .hash(joined_mandatory_triples.as_bytes())
            .map_err(|e| FormatterError::CouldNotFormat(format!("Hasher error: `{}`", e)))?;

        Ok(HashData {
            transformed_document: transformed_document.clone(),
            proof_config_hash: transformed_proof_config_hash,
            mandatory_hash: mandatory_triples_hash,
        })
    }

    pub(super) async fn serialize_proof_value(
        &self,
        hash_data: &HashData,
        hmac_key: &[u8],
        public_key: &[u8],
        mandatory_pointers: &[String],
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let bbs_header = [
            hash_data.proof_config_hash.as_slice(),
            hash_data.mandatory_hash.as_slice(),
        ]
        .concat();

        let bbs_messages: Vec<Vec<u8>> = hash_data
            .transformed_document
            .non_mandatory
            .value
            .iter()
            .map(|entry| entry.entry.as_bytes().to_vec())
            .collect();

        let bbs_input = BbsInput {
            header: bbs_header.clone(),
            messages: bbs_messages.clone(),
        };

        let signature_input = serde_json::to_vec(&bbs_input).map_err(|e| {
            FormatterError::CouldNotSign(format!("Could not serialize bbs_input: {e}"))
        })?;

        let bbs_signature = auth_fn
            .sign(&signature_input)
            .await
            .map_err(|e| FormatterError::CouldNotSign(e.to_string()))?;

        let mut proof_value = CBOR_PREFIX_BASE.to_vec();

        let bbs_components = BbsProofComponents {
            bbs_signature,
            bbs_header,
            public_key: public_key.to_owned(),
            hmac_key: hmac_key.to_owned(),
            mandatory_pointers: mandatory_pointers.to_owned(),
        };
        let mut cbor_components = Vec::new();
        ciborium::ser::into_writer(&bbs_components, &mut cbor_components).map_err(|e| {
            FormatterError::CouldNotFormat(format!("CBOR serialization failed: {}", e))
        })?;
        proof_value.append(&mut cbor_components);

        let b64 = Base64UrlSafeNoPadding::encode_to_string(proof_value)
            .map_err(|_| FormatterError::CouldNotFormat("B64 encoding failed".to_owned()))?;

        // For multibase output
        Ok(format!("u{b64}",))
    }
}

fn allow_bbs_key_only(did_document: &DidDocumentDTO) -> Result<(), FormatterError> {
    let jwk = &did_document
        .verification_method
        .first()
        .ok_or(FormatterError::BBSOnly)?
        .public_key_jwk;

    if let PublicKeyJwkDTO::Okp(public_key) = jwk {
        if public_key.crv != "Bls12381G2" {
            return Err(FormatterError::BBSOnly);
        }
    } else {
        return Err(FormatterError::BBSOnly);
    }
    Ok(())
}

fn prepare_mandatory_pointers(credential_status: &[CredentialStatus]) -> Vec<String> {
    let mut pointers = vec![
        "/issuer".to_string(),
        "/issuanceDate".to_string(),
        "/type".to_string(),
    ];
    if !credential_status.is_empty() {
        pointers.push("/credentialStatus".to_owned());
    }
    pointers
}
