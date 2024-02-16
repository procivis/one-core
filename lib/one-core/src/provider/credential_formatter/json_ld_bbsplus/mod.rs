use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use serde::Deserialize;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::vec;

use crate::crypto::signer::bbs::BbsInput;
use crate::crypto::CryptoProvider;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld_bbsplus::model::BbsProofComponents;
use crate::provider::credential_formatter::model::{CredentialStatus, DetailCredential};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::credential::dto::CredentialDetailResponseDTO;
use async_trait::async_trait;
use shared_types::DidValue;

use self::model::{HashData, TransformedDataDocument};

use super::json_ld::JsonLd;
use super::model::{CredentialPresentation, Presentation};
use super::{AuthenticationFn, CredentialFormatter, FormatterCapabilities, VerificationFn};

mod mapper;
pub mod model;

#[cfg(test)]
mod test;

#[allow(dead_code)]
pub struct JsonLdBbsplus {
    json_ld: JsonLd,
    pub base_url: Option<String>,
    pub crypto: Arc<dyn CryptoProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {}

#[async_trait]
impl CredentialFormatter for JsonLdBbsplus {
    async fn format_credentials(
        &self,
        credential: &CredentialDetailResponseDTO,
        credential_status: Option<CredentialStatus>,
        holder_did: &DidValue,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        if algorithm != "BBS_PLUS" {
            return Err(FormatterError::CouldNotFormat(
                "Only BBS_PLUS is supported".to_owned(),
            ));
        }

        let issuer_did = credential
            .issuer_did
            .as_ref()
            .map(|did| did.did.clone())
            .ok_or(FormatterError::MissingIssuer)?;

        // We only do that to get public key here. Maybe a public key could be exposed by AuthenticationFn trait?
        let did_document = self
            .did_method_provider
            .resolve(&issuer_did)
            .await
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        // Those fields have to be presented by holder for verifier.
        // It's not the same as 'required claim' for issuance.
        // Here we add everything that is mandatory which is everything except CredentialSubject.
        let mandatory_pointers = self.prepare_mandatory_pointers(&credential_status);

        let mut ld_credential = self.json_ld.prepare_credential(
            credential,
            credential_status,
            holder_did,
            &issuer_did,
            additional_context,
            additional_types,
        );

        let hmac_key = self.crypto.generate_bytes(32);

        // We are getting a string from normalization so we operate on it.
        let canonical = self.json_ld.canonize_any(&ld_credential).await?;

        let identifier_map = self.create_blank_node_identifier_map(&canonical, &hmac_key)?;

        let transformed = self.transform_canonical(&identifier_map, &canonical)?;

        let grouped = self.create_grouped_transformation(&transformed, &mandatory_pointers)?;

        let mut proof_config = self
            .json_ld
            .prepare_proof_config(
                "authentication",
                "bbs-2023",
                ld_credential.context.clone(),
                &did_document,
            )
            .await?;

        let canonical_proof_config = self.json_ld.canonize_any(&proof_config).await?;

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
            .prepare_proof_value(&hash_data, &hmac_key, &public_key_bytes, auth_fn)
            .await?;

        proof_config.proof_value = Some(proof_value);
        ld_credential.proof = Some(proof_config);

        let resp = serde_json::to_string(&ld_credential)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        Ok(resp)
    }

    async fn extract_credentials(
        &self,
        _credential: &str,
        _verification_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        todo!()
    }

    fn format_credential_presentation(
        &self,
        _credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    async fn format_presentation(
        &self,
        _tokens: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _nonce: Option<String>,
    ) -> Result<String, FormatterError> {
        unimplemented!()
    }

    async fn extract_presentation(
        &self,
        _json_ld: &str,
        _verification_fn: VerificationFn,
    ) -> Result<Presentation, FormatterError> {
        unimplemented!()
    }

    fn get_leeway(&self) -> u64 {
        0
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec!["BBS_PLUS".to_owned()],
            features: vec!["SELECTIVE_DISCLOSURE".to_owned()],
        }
    }
}

impl JsonLdBbsplus {
    #[allow(clippy::new_without_default)]
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        base_url: Option<String>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            json_ld: JsonLd::new(crypto.clone(), base_url.clone()),
            params,
            crypto,
            base_url,
            did_method_provider,
            key_algorithm_provider,
        }
    }

    fn create_blank_node_identifier_map<'a>(
        &self,
        canon: &'a str,
        hmac_key: &[u8],
    ) -> Result<HashMap<&'a str, String>, FormatterError> {
        let mut bnode_map = HashMap::new();

        // This is an approach for issuance. We will need an universal
        // pointers to n-quads implementation for verification.
        for line in canon.lines() {
            let first = line
                .split(' ')
                .next()
                .ok_or(FormatterError::CouldNotFormat(
                    "Canonical representation is broken.".to_string(),
                ))?;

            if first.starts_with("_:") {
                let identifier = first
                    .strip_prefix("_:")
                    .expect("Strip must succeed after verification");

                match bnode_map.entry(first) {
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

    fn transform_canonical(
        &self,
        identifier_map: &HashMap<&str, String>,
        canon: &str,
    ) -> Result<Vec<String>, FormatterError> {
        let lines: Result<Vec<String>, FormatterError> = canon
            .lines()
            .map(|line| {
                let mut parts: Vec<String> = line.split(' ').map(|s| s.to_owned()).collect();

                // Seems that the tokens to replace can only be in part 0 and 2.
                let subject = parts.get_mut(0).ok_or(FormatterError::CouldNotFormat(
                    "Canonical transformation failed".to_owned(),
                ))?;
                if subject.starts_with("_:") {
                    *subject = identifier_map
                        .get(subject.as_str())
                        .ok_or(FormatterError::CouldNotFormat(
                            "Canonical transformation failed".to_owned(),
                        ))?
                        .to_owned();
                }

                // Blank node will be detected here only if an entry contain blank node at all.
                // If not there will be a value that hopefully will not match the pattern.
                // Will try to parse it to RDF representation and operate on that.
                let object = parts.get_mut(2).ok_or(FormatterError::CouldNotFormat(
                    "Canonical transformation failed".to_owned(),
                ))?;
                if object.starts_with("_:") {
                    let replacement = identifier_map.get(object.as_str()).ok_or(
                        FormatterError::CouldNotFormat(
                            "Canonical transformation failed".to_owned(),
                        ),
                    )?;
                    *object = replacement.to_owned();
                }
                Ok(parts.join(" "))
            })
            .collect();

        let mut lines = lines?;

        lines.sort();

        Ok(lines)
    }

    fn create_grouped_transformation(
        &self,
        transformed: &[String],
        mandatory_pointers: &[String],
    ) -> Result<TransformedDataDocument, FormatterError> {
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

        Ok(TransformedDataDocument {
            mandatory_pointers: mandatory_pointers.to_owned(),
            mandatory: mapper::to_grouped_entry(mandatory_map),
            non_mandatory: mapper::to_grouped_entry(non_mandatory_map),
        })
    }

    fn prepare_mandatory_pointers(
        &self,
        credential_status: &Option<CredentialStatus>,
    ) -> Vec<String> {
        let mut pointers = vec![
            "/issuer".to_string(),
            "/issuanceDate".to_string(),
            "/type".to_string(),
        ];
        if credential_status.is_some() {
            pointers.push("/credentialStatus".to_owned());
        }
        pointers
    }

    pub(super) fn prepare_proof_hashes(
        &self,
        transformed_proof_config: &str,
        transformed_document: &TransformedDataDocument,
    ) -> Result<HashData, FormatterError> {
        let hashing_function = "sha-256";
        let hasher = self.crypto.get_hasher(hashing_function).map_err(|_| {
            FormatterError::CouldNotFormat(format!("Hasher {} unavailable", hashing_function))
        })?;

        let transformed_proof_config_hash = hasher
            .hash(transformed_proof_config.as_bytes())
            .map_err(|e| FormatterError::CouldNotFormat(format!("Hasher error: `{}`", e)))?;

        // join all mandatory triples
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

    async fn prepare_proof_value(
        &self,
        hash_data: &HashData,
        hmac_key: &[u8],
        public_key: &[u8],
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

        let bbs_signature = auth_fn
            .sign(&serde_json::to_vec(&bbs_input).unwrap())
            .await
            .unwrap();

        let mut proof_value: Vec<u8> = vec![0xd9, 0x5d, 0x02];

        let bbs_components = BbsProofComponents {
            bbs_signature,
            bbs_header,
            public_key: public_key.to_owned(),
            hmac_key: hmac_key.to_owned(),
            mandatory_pointers: hash_data.transformed_document.mandatory_pointers.clone(),
        };

        let mut cbor_components = serde_cbor::to_vec(&bbs_components).map_err(|e| {
            FormatterError::CouldNotFormat(format!("CBOR serialization failed: {}", e))
        })?;
        proof_value.append(&mut cbor_components);

        // For multibase output
        Ok(format!(
            "u{}",
            Base64UrlSafeNoPadding::encode_to_string(proof_value).unwrap()
        ))
    }
}
