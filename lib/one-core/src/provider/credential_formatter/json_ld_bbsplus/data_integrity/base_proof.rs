use std::collections::HashMap;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use indexmap::IndexMap;
use itertools::Itertools;
use json_ld::Loader;
use one_crypto::Hasher;
use one_crypto::signer::bbs::BbsInput;
use one_crypto::utilities::{build_hmac_sha256, generate_random_bytes};
use time::OffsetDateTime;

use super::canonicalize::{canonicalize_and_group, create_shuffled_id_label_map_function};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld_bbsplus::model::{
    BbsBaseProofComponents, CBOR_PREFIX_BASE,
};
use crate::provider::credential_formatter::model::SignatureProvider;
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmProof};
use crate::util::rdf_canonization::rdf_canonize;

pub async fn create_base_proof(
    unsecured_document: &VcdmCredential,
    mandatory_pointers: Vec<String>,
    verification_method: String,
    loader: &impl Loader,
    hasher: &dyn Hasher,
    auth_fn: &dyn SignatureProvider,
    options: json_ld::Options,
) -> Result<VcdmProof, FormatterError> {
    create_base_proof_with_options(
        unsecured_document,
        mandatory_pointers,
        verification_method,
        loader,
        hasher,
        auth_fn,
        None,
        None,
        options,
    )
    .await
}

pub fn parse_base_proof_value(proof_value: &str) -> Result<BbsBaseProofComponents, FormatterError> {
    let Some(proof_value) = proof_value.strip_prefix("u") else {
        return Err(FormatterError::Failed(
            "Proof value is not multibase-base64url-no-pad-encoded".to_string(),
        ));
    };

    let proof_value = Base64UrlSafeNoPadding::decode_to_vec(proof_value, None)
        .map_err(|e| FormatterError::Failed(format!("Failed to b64 decoding proof value: {e}")))?;

    let proof_value = match proof_value.get(..3).ok_or(FormatterError::Failed(format!(
        "Invalid proof value. expected prefix got: {}",
        hex::encode(&proof_value)
    )))? {
        prefix if prefix == CBOR_PREFIX_BASE => {
            proof_value.get(3..).ok_or(FormatterError::Failed(format!(
                "Invalid proof value. got: {}",
                hex::encode(&proof_value)
            )))?
        }
        other => {
            return Err(FormatterError::Failed(format!(
                "Invalid proof value. expected baseline prefix got: {}",
                hex::encode(other)
            )));
        }
    };

    let proof_components: BbsBaseProofComponents =
        ciborium::de::from_reader(proof_value).map_err(|e| {
            FormatterError::Failed(format!("Failed to deserialize bbs+ proof components: {e}"))
        })?;

    Ok(proof_components)
}

// https://www.w3.org/TR/vc-di-bbs/#create-base-proof-bbs-2023
#[expect(clippy::too_many_arguments)]
async fn create_base_proof_with_options(
    unsecured_document: &VcdmCredential,
    mandatory_pointers: Vec<String>,
    verification_method: String,
    loader: &impl Loader,
    hasher: &dyn Hasher,
    auth_fn: &dyn SignatureProvider,
    hmac_key: Option<[u8; 32]>,
    created: Option<OffsetDateTime>,
    options: json_ld::Options,
) -> Result<VcdmProof, FormatterError> {
    if unsecured_document.proof.is_some() {
        return Err(FormatterError::Failed(
            "Cannot create base proof for credential with existing proof".to_string(),
        ));
    }

    let context = unsecured_document.context.clone();
    let unsecured_document = json_syntax::to_value(unsecured_document).map_err(|e| {
        FormatterError::Failed(format!(
            "Failed to convert unsecured document to value: {e}",
        ))
    })?;

    let mut proof_config = VcdmProof::builder()
        .context(context)
        .proof_purpose("assertionMethod")
        .cryptosuite("bbs-2023")
        .verification_method(verification_method)
        .created(created.unwrap_or_else(OffsetDateTime::now_utc))
        .build();

    let canonical_proof_config = base_proof_config(&proof_config, loader, options.clone()).await?;

    let transformed_doc = base_proof_transformation(
        unsecured_document,
        &mandatory_pointers,
        loader,
        options,
        hmac_key,
    )
    .await?;

    let hash_data = base_proof_hashing(transformed_doc, canonical_proof_config, hasher)?;
    let proof_value = base_proof_serialization(hash_data, mandatory_pointers, auth_fn).await?;

    proof_config.proof_value = Some(proof_value);
    proof_config.context = None;

    Ok(proof_config)
}

pub(super) async fn base_proof_config(
    proof: &VcdmProof,
    loader: &impl Loader,
    options: json_ld::Options,
) -> Result<String, FormatterError> {
    rdf_canonize(proof, loader, options).await
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(super) struct TransformedDocument {
    mandatory: IndexMap<usize, String>,
    non_mandatory: IndexMap<usize, String>,
    hmac_key: [u8; 32],
}

// Follows the steps defined here: https://www.w3.org/TR/vc-di-bbs/#base-proof-transformation-bbs-2023
pub(super) async fn base_proof_transformation(
    unsecured_document: json_syntax::Value,
    mandatory_pointers: &[String],
    loader: &impl Loader,
    json_ld_processor_options: json_ld::Options,
    hmac_key: Option<[u8; 32]>,
) -> Result<TransformedDocument, FormatterError> {
    // 1. Initialize hmac to an HMAC API using a locally generated and exportable HMAC key.
    let hmac_key = hmac_key.unwrap_or_else(generate_random_bytes::<32>);
    let hmac = build_hmac_sha256(&hmac_key).ok_or_else(|| {
        FormatterError::Failed("Failed to build HMAC-SHA256 for specified key".to_string())
    })?;
    // 2. Initialize labelMapFactoryFunction to the result of calling the createShuffledIdLabelMapFunction algorithm passing hmac as HMAC.
    let label_map_factory_function = create_shuffled_id_label_map_function(hmac);
    // 3. Initialize groupDefinitions to a map with an entry with a key of the string "mandatory" and a value of mandatoryPointers.
    let mut group_definitions = HashMap::new();
    group_definitions.insert("mandatory".to_string(), mandatory_pointers);
    // 4. Partition the document into mandatory and non-mandatory groups.
    let mut result = canonicalize_and_group(
        label_map_factory_function,
        group_definitions,
        unsecured_document,
        loader,
        json_ld_processor_options,
    )
    .await?;

    let entry = result.groups.remove("mandatory").ok_or_else(|| {
        FormatterError::Failed("Mandatory group not found in canonicalized document".to_string())
    })?;

    Ok(TransformedDocument {
        mandatory: entry.matching,
        non_mandatory: entry.non_matching,
        hmac_key,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct HashData {
    pub(super) proof_hash: Vec<u8>,
    pub(super) mandatory_hash: Vec<u8>,
    pub(super) transformed_document: TransformedDocument,
}

pub(super) fn base_proof_hashing(
    transformed_document: TransformedDocument,
    canonical_proof_config: String,
    hasher: &dyn Hasher,
) -> Result<HashData, FormatterError> {
    let proof_hash = hasher
        .hash(canonical_proof_config.as_bytes())
        .map_err(|e| {
            FormatterError::Failed(format!("Failed to hash canonical proof config: {e}"))
        })?;
    let mandatory_concat = transformed_document.mandatory.values().join("");
    let mandatory_hash = hasher
        .hash(mandatory_concat.as_bytes())
        .map_err(|e| FormatterError::Failed(format!("Failed to hash mandatory concat: {e}")))?;

    Ok(HashData {
        proof_hash,
        mandatory_hash,
        transformed_document,
    })
}

pub(super) struct SignatureInput {
    pub(super) header: Vec<u8>,
    pub(super) message: Vec<u8>,
}

pub(super) fn generate_signature_input(
    hash_data: HashData,
) -> Result<SignatureInput, FormatterError> {
    let HashData {
        proof_hash,
        mandatory_hash,
        transformed_document,
    } = hash_data;
    let header = [proof_hash, mandatory_hash].concat();
    let bbs_messages: Vec<Vec<u8>> = transformed_document
        .non_mandatory
        .into_values()
        .map(|v| v.into_bytes())
        .collect();

    // assume multisign payload {header, messages}
    let message = serde_json::to_vec(&BbsInput {
        header: header.clone(),
        messages: bbs_messages,
    })
    .map_err(|e| FormatterError::Failed(format!("Failed to serialize bbs input: {e}")))?;

    Ok(SignatureInput { header, message })
}

async fn base_proof_serialization(
    hash_data: HashData,
    mandatory_pointers: Vec<String>,
    auth_fn: &dyn SignatureProvider,
) -> Result<String, FormatterError> {
    let hmac_key = hash_data.transformed_document.hmac_key.to_vec();
    let SignatureInput { header, message } = generate_signature_input(hash_data)?;

    let signature = auth_fn
        .sign(&message)
        .await
        .map_err(|e| FormatterError::Failed(format!("Failed to sign bbs input: {e}")))?;

    let proof_value = serialize_base_proof_value(
        signature,
        header,
        auth_fn.get_public_key(),
        hmac_key,
        mandatory_pointers,
    )?;

    Ok(proof_value)
}

fn serialize_base_proof_value(
    bbs_signature: Vec<u8>,
    bbs_header: Vec<u8>,
    public_key: Vec<u8>,
    hmac_key: Vec<u8>,
    mandatory_pointers: Vec<String>,
) -> Result<String, FormatterError> {
    let bbs_components = BbsBaseProofComponents {
        bbs_signature,
        bbs_header,
        public_key,
        hmac_key,
        mandatory_pointers,
    };

    let mut cbor_components = Vec::new();
    ciborium::ser::into_writer(&bbs_components, &mut cbor_components)
        .map_err(|e| FormatterError::CouldNotFormat(format!("CBOR serialization failed: {e}")))?;

    let mut cbor = CBOR_PREFIX_BASE.to_vec();
    cbor.extend(cbor_components);

    let b64 = Base64UrlSafeNoPadding::encode_to_string(cbor)
        .map_err(|_| FormatterError::CouldNotFormat("B64 encoding failed".to_owned()))?;

    Ok(format!("u{b64}"))
}

#[cfg(test)]
// tests use examples from test vectors: https://www.w3.org/TR/vc-di-bbs/#base-proof
mod test {
    use std::sync::Arc;

    use one_crypto::hasher::sha256::SHA256;
    use serde_json::json;
    use similar_asserts::assert_eq;
    use time::format_description::well_known::Rfc3339;
    use uuid::Uuid;

    use super::*;
    use crate::model::key::Key;
    use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::test_data::{
        document_loader, vc_permanent_resident_card, vc_windsurf_race_committee,
    };
    use crate::provider::key_algorithm::KeyAlgorithm;
    use crate::provider::key_algorithm::bbs::BBS;
    use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
    use crate::provider::key_storage::provider::SignatureProviderImpl;
    use crate::util::rdf_canonization::json_ld_processor_options;

    #[tokio::test]
    // test vector from https://www.w3.org/TR/vc-di-bbs/#base-proof-0
    async fn test_create_base_proof_vc_with_arrays() {
        let credential: VcdmCredential =
            serde_json::from_value(vc_windsurf_race_committee().into_serde_json()).unwrap();
        let mandatory_pointers = [
            "/issuer",
            "/credentialSubject/sailNumber",
            "/credentialSubject/sails/1",
            "/credentialSubject/boards/0/year",
            "/credentialSubject/sails/2",
        ]
        .map(ToString::to_string)
        .to_vec();
        let verification_method = "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ".to_string();

        let hasher = SHA256 {};
        let hmac_key =
            hex_literal::hex!("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");

        let auth_fn = auth_fn();

        let proof = create_base_proof_with_options(
            &credential,
            mandatory_pointers,
            verification_method.clone(),
            &document_loader(),
            &hasher,
            &auth_fn,
            Some(hmac_key),
            Some(OffsetDateTime::parse("2023-08-15T23:36:38Z", &Rfc3339).unwrap()),
            json_ld_processor_options(),
        )
        .await
        .unwrap();

        assert!(proof.context.is_none());
        assert_eq!(proof.cryptosuite, "bbs-2023");
        assert_eq!(proof.verification_method, verification_method);
        assert_eq!(proof.proof_purpose, "assertionMethod");
        assert_eq!(
            proof.proof_value.unwrap(),
            "u2V0ChVhQgzH1WtRY_lwyJCCyy4BvmiDqayuKKdUXEAJtcazl2ggAZLSIgY78daQ5UlvQMUUIIqajMtp4GSbhk2C5AWZDESTvzz0GD7x1DGEixxTAf3FYQDpbvyXTTZCxjDXNI1e-am9CMB6U_J5S936Tt3PFYUvfVV3gX4mIF-MTAbrBh9DD_ysD4svbSttNVowX3pYfmhhYYKTvGvo9pXVJbxIrm3i4wkdhUxqKCTIGrnxFuAdZwWi6T3omD5wzZ7bAGbRneEEQSxBmXtvnC6Pr59nPv_v3HrAW9wq_uxYzF_NyaX3GPv0h_FV2T2OSao8C6uoyWiqIj1ggABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v-FZy9pc3N1ZXJ4HS9jcmVkZW50aWFsU3ViamVjdC9zYWlsTnVtYmVyeBovY3JlZGVudGlhbFN1YmplY3Qvc2FpbHMvMXggL2NyZWRlbnRpYWxTdWJqZWN0L2JvYXJkcy8wL3llYXJ4Gi9jcmVkZW50aWFsU3ViamVjdC9zYWlscy8y"
        );
    }

    #[tokio::test]
    // test vector from https://www.w3.org/TR/vc-di-bbs/#base-proof
    async fn test_create_base_proof_vc_with_issuer_object() {
        let credential: VcdmCredential =
            serde_json::from_value(vc_permanent_resident_card().into_serde_json()).unwrap();
        let mandatory_pointers = vec!["/issuer".to_string()];
        let verification_method = "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ".to_string();
        let hasher = SHA256 {};
        let hmac_key =
            hex_literal::hex!("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");

        let auth_fn = auth_fn();

        let proof = create_base_proof_with_options(
            &credential,
            mandatory_pointers,
            verification_method.clone(),
            &document_loader(),
            &hasher,
            &auth_fn,
            Some(hmac_key),
            Some(OffsetDateTime::parse("2023-08-15T23:36:38Z", &Rfc3339).unwrap()),
            json_ld_processor_options(),
        )
        .await
        .unwrap();

        assert!(proof.context.is_none());
        assert_eq!(proof.cryptosuite, "bbs-2023");
        assert_eq!(proof.verification_method, verification_method);
        assert_eq!(proof.proof_purpose, "assertionMethod");
        assert_eq!(
            proof.proof_value.unwrap(),
            "u2V0ChVhQhhaN0rXQx8alajD0IS7RFqU97wXQ1nCCB9SDx_8gU676ItJLp2WdYIUmlPjYW-D6Ktw5dMfcTMaLPbF7JCOXUEcQQWLCRQK0FZGHmsJPG7FYQDpbvyXTTZCxjDXNI1e-am9CMB6U_J5S936Tt3PFYUvfjnzCLDGN0glOAtC\
            _BsXXOl26cXYRpA9tG-3F6nwwD9ZYYKTvGvo9pXVJbxIrm3i4wkdhUxqKCTIGrnxFuAdZwWi6T3omD5wzZ7bAGbRneEEQSxBmXtvnC6Pr59nPv_v3HrAW9wq_uxYzF_NyaX3GPv0h_FV2T2OSao8C6uoyWiqIj1ggABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v-BZy9pc3N1ZXI"
        );
    }

    #[tokio::test]
    async fn test_base_proof_config() {
        let proof: VcdmProof = serde_json::from_value(json!(
            {
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://w3id.org/citizenship/v4rc1"
                ],
                "type": "DataIntegrityProof",
                "cryptosuite": "bbs-2023",
                "created": "2023-08-15T23:36:38Z",
                "verificationMethod": "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ",
                "proofPurpose": "assertionMethod"
            }
        )).unwrap();

        let canonical_proof_config =
            base_proof_config(&proof, &document_loader(), json_ld_processor_options())
                .await
                .unwrap();

        let expected = "_:c14n0 <http://purl.org/dc/terms/created> \"2023-08-15T23:36:38Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n\
        _:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .\n\
        _:c14n0 <https://w3id.org/security#cryptosuite> \"bbs-2023\"^^<https://w3id.org/security#cryptosuiteString> .\n\
        _:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .\n\
        _:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ> .\n";

        assert_eq!(canonical_proof_config, expected);
    }

    #[test]
    fn test_base_proof_hash() {
        let transformed_document = TransformedDocument {
            mandatory: IndexMap::from_iter(
                [
                (0, "<did:key:zDnaeTHxNEBZoKaEo6PdA83fq98ebiFvo3X273Ydu4YmV96rg> <https://schema.org/image> <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2P4z/DiPwAG0ALnwgz64QAAAABJRU5ErkJggg==> .\n"),
                (16, "_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCardCredential> .\n"),
                (17, "_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n"),
                (21, "_:b2 <https://www.w3.org/2018/credentials#issuer> <did:key:zDnaeTHxNEBZoKaEo6PdA83fq98ebiFvo3X273Ydu4YmV96rg> .\n")
                ].map(|(index, line)| (index, line.to_string()))
            ),
            non_mandatory: IndexMap::from_iter(
                [
                (1, "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://schema.org/Person> .\n"),
                (2, "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .\n"),
                (3, "_:b0 <https://schema.org/birthDate> \"1978-07-17\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n"),
                (4, "_:b0 <https://schema.org/familyName> \"SMITH\" .\n"),
                (5, "_:b0 <https://schema.org/gender> \"Female\" .\n"),
                (6, "_:b0 <https://schema.org/givenName> \"JANE\" .\n"),
                (7, "_:b0 <https://schema.org/image> <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2P4v43hPwAHIgK1v4tX6wAAAABJRU5ErkJggg==> .\n"),
                (8, "_:b0 <https://w3id.org/citizenship#birthCountry> \"Arcadia\" .\n"),
                (9, "_:b0 <https://w3id.org/citizenship#commuterClassification> \"C1\" .\n"),
                (10, "_:b0 <https://w3id.org/citizenship#permanentResidentCard> _:b1 .\n"),
                (11, "_:b0 <https://w3id.org/citizenship#residentSince> \"2015-01-01\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n"),
                (12, "_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .\n"),
                (13, "_:b1 <https://schema.org/identifier> \"83627465\" .\n"),
                (14, "_:b1 <https://w3id.org/citizenship#lprCategory> \"C09\" .\n"),
                (15, "_:b1 <https://w3id.org/citizenship#lprNumber> \"999-999-999\" .\n"),
                (18, "_:b2 <https://schema.org/description> \"Permanent Resident Card from Government of Utopia.\" .\n"),
                (19, "_:b2 <https://schema.org/name> \"Permanent Resident Card\" .\n"),
                (20, "_:b2 <https://www.w3.org/2018/credentials#credentialSubject> _:b0 .\n"),
                (22, "_:b2 <https://www.w3.org/2018/credentials#validFrom> \"2024-12-16T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n"),
                (23, "_:b2 <https://www.w3.org/2018/credentials#validUntil> \"2025-12-16T23:59:59Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n")
            ]   .map(|(index, line)| (index, line.to_string()))
            ),
            hmac_key: hex_literal::hex!(
                "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
            ),
        };
        let canonical_proof_config = "_:c14n0 <http://purl.org/dc/terms/created> \"2023-08-15T23:36:38Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n\
        _:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .\n\
        _:c14n0 <https://w3id.org/security#cryptosuite> \"bbs-2023\"^^<https://w3id.org/security#cryptosuiteString> .\n\
        _:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .\n\
        _:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ> .\n";
        let hasher = SHA256 {};

        let hash_data = base_proof_hashing(
            transformed_document.clone(),
            canonical_proof_config.to_string(),
            &hasher,
        );

        assert_eq!(
            hash_data,
            Ok(HashData {
                proof_hash: hex::decode(
                    "3a5bbf25d34d90b18c35cd2357be6a6f42301e94fc9e52f77e93b773c5614bdf"
                )
                .unwrap(),
                mandatory_hash: hex::decode(
                    "8e7cc22c318dd2094e02d0bf06c5d73a5dba717611a40f6d1bedc5ea7c300fd6"
                )
                .unwrap(),
                transformed_document,
            }),
        );
    }

    #[tokio::test]
    async fn test_base_proof_serialization() {
        let transformed_document = TransformedDocument {
            mandatory: IndexMap::new(),
            non_mandatory: IndexMap::from_iter([
                    (1, "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://schema.org/Person> .\n"),
                    (2, "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .\n"),
                    (3, "_:b0 <https://schema.org/birthDate> \"1978-07-17\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n"),
                    (4, "_:b0 <https://schema.org/familyName> \"SMITH\" .\n"),
                    (5, "_:b0 <https://schema.org/gender> \"Female\" .\n"),
                    (6, "_:b0 <https://schema.org/givenName> \"JANE\" .\n"),
                    (7, "_:b0 <https://schema.org/image> <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2P4v43hPwAHIgK1v4tX6wAAAABJRU5ErkJggg==> .\n"),
                    (8, "_:b0 <https://w3id.org/citizenship#birthCountry> \"Arcadia\" .\n"),
                    (9, "_:b0 <https://w3id.org/citizenship#commuterClassification> \"C1\" .\n"),
                    (10, "_:b0 <https://w3id.org/citizenship#permanentResidentCard> _:b1 .\n"),
                    (11, "_:b0 <https://w3id.org/citizenship#residentSince> \"2015-01-01\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n"),
                    (12, "_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .\n"),
                    (13, "_:b1 <https://schema.org/identifier> \"83627465\" .\n"),
                    (14, "_:b1 <https://w3id.org/citizenship#lprCategory> \"C09\" .\n"),
                    (15, "_:b1 <https://w3id.org/citizenship#lprNumber> \"999-999-999\" .\n"),
                    (18, "_:b2 <https://schema.org/description> \"Permanent Resident Card from Government of Utopia.\" .\n"),
                    (19, "_:b2 <https://schema.org/name> \"Permanent Resident Card\" .\n"),
                    (20, "_:b2 <https://www.w3.org/2018/credentials#credentialSubject> _:b0 .\n"),
                    (22, "_:b2 <https://www.w3.org/2018/credentials#validFrom> \"2024-12-16T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n"),
                    (23, "_:b2 <https://www.w3.org/2018/credentials#validUntil> \"2025-12-16T23:59:59Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n")
                ].map(|(index, line)| (index, line.to_string()))
            ),
            hmac_key: hex_literal::hex!(
                "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
            ),
        };

        let hash_data = HashData {
            proof_hash: hex::decode(
                "3a5bbf25d34d90b18c35cd2357be6a6f42301e94fc9e52f77e93b773c5614bdf",
            )
            .unwrap(),
            mandatory_hash: hex::decode(
                "8e7cc22c318dd2094e02d0bf06c5d73a5dba717611a40f6d1bedc5ea7c300fd6",
            )
            .unwrap(),
            transformed_document,
        };

        let mandatory_pointers = vec!["/issuer".to_string()];

        let auth_fn = auth_fn();
        let proof_value = base_proof_serialization(hash_data, mandatory_pointers, &auth_fn)
            .await
            .unwrap();

        assert_eq!(
            proof_value,
            "u2V0ChVhQhhaN0rXQx8alajD0IS7RFqU97wXQ1nCCB9SDx_8gU676ItJLp2WdYIUmlPjYW-D6Ktw5dMfcTMaLPbF7JCOXUEcQQWLCRQK0FZGHmsJPG7FYQDpbvyXTTZCxjDXNI1e-am9CMB6U\
        _J5S936Tt3PFYUvfjnzCLDGN0glOAtC_BsXXOl26cXYRpA9tG-3F6nwwD9ZYYKTvGvo9pXVJbxIrm3i4wkdhUxqKCTIGrnxFuAdZwWi6T3omD5wzZ7bAGbRneEEQSxBmXtvnC6Pr59nPv_v3HrAW9wq_uxYzF_NyaX3GPv0h_FV\
        2T2OSao8C6uoyWiqIj1ggABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v-BZy9pc3N1ZXI"
        );
    }

    // auth fn for test vectors
    fn auth_fn() -> impl SignatureProvider {
        let public_key = hex::decode("a4ef1afa3da575496f122b9b78b8c24761531a8a093206ae7c45b80759c168ba4f7a260f9c3367b6c019b4677841104b10665edbe70ba3ebe7d9cfbffbf71eb016f70abfbb163317f372697dc63efd21fc55764f63926a8f02eaea325a2a888f").unwrap();
        let key_handle = BBS
            .reconstruct_key(
                &public_key,
                Some(
                    hex::decode("66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0")
                        .unwrap()
                        .into(),
                ),
                None,
            )
            .unwrap();

        SignatureProviderImpl {
            // dummy key, only public key needs to match
            key: Key {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key,
                name: "test".to_string(),
                key_reference: None,
                storage_type: "test".to_string(),
                key_type: "test".to_string(),
                organisation: None,
            },
            key_handle,
            jwk_key_id: None,
            key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        }
    }
}
