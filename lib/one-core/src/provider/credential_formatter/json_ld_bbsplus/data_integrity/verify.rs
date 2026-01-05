use std::borrow::Cow;

use json_ld::Loader;
use one_crypto::Hasher;
use one_crypto::signer::bbs::{BBSSigner, BbsProofInput};

use super::parse_base_proof_value;
use crate::config::core_config::KeyAlgorithmType;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::canonicalize::{
    create_label_map_function, label_replacement_canonicalize_json_ld,
};
use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::{
    base_proof_config, base_proof_hashing, base_proof_transformation, generate_signature_input,
    parse_derived_proof_value,
};
use crate::provider::credential_formatter::json_ld_bbsplus::model::BbsBaseProofComponents;
use crate::provider::credential_formatter::model::{PublicKeySource, TokenVerifier};
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmProof};
use crate::util::rdf_canonization::rdf_canonize;

pub async fn verify_base_proof(
    vcdm: &VcdmCredential,
    mut proof: VcdmProof,
    loader: &impl Loader,
    hasher: &dyn Hasher,
    verifier: &dyn TokenVerifier,
    options: json_ld::Options,
) -> Result<BbsBaseProofComponents, FormatterError> {
    if vcdm.proof.is_some() {
        return Err(FormatterError::Failed(
            "VCDM should not contain proof".to_string(),
        ));
    }

    let Some(proof_value) = proof.proof_value.take() else {
        return Err(FormatterError::Failed(
            "VCDM proof is missing proofValue".to_string(),
        ));
    };

    let canonical_proof_config = base_proof_config(&proof, &loader, options.clone()).await?;

    let proof_components = parse_base_proof_value(&proof_value)?;
    let hmac_key = <[u8; 32]>::try_from(proof_components.hmac_key.as_slice())
        .map_err(|_| FormatterError::Failed("Invalid hmac key".to_string()))?;

    let unsecured_document = json_syntax::to_value(vcdm).map_err(|error| {
        FormatterError::Failed(format!("Failed to convert VCDM to json value: {error}"))
    })?;
    let transformed_doc = base_proof_transformation(
        unsecured_document,
        &proof_components.mandatory_pointers,
        loader,
        options,
        Some(hmac_key),
    )
    .await?;

    let hash_data = base_proof_hashing(transformed_doc, canonical_proof_config, hasher)?;

    let signature_input = generate_signature_input(hash_data)?;

    if signature_input.header != proof_components.bbs_header {
        return Err(FormatterError::Failed("Invalid bbs header".to_string()));
    }

    let did_value = vcdm.issuer.to_did_value()?;
    let params = PublicKeySource::Did {
        did: Cow::Owned(did_value),
        key_id: Some(&proof.verification_method),
    };
    verifier
        .verify(
            params,
            KeyAlgorithmType::BbsPlus,
            &signature_input.message,
            &proof_components.bbs_signature,
        )
        .await
        .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))?;

    Ok(proof_components)
}

pub async fn verify_derived_proof(
    unsecured_document: &VcdmCredential,
    proof: VcdmProof,
    public_key: &[u8],
    loader: &impl Loader,
    hasher: &dyn Hasher,
    options: json_ld::Options,
) -> Result<(), FormatterError> {
    let VerifyData {
        base_proof,
        proof_hash,
        non_mandatory,
        mandatory_hash,
        selective_indexes,
        presentation_header,
    } = create_verify_data(unsecured_document, proof, loader, hasher, options).await?;

    let bbs_header = [proof_hash, mandatory_hash].concat();

    if non_mandatory.len() != selective_indexes.len() {
        return Err(FormatterError::Failed(format!(
            "Disclosed messages length `{}` and selective indexes length `{}` mismatch",
            non_mandatory.len(),
            selective_indexes.len()
        )));
    }

    let disclosed_messages = non_mandatory
        .into_iter()
        .enumerate()
        .map(|(i, quad)| {
            Ok((
                selective_indexes
                    .get(i)
                    .ok_or(FormatterError::Failed("Invalid index".to_string()))?
                    .to_owned(),
                quad.into_bytes(),
            ))
        })
        .collect::<Result<_, FormatterError>>()?;

    let proof_input = BbsProofInput {
        header: bbs_header,
        messages: disclosed_messages,
        proof: base_proof,
        presentation_header: Some(presentation_header),
    };
    BBSSigner::verify_proof(&proof_input, public_key)
        .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))
}

struct VerifyData {
    base_proof: Vec<u8>,
    proof_hash: Vec<u8>,
    non_mandatory: Vec<String>,
    mandatory_hash: Vec<u8>,
    selective_indexes: Vec<usize>,
    presentation_header: Vec<u8>,
}
// https://www.w3.org/TR/vc-di-bbs/#createverifydata
async fn create_verify_data(
    vcdm: &VcdmCredential,
    proof: VcdmProof,
    loader: &impl Loader,
    hasher: &dyn Hasher,
    options: json_ld::Options,
) -> Result<VerifyData, FormatterError> {
    if vcdm.proof.is_some() {
        return Err(FormatterError::Failed(
            "VCDM should not contain proof".to_string(),
        ));
    }

    let mut proof = proof;
    let Some(proof_value) = proof.proof_value.take() else {
        return Err(FormatterError::Failed(
            "VCDM proof is missing proofValue".to_string(),
        ));
    };

    let canonical_proof_config = rdf_canonize(&proof, &loader, options.clone()).await?;
    let proof_hash = hasher
        .hash(canonical_proof_config.as_bytes())
        .map_err(|e| {
            FormatterError::Failed(format!("Failed to hash canonical proof config: {e}"))
        })?;

    let proof_components = parse_derived_proof_value(&proof_value)?;
    let label_map_function = create_label_map_function(proof_components.decompressed_label_map);

    let document = json_syntax::to_value(vcdm).map_err(|error| {
        FormatterError::Failed(format!("Failed to convert VCDM to json value: {error}"))
    })?;
    let canonical_nquads =
        label_replacement_canonicalize_json_ld(document, label_map_function, loader, options)
            .await?;

    let mut mandatory = Vec::new();
    let mut non_mandatory = Vec::new();
    for (index, quad) in canonical_nquads.iter().enumerate() {
        if proof_components.mandatory_indexes.contains(&index) {
            mandatory.push(quad.clone());
        } else {
            non_mandatory.push(quad.clone());
        }
    }
    let mandatory_hash = hash_mandatory_nquads(mandatory, hasher)?;

    Ok(VerifyData {
        base_proof: proof_components.bbs_proof,
        proof_hash,
        non_mandatory,
        mandatory_hash,
        selective_indexes: proof_components.selective_indexes,
        presentation_header: proof_components.presentation_header,
    })
}

fn hash_mandatory_nquads(
    mandatory: Vec<String>,
    hasher: &dyn Hasher,
) -> Result<Vec<u8>, FormatterError> {
    let bytes = mandatory.join("").into_bytes();
    hasher
        .hash(&bytes)
        .map_err(|e| FormatterError::Failed(format!("Failed to hash mandatory nquads: {e}")))
}

#[cfg(test)]
mod test {
    use one_crypto::hasher::sha256::SHA256;

    use super::*;
    use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::test_data::document_loader;
    use crate::provider::credential_formatter::model::MockTokenVerifier;
    use crate::provider::key_algorithm::KeyAlgorithm;
    use crate::provider::key_algorithm::bbs::BBS;
    use crate::util::rdf_canonization::json_ld_processor_options;

    #[tokio::test]
    // from https://www.w3.org/TR/vc-di-bbs/#example-signed-base-document
    async fn test_verify_base_proof() {
        let mut vcdm: VcdmCredential = json_syntax::from_value(json_syntax::json!({
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://w3id.org/citizenship/v4rc1"
          ],
          "type": [
            "VerifiableCredential",
            "PermanentResidentCardCredential"
          ],
          "issuer": {
            "id": "did:key:zDnaeTHxNEBZoKaEo6PdA83fq98ebiFvo3X273Ydu4YmV96rg",
            "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2P4z/DiPwAG0ALnwgz64QAAAABJRU5ErkJggg=="
          },
          "name": "Permanent Resident Card",
          "description": "Permanent Resident Card from Government of Utopia.",
          "credentialSubject": {
            "type": [
              "PermanentResident",
              "Person"
            ],
            "givenName": "JANE",
            "familyName": "SMITH",
            "gender": "Female",
            "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2P4v43hPwAHIgK1v4tX6wAAAABJRU5ErkJggg==",
            "residentSince": "2015-01-01",
            "commuterClassification": "C1",
            "birthCountry": "Arcadia",
            "birthDate": "1978-07-17",
            "permanentResidentCard": {
              "type": [
                "PermanentResidentCard"
              ],
              "identifier": "83627465",
              "lprCategory": "C09",
              "lprNumber": "999-999-999"
            }
          },
          "validFrom": "2024-12-16T00:00:00Z",
          "validUntil": "2025-12-16T23:59:59Z",
          "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "bbs-2023",
            "created": "2023-08-15T23:36:38Z",
            "verificationMethod": "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ",
            "proofPurpose": "assertionMethod",
            "proofValue": "u2V0ChVhQhhaN0rXQx8alajD0IS7RFqU97wXQ1nCCB9SDx_8gU676ItJLp2WdYIUmlPjYW-D6Ktw5dMfcTMaLPbF7JCOXUEcQQWLCRQK0FZGHmsJPG7FYQDpbvyXTTZCxjDXNI1e-am9CMB6U_J5S936Tt3PFYUvfjnzCLDGN0glOAtC_BsXXOl26cXYRpA9tG-3F6nwwD9ZYYKTvGvo9pXVJbxIrm3i4wkdhUxqKCTIGrnxFuAdZwWi6T3omD5wzZ7bAGbRneEEQSxBmXtvnC6Pr59nPv_v3HrAW9wq_uxYzF_NyaX3GPv0h_FV2T2OSao8C6uoyWiqIj1ggABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v-BZy9pc3N1ZXI"
          }
        })).unwrap();
        let mut proof = vcdm.proof.take().unwrap();
        proof.context = Some(vcdm.context.clone());

        let hasher = SHA256 {};
        let verifier = build_verifier();

        verify_base_proof(
            &vcdm,
            proof,
            &document_loader(),
            &hasher,
            &verifier,
            json_ld_processor_options(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    // from https://www.w3.org/TR/vc-di-bbs/#example-signed-base-document
    async fn test_verify_derived_proof() {
        let credentials: [VcdmCredential; 2] = [
            json_syntax::from_value(json_syntax::json!({
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://w3id.org/citizenship/v4rc1"
                ],
                "type": [
                    "VerifiableCredential",
                    "PermanentResidentCardCredential"
                ],
                "issuer": {
                    "id": "did:key:zDnaeTHxNEBZoKaEo6PdA83fq98ebiFvo3X273Ydu4YmV96rg",
                    "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2P4z/DiPwAG0ALnwgz64QAAAABJRU5ErkJggg=="
                },
                "validFrom": "2024-12-16T00:00:00Z",
                "validUntil": "2025-12-16T23:59:59Z",
                "credentialSubject": {
                    "type": [
                        "PermanentResident",
                        "Person"
                    ],
                    "birthCountry": "Arcadia"
                },
                "proof": {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "bbs-2023",
                    "created": "2023-08-15T23:36:38Z",
                    "verificationMethod": "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "u2V0DhVkC0JasX_e4m_LYsPPMUcVH8aIrAeJOJGV50hI2LN9r8Pq-GL4MnR-EyQS7TGxhP9Dsq7etkuYVNB2pekWpGHIWJsyFnEVbRzo245VyVh1fxIPGN0JHF6Q9z_s7Ew2P4R-IqIAvOyMe_iRE-LR_7e0LYh49XNIss-wj68T23KdFtcHOL0KnELklEKcSJafTngDgwm2i-uJCzfFU6T3kIBcnC5kCP-lbQsQqRhouqxngSqRIOa85qnH4MBYstCSlqgrMBG3H57i9_HPPNkHHau63-7Vs2TZ3YFDb1jK_f8gNM8Yh3GuDcYSt5hljD3K9Jdiupia6mU0Vpl3vGw3IrwnFSgz15bVNGxsoBHqi2_Y4Bf7JUzurRtEjScpH39g_8wRUztrNI9pOuaPr4ZjICsGZLiogP_z0avqjSCpjt7AAM98aLaNh1gChz9UTm-AQyjAuCCr37jSl_z0kzHBi9X-jbUeEbt1SGeWb1DhXa_9wm_15INa62DZ7D-jHSTGO-HJr7anB2Qlb7XOOT9HDgzOif08gcaIahjZxtD_lIfc3REvoZeiHy_M8qjkib7gBMANyHjfG2UmGe--6HIt79kG9ZHhRrZKu09qRr1LxfQWKn3TrMHRDBMBYE4QL5qUo9UzVoktzri9C3sG_wuE1T7BhqWwN86uW3cmtqWy4glcczLiXdPzwMm4ciyuHzEz06vvXVjJRiRnL5Yqfhq3hKw9picCIbjWNgBuZsd0yx-blamU8DiZKhLUdLSNnnHXigkUa87yqbxnse8OqYD_sh9taV9QpYeKQfYmaj9XRzhfd6Kdc0RkklM2TsRLad3TCuy9nn1tLQE2r5IXXigF7K-geX_i6z5DV8ksug6tBafj1XKb3AxQfkVZau-x0RebPRmP140uRiCg9V87fNsWGsYoTC4NlJDa_aGJnPd7r2a79wvv8l93oDjZINJHENXzNL8Ex-6IAAAEChAAEBQeGAAEHERITRBEzd6o"
                }
            })).unwrap(),
            json_syntax::from_value(json_syntax::json!({
                "@context": [
                "https://www.w3.org/ns/credentials/v2",
                {
                    "@vocab": "https://windsurf.grotto-networking.com/selective#"
                }
                ],
                "type": [
                    "VerifiableCredential"
                ],
                "issuer": "https://vc.example/windsurf/racecommittee",
                "credentialSubject": {
                    "sailNumber": "Earth101",
                    "sails": [
                        {
                        "size": 6.1,
                        "sailName": "Lahaina",
                        "year": 2023
                        },
                        {
                        "size": 7,
                        "sailName": "Lahaina",
                        "year": 2020
                        }
                    ],
                    "boards": [
                        {
                        "year": 2022,
                        "boardName": "CompFoil170",
                        "brand": "Wailea"
                        },
                        {
                        "boardName": "Kanaha Custom",
                        "brand": "Wailea",
                        "year": 2019
                        }
                    ]
                },
                "proof": {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "bbs-2023",
                    "created": "2023-08-15T23:36:38Z",
                    "verificationMethod": "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "u2V0DhVkCEJgxugaFJpT7ROtWzZ9mWBMw2Uk2caOtXtKGEMJVDFv9psrafLrzfprwyHOk7GgTv4V9U5VDvEW6E0n-MjO0RvbEYZDECqhFbZgxLtdTXDAD46d691Ltb37hYt9OOKJorYfMWhD_ONzGYzgQ4IrFqA2s_m597DymX7HauNGw2iK48mBAI4xwC4MQ3pLJwuwRiy3msMzccvvdMynM97xymCnoSS0KeW9uCRMYhPb90N-AKNXvjwXZqpgXhyWYxWQhUm2-XbQFhs0rg6RUZS9xY35XkXq9IvRbtn1I_OvfVGRnGuwuhF-H-HwdDrk02z-54jENSD1nEQtfZBJ4J4iOjNklnqePZoMYTKTnGEW4A9k6NVT0V3cW-Tm9NvJut0B3G9XDUkfvSrwrDnAXIabo7fYqY686Ay34lc3gbQsVyowadQckkRj50Jb8xaP5o57BqHDvYZ76avYf2Tt0uCskMX3vWfmB_I7CtWM9jrhxGxCFUre250hkhQP-zfUqwKduyokwY2EmLMR2e7uE6QTRp1I7wZ1nvFAceJSWFr72VHCwZ_gXWdmin5wndcCIikYXtXAY7OER5izYNltHg_vlO87IRr9yS93cGW_O0FxZw167c1rqmoPw5SM825-7j9LjsAfuf2nK_DfEmT3fx0fXeTtI6kghMVS0WSYMKdpt1B3pU5ozUoVa-jmLK6_UfQfXZaYAAgEEAgMDBwQGBQCOAAECBQYICQoODxAREhOGAwQFCAkKRBEzd6o"
                }
            })).unwrap()
        ];

        let hasher = SHA256 {};

        let public_key = hex::decode("a4ef1afa3da575496f122b9b78b8c24761531a8a093206ae7c45b80759c168ba4f7a260f9c3367b6c019b4677841104b10665edbe70ba3ebe7d9cfbffbf71eb016f70abfbb163317f372697dc63efd21fc55764f63926a8f02eaea325a2a888f").unwrap();
        for mut vcdm in credentials {
            let mut proof = vcdm.proof.take().unwrap();
            proof.context = Some(vcdm.context.clone());

            verify_derived_proof(
                &vcdm,
                proof,
                &public_key,
                &document_loader(),
                &hasher,
                json_ld_processor_options(),
            )
            .await
            .unwrap();
        }
    }

    fn build_verifier() -> impl TokenVerifier {
        let mut verifier = MockTokenVerifier::new();
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

        verifier
            .expect_verify()
            .returning(move |_, _, token, signature| key_handle.verify(token, signature));

        verifier
    }
}
