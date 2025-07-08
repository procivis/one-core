use std::collections::{BTreeMap, HashMap};

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use json_ld::Loader;
use one_crypto::signer::bbs::{BBSSigner, BbsDeriveInput};
use one_crypto::utilities::build_hmac_sha256;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::canonicalize::{
    CanonicializeAndGroupOutput, canonicalize_and_group, create_shuffled_id_label_map_function,
};
use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::parse_base_proof_value;
use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::selection::select_json_ld;
use crate::provider::credential_formatter::json_ld_bbsplus::model::{
    BbsDerivedProofComponents, CBOR_PREFIX_DERIVED, ParsedBbsDerivedProofComponents,
};
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmProof};

// https://www.w3.org/TR/vc-di-bbs/#add-derived-proof-bbs-2023
pub async fn add_derived_proof(
    vcdm: &VcdmCredential,
    base_proof: &VcdmProof,
    selective_pointers: Vec<String>,
    presentation_header: Option<Vec<u8>>,
    loader: &impl Loader,
    options: json_ld::Options,
) -> Result<VcdmCredential, FormatterError> {
    let disclosure_data = create_disclosure_data(
        vcdm,
        base_proof,
        selective_pointers,
        presentation_header.clone(),
        loader,
        options,
    )
    .await?;

    let mut reveal_document: VcdmCredential =
        json_syntax::from_value(disclosure_data.reveal_document)
            .map_err(|e| FormatterError::Failed(format!("Invalid reveal document: {e}")))?;

    let proof_value = serialize_derived_proof_value(
        disclosure_data.bbs_proof,
        disclosure_data.verifier_label_map,
        disclosure_data.mandatory_indexes,
        disclosure_data.selective_indexes,
        presentation_header,
    )?;

    let mut new_proof = base_proof.clone();
    new_proof.proof_value = Some(proof_value);

    reveal_document.proof = Some(new_proof);

    Ok(reveal_document)
}

pub fn parse_derived_proof_value(
    proof_value: &str,
) -> Result<ParsedBbsDerivedProofComponents, FormatterError> {
    let Some(proof_value) = proof_value.strip_prefix("u") else {
        return Err(FormatterError::Failed(
            "Proof value is not multibase-base64url-no-pad-encoded".to_string(),
        ));
    };

    let proof_value = Base64UrlSafeNoPadding::decode_to_vec(proof_value, None)
        .map_err(|e| FormatterError::Failed(format!("Failed to b64 decoding proof value: {e}")))?;

    let proof_value = match &proof_value[..3] {
        prefix if prefix == CBOR_PREFIX_DERIVED => &proof_value[3..],
        other => {
            return Err(FormatterError::Failed(format!(
                "Invalid proof value. expected derived prefix got: {}",
                hex::encode(other)
            )));
        }
    };

    let proof_components: BbsDerivedProofComponents = ciborium::de::from_reader(proof_value)
        .map_err(|e| {
            FormatterError::Failed(format!("Failed to deserialize bbs+ proof components: {e}"))
        })?;

    let decompressed_label_map = decompress_label_map(proof_components.compressed_label_map)?;

    Ok(ParsedBbsDerivedProofComponents {
        bbs_proof: proof_components.bbs_proof,
        decompressed_label_map,
        mandatory_indexes: proof_components.mandatory_indexes,
        selective_indexes: proof_components.selective_indexes,
        presentation_header: proof_components.presentation_header,
    })
}

struct DisclosureData {
    bbs_proof: Vec<u8>,
    verifier_label_map: BTreeMap<String, String>,
    mandatory_indexes: Vec<usize>,
    selective_indexes: Vec<usize>,
    reveal_document: json_syntax::Value,
}

// Follows steps from: https://www.w3.org/TR/vc-di-bbs/#createdisclosuredata
async fn create_disclosure_data(
    vcdm: &VcdmCredential,
    base_proof: &VcdmProof,
    selective_pointers: Vec<String>,
    presentation_header: Option<Vec<u8>>,
    loader: &impl Loader,
    json_ld_processor_options: json_ld::Options,
) -> Result<DisclosureData, FormatterError> {
    let Some(proof_value) = base_proof.proof_value.as_ref() else {
        return Err(FormatterError::Failed(
            "VCDM proof is missing proofValue".to_string(),
        ));
    };

    // 1. Obtain proof components
    let proof_components = parse_base_proof_value(proof_value)?;

    // 2. Create hmac function
    let hmac = build_hmac_sha256(&proof_components.hmac_key).ok_or_else(|| {
        FormatterError::Failed("Failed to build HMAC-SHA256 for specified key".to_string())
    })?;

    // 3. Create label map factory function
    let label_map_factory_function = create_shuffled_id_label_map_function(hmac);

    // 4. Create combined pointers
    let combined_pointers: Vec<String> = [
        proof_components.mandatory_pointers.as_slice(),
        selective_pointers.as_slice(),
    ]
    .concat();

    // 5. Create group definitions
    let mut group_definitions = HashMap::new();
    group_definitions.insert(
        "mandatory".to_string(),
        proof_components.mandatory_pointers.as_slice(),
    );
    group_definitions.insert("selective".to_string(), selective_pointers.as_slice());
    group_definitions.insert("combined".to_string(), combined_pointers.as_slice());

    // 6. Canonicalize and group
    let document = json_syntax::to_value(vcdm).map_err(|e| {
        FormatterError::Failed(format!("Failed to convert VCDMCredential to JSON: {e}"))
    })?;
    let CanonicializeAndGroupOutput {
        groups, label_map, ..
    } = canonicalize_and_group(
        label_map_factory_function,
        group_definitions,
        document.clone(),
        loader,
        json_ld_processor_options,
    )
    .await?;

    let mandatory_group = groups.get("mandatory").ok_or_else(|| {
        FormatterError::Failed("Mandatory group not found in canonicalized document".to_string())
    })?;
    let selective_group = groups.get("selective").ok_or_else(|| {
        FormatterError::Failed("Selective group not found in canonicalized document".to_string())
    })?;
    let combined_group = groups.get("combined").ok_or_else(|| {
        FormatterError::Failed("Combined group not found in canonicalized document".to_string())
    })?;

    // 7. Compute mandatory indexes relative to combined group
    let mandatory_indexes: Vec<usize> = combined_group
        .matching
        .keys()
        .enumerate()
        .filter_map(|(relative_index, absolute_index)| {
            mandatory_group
                .matching
                .contains_key(absolute_index)
                .then_some(relative_index)
        })
        .collect();

    // 8. Compute selective indexes relative to combined group
    // 9. Create BBS messages
    let mut selective_indexes: Vec<usize> = Vec::new();
    let mut bbs_messages: Vec<(Vec<u8>, bool)> = Vec::new();
    for (relative_index, (absolute_index, msg)) in mandatory_group.non_matching.iter().enumerate() {
        if selective_group.matching.contains_key(absolute_index) {
            selective_indexes.push(relative_index);
            bbs_messages.push((msg.clone().into_bytes(), true));
        } else {
            bbs_messages.push((msg.clone().into_bytes(), false));
        }
    }
    // 10. Compute BBS proof
    let derive_input = BbsDeriveInput {
        header: proof_components.bbs_header,
        messages: bbs_messages,
        signature: proof_components.bbs_signature,
        presentation_header,
    };
    let bbs_proof = BBSSigner::derive_proof(derive_input, &proof_components.public_key)
        .map_err(|e| FormatterError::Failed(format!("Failed to derive BBS proof: {e}")))?;
    // 12. Generate reveal document (we skip step 11 as we default to baseline featureOption)
    let document = document.into_serde_json();
    let reveal_document = select_json_ld(&document, &combined_pointers)?;

    // 13. Get canonical id map from combined group deskolemized nquads
    let (_, canonical_id_map) = sophia_c14n::rdfc10::relabel(&combined_group.deskolemized_nquads)
        .map_err(|e| {
        FormatterError::Failed(format!("Failed to relabel combined group nquads: {e}"))
    })?;

    // 14. Create verifier label map
    let mut verifier_label_map = BTreeMap::new();
    for (input_label, verifier_label) in canonical_id_map {
        verifier_label_map.insert(
            verifier_label.to_string(),
            label_map[input_label.as_ref()].clone(),
        );
    }

    Ok(DisclosureData {
        bbs_proof,
        verifier_label_map,
        mandatory_indexes,
        selective_indexes,
        reveal_document: reveal_document.into(),
    })
}

fn serialize_derived_proof_value(
    bbs_proof: Vec<u8>,
    label_map: BTreeMap<String, String>,
    mandatory_indexes: Vec<usize>,
    selective_indexes: Vec<usize>,
    presentation_header: Option<Vec<u8>>,
) -> Result<String, FormatterError> {
    let compressed_label_map = compress_label_map(label_map)?;

    let bbs_derived_proof_components = BbsDerivedProofComponents {
        bbs_proof,
        compressed_label_map,
        mandatory_indexes,
        selective_indexes,
        presentation_header: presentation_header.unwrap_or_default(),
    };

    let mut proof_value = CBOR_PREFIX_DERIVED.to_vec();
    let mut cbor = Vec::new();
    ciborium::into_writer(&bbs_derived_proof_components, &mut cbor).map_err(|e| {
        FormatterError::Failed(format!(
            "Failed to serialize BBS derived proof components: {e}"
        ))
    })?;
    proof_value.extend(cbor);
    let proof_value = Base64UrlSafeNoPadding::encode_to_string(&proof_value).map_err(|e| {
        FormatterError::Failed(format!(
            "Failed to encode BBS derived proof components: {e}"
        ))
    })?;

    Ok(format!("u{proof_value}"))
}

fn compress_label_map(
    label_map: BTreeMap<String, String>,
) -> Result<BTreeMap<usize, usize>, FormatterError> {
    let mut map = BTreeMap::new();
    for (k, v) in label_map {
        let k = k
            .strip_prefix("c14n")
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or_else(|| FormatterError::Failed("Invalid label map key format".to_string()))?;

        let v = v
            .strip_prefix("b")
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or_else(|| FormatterError::Failed("Invalid label map value format".to_string()))?;

        map.insert(k, v);
    }

    Ok(map)
}

fn decompress_label_map(
    compressed_label_map: BTreeMap<usize, usize>,
) -> Result<BTreeMap<String, String>, FormatterError> {
    let mut map = BTreeMap::new();
    for (k, v) in compressed_label_map {
        let k = format!("c14n{k}");
        let v = format!("b{v}");
        map.insert(k, v);
    }

    Ok(map)
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;
    use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::test_data::{
        document_loader, vc_permanent_resident_card,
    };
    use crate::util::rdf_canonization::json_ld_processor_options;

    #[tokio::test]
    async fn test_create_disclosure_data() {
        let vcdm: VcdmCredential = json_syntax::from_value(vc_permanent_resident_card()).unwrap();
        let proof: VcdmProof = json_syntax::from_value(json_syntax::json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "bbs-2023",
            "created": "2023-08-15T23:36:38Z",
            "verificationMethod": "did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ",
            "proofPurpose": "assertionMethod",
            "proofValue": "u2V0ChVhQhhaN0rXQx8alajD0IS7RFqU97wXQ1nCCB9SDx_8gU676ItJLp2WdYIUmlPjYW-D6Ktw5dMfcTMaLPbF7JCOXUEcQQWLCRQK0FZGHmsJPG7FYQDpbvyXTTZCxjDXNI1e-am9CMB6U_J5S936Tt3PFYUvfjnzCLDGN0glOAtC_BsXXOl26cXYRpA9tG-3F6nwwD9ZYYKTvGvo9pXVJbxIrm3i4wkdhUxqKCTIGrnxFuAdZwWi6T3omD5wzZ7bAGbRneEEQSxBmXtvnC6Pr59nPv_v3HrAW9wq_uxYzF_NyaX3GPv0h_FV2T2OSao8C6uoyWiqIj1ggABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v-BZy9pc3N1ZXI"
        })).unwrap();

        let selective_pointers = [
            "/validFrom",
            "/validUntil",
            "/credentialSubject/birthCountry",
        ]
        .map(ToString::to_string)
        .to_vec();
        let presentation_header = hex::decode("113377aa").unwrap();
        let disclosure_data = create_disclosure_data(
            &vcdm,
            &proof,
            selective_pointers,
            Some(presentation_header),
            &document_loader(),
            json_ld_processor_options(),
        )
        .await
        .unwrap();

        assert_eq!(
            disclosure_data.reveal_document.into_serde_json(),
            serde_json::json!({
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
              }
            })
        );

        assert_eq!(disclosure_data.mandatory_indexes, vec![0, 4, 5, 7]);
        assert_eq!(disclosure_data.selective_indexes, vec![0, 1, 7, 17, 18, 19]);
        assert_eq!(
            disclosure_data.verifier_label_map,
            maplit::btreemap! {
                "c14n0".to_string() => "b0".to_string(),
                "c14n1".to_string() => "b2".to_string(),
            }
        );
    }

    #[test]
    fn test_serialize_derived_proof_value() {
        let bbs_proof = hex::decode("96ac5ff7b89bf2d8b0f3cc51c547f1a22b01e24e246579d212362cdf6bf0fabe18be0c9d1f84c904bb4c6c613fd0ecabb7ad92e615341da9\
        7a45a918721626cc859c455b473a36e39572561d5fc483c637424717a43dcffb3b130d8fe11f88a8802f3b231efe2444f8b47feded0b621e3d5cd22cb3ec23ebc4f6dca745b5c1ce2f42a710b925\
        10a71225a7d39e00e0c26da2fae242cdf154e93de42017270b99023fe95b42c42a461a2eab19e04aa44839af39aa71f830162cb424a5aa0acc046dc7e7b8bdfc73cf3641c76aeeb7fbb56cd936776\
        050dbd632bf7fc80d33c621dc6b837184ade619630f72bd25d8aea626ba994d15a65def1b0dc8af09c54a0cf5e5b54d1b1b28047aa2dbf63805fec9533bab46d12349ca47dfd83ff30454cedacd23\
        da4eb9a3ebe198c80ac1992e2a203ffcf46afaa3482a63b7b00033df1a2da361d600a1cfd5139be010ca302e082af7ee34a5ff3d24cc7062f57fa36d47846edd5219e59bd438576bff709bfd7920d\
        6bad8367b0fe8c749318ef8726beda9c1d9095bed738e4fd1c38333a27f4f2071a21a863671b43fe521f737444be865e887cbf33caa39226fb8013003721e37c6d949867befba1c8b7bf641bd6478\
        51ad92aed3da91af52f17d058a9f74eb30744304c05813840be6a528f54cd5a24b73ae2f42dec1bfc2e1354fb061a96c0df3ab96ddc9ada96cb882571cccb89774fcf0326e1c8b2b87cc4cf4eafbd\
        75632518919cbe58a9f86ade12b0f6989c0886e358d801b99b1dd32c7e6e56a653c0e264a84b51d2d23679c75e282451af3bcaa6f19ec7bc3aa603fec87db5a57d42961e2907d899a8fd5d1ce17dd\
        e8a75cd1192494cd93b112da7774c2bb2f679f5b4b404dabe485d78a017b2be81e5ff8bacf90d5f24b2e83ab4169f8f55ca6f703141f91565abbec7445e6cf4663f5e34b9188283d57cedf36c586b\
        18a130b83652436bf6862673ddeebd9aefdc2fbfc97dde80e36483491c4357ccd2fc131fb").unwrap();

        let label_map = maplit::btreemap! {
            "c14n0".to_string() => "b0".to_string(),
            "c14n1".to_string() => "b2".to_string(),
        };
        let mandatory_indexes = vec![0, 4, 5, 7];
        let selective_indexes = vec![0, 1, 7, 17, 18, 19];
        let presentation_header = hex::decode("113377aa").unwrap();

        let proof_value = serialize_derived_proof_value(
            bbs_proof,
            label_map,
            mandatory_indexes,
            selective_indexes,
            Some(presentation_header),
        )
        .unwrap();

        assert_eq!(
            proof_value,
            "u2V0DhVkC0JasX_e4m_LYsPPMUcVH8aIrAeJOJGV50hI2LN9r8Pq-GL4MnR-EyQS7TGxhP9Dsq7etkuYVNB2pekWpGHIWJsyFnEVbRzo245VyVh1fxIPGN0JHF6Q9\
            z_s7Ew2P4R-IqIAvOyMe_iRE-LR_7e0LYh49XNIss-wj68T23KdFtcHOL0KnELklEKcSJafTngDgwm2i-uJCzfFU6T3kIBcnC5kCP-lbQsQqRhouqxngSqRIOa85qn\
            H4MBYstCSlqgrMBG3H57i9_HPPNkHHau63-7Vs2TZ3YFDb1jK_f8gNM8Yh3GuDcYSt5hljD3K9Jdiupia6mU0Vpl3vGw3IrwnFSgz15bVNGxsoBHqi2_Y4Bf7JUzur\
            RtEjScpH39g_8wRUztrNI9pOuaPr4ZjICsGZLiogP_z0avqjSCpjt7AAM98aLaNh1gChz9UTm-AQyjAuCCr37jSl_z0kzHBi9X-jbUeEbt1SGeWb1DhXa_9wm_15IN\
            a62DZ7D-jHSTGO-HJr7anB2Qlb7XOOT9HDgzOif08gcaIahjZxtD_lIfc3REvoZeiHy_M8qjkib7gBMANyHjfG2UmGe--6HIt79kG9ZHhRrZKu09qRr1LxfQWKn3Tr\
            MHRDBMBYE4QL5qUo9UzVoktzri9C3sG_wuE1T7BhqWwN86uW3cmtqWy4glcczLiXdPzwMm4ciyuHzEz06vvXVjJRiRnL5Yqfhq3hKw9picCIbjWNgBuZsd0yx-blam\
            U8DiZKhLUdLSNnnHXigkUa87yqbxnse8OqYD_sh9taV9QpYeKQfYmaj9XRzhfd6Kdc0RkklM2TsRLad3TCuy9nn1tLQE2r5IXXigF7K-geX_i6z5DV8ksug6tBafj1\
            XKb3AxQfkVZau-x0RebPRmP140uRiCg9V87fNsWGsYoTC4NlJDa_aGJnPd7r2a79wvv8l93oDjZINJHENXzNL8Ex-6IAAAEChAAEBQeGAAEHERITRBEzd6o"
        );
    }
}
