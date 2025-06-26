use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use indexmap::IndexMap;
use itertools::Itertools;
use json_ld::{JsonLdProcessor, Loader, RemoteDocument, rdf_types};
use regex::{Captures, Regex};
use sophia_api::quad::Spog;
use sophia_c14n::rdfc10::C14nIdMap;

use super::NQuadLines;
use super::selection::{SelectionResult, select_canonical_nquads};
use super::skolemize::{skolemize_compact_json_ld, to_deskolemized_nquads};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::canonization::TermAdapter;

static BLANK_NODE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(_:([^\s]+))"#).expect("Failed to compile regex"));

pub struct CanonicializeAndGroupOutput {
    pub groups: HashMap<String, GroupEntry>,
    pub _deskolemized_nquads: HashSet<Spog<TermAdapter>>,
    pub label_map: BTreeMap<String, String>,
    pub _nquads: Vec<String>,
}

pub struct GroupEntry {
    pub matching: IndexMap<usize, String>,
    pub non_matching: IndexMap<usize, String>,
    pub deskolemized_nquads: HashSet<Spog<TermAdapter>>,
}

pub async fn canonicalize_and_group(
    label_map_factory_function: impl FnMut(
        C14nIdMap,
    ) -> Result<BTreeMap<String, String>, FormatterError>,
    group_definitions: HashMap<String, &[String]>,
    document: json_syntax::Value,
    loader: &impl Loader,
    options: json_ld::Options,
) -> Result<CanonicializeAndGroupOutput, FormatterError> {
    // skolemize jsonld document
    let skolemized = skolemize_compact_json_ld(document, loader, options.clone()).await?;
    // get deskolemized nquads
    let deskolemized_nquads: HashSet<Spog<TermAdapter>> =
        to_deskolemized_nquads(&skolemized.expanded);
    // get canonicalize nquads from deskolemized nquads
    let (nquads, label_map) = label_replacement_canonicalize_nquads(
        deskolemized_nquads.clone(),
        label_map_factory_function,
    )?;
    // for each group, select the canonical nquads matching the pointers
    let document = skolemized.compact.clone().into_serde_json();

    let mut selections = HashMap::new();
    for (name, pointers) in group_definitions {
        let selection =
            select_canonical_nquads(&document, pointers, &label_map, loader, options.clone())
                .await?;
        selections.insert(name, selection);
    }

    // group matching and non matching nquads
    let mut groups = HashMap::new();
    for (name, selection_result) in selections {
        let SelectionResult {
            selected_deskolemized_nquads,
            selected_nquads,
            ..
        } = selection_result;

        let mut matching = IndexMap::new();
        let mut non_matching = IndexMap::new();

        for (index, nq) in nquads.iter().enumerate() {
            if selected_nquads.nquad_lines().any(|line| nq == &line) {
                matching.insert(index, nq.clone());
            } else {
                non_matching.insert(index, nq.clone());
            }
        }

        groups.insert(
            name,
            GroupEntry {
                matching,
                non_matching,
                deskolemized_nquads: selected_deskolemized_nquads,
            },
        );
    }

    Ok(CanonicializeAndGroupOutput {
        groups,
        _deskolemized_nquads: deskolemized_nquads,
        label_map,
        _nquads: nquads,
    })
}

pub fn label_replacement_canonicalize_nquads(
    nquads: HashSet<Spog<TermAdapter>>,
    label_map_factory_function: impl FnMut(
        C14nIdMap,
    ) -> Result<BTreeMap<String, String>, FormatterError>,
) -> Result<(Vec<String>, BTreeMap<String, String>), FormatterError> {
    let (_, canonical_id_map) = sophia_c14n::rdfc10::relabel(&nquads)
        .map_err(|e| FormatterError::Failed(format!("Failed to relabel nquads: {e}")))?;

    let mut label_map_factory_function = label_map_factory_function;
    let label_map = label_map_factory_function(canonical_id_map.clone())?;
    let c14n_label_map: BTreeMap<String, String> = label_map
        .iter()
        .map(|(key, new_label)| {
            let key = &canonical_id_map[key.as_str()];
            (key.to_string(), new_label.to_string())
        })
        .collect();

    let canonical_nquads = {
        let mut canonical_nquads = Vec::<u8>::new();
        sophia_c14n::rdfc10::normalize(&nquads, &mut canonical_nquads)
            .map_err(|e| FormatterError::Failed(format!("Failed to normalize nquads: {e}")))?;
        String::from_utf8(canonical_nquads).map_err(|e| {
            FormatterError::Failed(format!("Failed to convert nquads to string: {e}"))
        })?
    };

    let canonical_nquads: Vec<String> = canonical_nquads
        .split_inclusive('\n')
        .map(|quad| {
            BLANK_NODE_REGEX
                .replace_all(quad, |capture: &Captures<'_>| {
                    let old_label = &capture[2];
                    let new_label = &c14n_label_map[old_label];
                    format!("_:{new_label}")
                })
                .into_owned()
        })
        .sorted()
        .collect();

    Ok((canonical_nquads, label_map))
}

pub async fn label_replacement_canonicalize_json_ld(
    document: json_syntax::Value,
    label_map_factory_function: impl FnMut(
        C14nIdMap,
    ) -> Result<BTreeMap<String, String>, FormatterError>,
    loader: &impl Loader,
    json_ld_processor_options: json_ld::Options,
) -> Result<Vec<String>, FormatterError> {
    let document = RemoteDocument::new(None, None, document);
    let labeler = rdf_types::generator::Blank::new_with_prefix("b".to_string());
    let quads: HashSet<Spog<TermAdapter>> = document
        .to_rdf_using(labeler, &loader, json_ld_processor_options)
        .await
        .map_err(|e| {
            FormatterError::Failed(format!(
                "Failed to expand document during label replacement step: {e}"
            ))
        })?
        .cloned_quads()
        .map(|quad| {
            let (subject, predicate, object, maybe_graph) = quad.into_parts();
            (
                [subject.into_term(), predicate.into_term(), object].map(TermAdapter),
                maybe_graph.map(|graph| TermAdapter(graph.into_term())),
            )
        })
        .collect();

    Ok(label_replacement_canonicalize_nquads(quads, label_map_factory_function)?.0)
}

// https://www.w3.org/TR/vc-di-bbs/#createshuffledidlabelmapfunction
pub fn create_shuffled_id_label_map_function(
    hmac: impl FnMut(&[u8]) -> Vec<u8>,
) -> impl FnMut(C14nIdMap) -> Result<BTreeMap<String, String>, FormatterError> {
    let mut hmac = hmac;
    move |canonical_id_map| {
        let mut bnode_id_map = Vec::new();

        for (input, c14n_label) in canonical_id_map {
            let digest = hmac(c14n_label.as_bytes());
            let b64url_digest = Base64UrlSafeNoPadding::encode_to_string(&digest)
                .map_err(|e| FormatterError::Failed(e.to_string()))?;
            bnode_id_map.push((input, format!("u{b64url_digest}")));
        }
        // Derive the shuffled mapping from the bnode_id_map
        // sort by hmac ids.
        bnode_id_map.sort_by(|(_, v1), (_, v2)| v1.cmp(v2));

        Ok(bnode_id_map
            .into_iter()
            .enumerate()
            .map(|(index, (key, _))| (key.to_string(), format!("b{index}")))
            .collect())
    }
}
// https://www.w3.org/TR/vc-di-ecdsa/#createlabelmapfunction
pub fn create_label_map_function(
    label_map: BTreeMap<String, String>,
) -> impl FnMut(C14nIdMap) -> Result<BTreeMap<String, String>, FormatterError> {
    move |canonical_id_map| {
        let mut bnode_id_map = BTreeMap::new();

        for (input, c14n_label) in canonical_id_map {
            bnode_id_map.insert(input.to_string(), label_map[c14n_label.as_str()].clone());
        }

        Ok(bnode_id_map)
    }
}

#[cfg(test)]
mod test {
    use one_crypto::utilities::build_hmac_sha256;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::provider::credential_formatter::json_ld::json_ld_processor_options;
    use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::test_data::{
        document_loader, vc_permanent_resident_card,
    };

    #[tokio::test]
    // test using data from basic test vector https://www.w3.org/TR/vc-di-bbs/#base-proof
    async fn test_canonicalise_and_group() {
        let hmac_key =
            hex_literal::hex!("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");
        let hmac = build_hmac_sha256(&hmac_key).unwrap();
        let label_map_factory_function = create_shuffled_id_label_map_function(hmac);

        let document = vc_permanent_resident_card();
        let loader = document_loader();
        let mandatory_pointers = [
            "/issuer",
            "/credentialSubject/givenName",
            "/credentialSubject/birthDate",
            "/credentialSubject/permanentResidentCard/identifier",
        ]
        .map(ToString::to_string);

        let mut result = canonicalize_and_group(
            label_map_factory_function,
            maplit::hashmap! {
                "mandatory".into() => mandatory_pointers.as_slice(),
            },
            document,
            &loader,
            json_ld_processor_options(),
        )
        .await
        .unwrap();

        assert_eq!(result.groups.len(), 1);

        let mandatory = result.groups.remove("mandatory").unwrap();

        let expected_matching = indexmap::indexmap! {
            0 => "<did:key:zDnaeTHxNEBZoKaEo6PdA83fq98ebiFvo3X273Ydu4YmV96rg> <https://schema.org/image> <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2P4z/DiPwAG0ALnwgz64QAAAABJRU5ErkJggg==> .\n",
            1 => "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://schema.org/Person> .\n",
            2 => "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .\n",
            3 => "_:b0 <https://schema.org/birthDate> \"1978-07-17\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n",
            6 => "_:b0 <https://schema.org/givenName> \"JANE\" .\n",
            10 => "_:b0 <https://w3id.org/citizenship#permanentResidentCard> _:b1 .\n",
            12 => "_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .\n",
            13 => "_:b1 <https://schema.org/identifier> \"83627465\" .\n",
            16 => "_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCardCredential> .\n",
            17 => "_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n",
            20 => "_:b2 <https://www.w3.org/2018/credentials#credentialSubject> _:b0 .\n",
            21 => "_:b2 <https://www.w3.org/2018/credentials#issuer> <did:key:zDnaeTHxNEBZoKaEo6PdA83fq98ebiFvo3X273Ydu4YmV96rg> .\n"
        };

        let expected_non_matching = indexmap::indexmap! {
            4 => "_:b0 <https://schema.org/familyName> \"SMITH\" .\n",
            5 => "_:b0 <https://schema.org/gender> \"Female\" .\n",
            7 => "_:b0 <https://schema.org/image> <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2P4v43hPwAHIgK1v4tX6wAAAABJRU5ErkJggg==> .\n",
            8 => "_:b0 <https://w3id.org/citizenship#birthCountry> \"Arcadia\" .\n",
            9 => "_:b0 <https://w3id.org/citizenship#commuterClassification> \"C1\" .\n",
            11 => "_:b0 <https://w3id.org/citizenship#residentSince> \"2015-01-01\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n",
            14 => "_:b1 <https://w3id.org/citizenship#lprCategory> \"C09\" .\n",
            15 => "_:b1 <https://w3id.org/citizenship#lprNumber> \"999-999-999\" .\n",
            18 => "_:b2 <https://schema.org/description> \"Permanent Resident Card from Government of Utopia.\" .\n",
            19 => "_:b2 <https://schema.org/name> \"Permanent Resident Card\" .\n",
            22 => "_:b2 <https://www.w3.org/2018/credentials#validFrom> \"2024-12-16T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n",
            23 => "_:b2 <https://www.w3.org/2018/credentials#validUntil> \"2025-12-16T23:59:59Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n"
        };

        assert_eq!(mandatory.matching, expected_matching);
        assert_eq!(mandatory.non_matching, expected_non_matching);
        assert_eq!(mandatory.deskolemized_nquads.len(), 12);
    }
}
