use std::collections::HashSet;

use json_ld::context_processing::ProcessedOwned;
use json_ld::rdf::RdfDirection;
use json_ld::rdf_types::Generator;
use json_ld::{
    BlankIdBuf, Compact, ExpandedDocument, ExtractContext, IriBuf, JsonLdProcessor, Loader,
    Process, RdfQuads, RemoteDocument, rdf_types,
};
use sophia_api::quad::Spog;
use uuid::Uuid;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::canonization::TermAdapter;

const URN_CUSTOM_SCHEME_PREFIX: &str = "urn:bnid:";

pub struct SkolemizedDocument {
    pub expanded: ExpandedDocument,
    pub compact: json_syntax::Value,
}

pub async fn skolemize_compact_json_ld(
    document: json_syntax::Value,
    loader: &impl Loader,
    json_ld_processor_options: json_ld::Options,
) -> Result<SkolemizedDocument, FormatterError> {
    let document = RemoteDocument::new(None, None, document);
    // expand document
    let mut expanded = document
        .expand_with_using(&mut (), &loader, json_ld_processor_options)
        .await
        .map_err(|e| {
            FormatterError::Failed(format!(
                "Failed to expand document during skolemization step: {e}"
            ))
        })?;

    // skolemize expanded document
    let mut labeler = CustomUrnSchemaBlankNodeLabeler::default();
    expanded.relabel_and_canonicalize(&mut labeler);

    // skolemize compact document
    let processed_context = match document.into_document().into_ld_context() {
        Ok(context) => {
            let processed_context = context
                .process(&mut (), &loader, None)
                .await
                .map_err(|e| FormatterError::Failed(format!("Failed to process context: {e}")))?
                .into_processed();

            ProcessedOwned::new(context, processed_context)
        }
        Err(_) => ProcessedOwned::new(Default::default(), Default::default()),
    };

    let compact = expanded
        .compact(processed_context.as_ref(), loader)
        .await
        .map_err(|e| FormatterError::Failed(format!("Failed to compact document: {e}")))?;

    Ok(SkolemizedDocument { expanded, compact })
}

pub fn to_deskolemized_nquads(document: &ExpandedDocument) -> HashSet<Spog<TermAdapter>> {
    let mut labeler = rdf_types::generator::Blank::new_with_prefix("b".to_string());
    // convert to rdf quads
    document
        .rdf_quads(&mut labeler, Some(RdfDirection::I18nDatatype))
        .cloned()
        .map(|quad| {
            let (subject, predicate, object, maybe_graph) = quad.into_parts();
            (
                [subject.into_term(), predicate.into_term(), object].map(TermAdapter),
                maybe_graph.map(|graph| TermAdapter(graph.into_term())),
            )
        })
        .map(deskolemize_quad)
        .collect()
}

fn deskolemize_quad((triple, graph): Spog<TermAdapter>) -> Spog<TermAdapter> {
    let custom_scheme_iri_to_bnode = |TermAdapter(term): TermAdapter| match term {
        rdf_types::Term::Id(rdf_types::Id::Iri(iri))
            if iri.starts_with(URN_CUSTOM_SCHEME_PREFIX) =>
        {
            let suffix = &iri[URN_CUSTOM_SCHEME_PREFIX.len()..];
            let bid = BlankIdBuf::new(format!("_:{suffix}"))
                .expect("should always be a valid BlankIdBuf");
            TermAdapter(rdf_types::Term::Id(rdf_types::Id::Blank(bid)))
        }
        _ => TermAdapter(term),
    };

    (
        triple.map(custom_scheme_iri_to_bnode),
        graph.map(custom_scheme_iri_to_bnode),
    )
}

#[derive(Default)]
struct CustomUrnSchemaBlankNodeLabeler {
    count: usize,
}

impl Generator for CustomUrnSchemaBlankNodeLabeler {
    fn next(&mut self, _: &mut ()) -> rdf_types::Id {
        let random = Uuid::new_v4();
        let bid = IriBuf::new(format!("{URN_CUSTOM_SCHEME_PREFIX}{random}_{}", self.count))
            .expect("should always be a valid Iri");
        self.count += 1;
        rdf_types::Id::Iri(bid)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::str::FromStr;

    use itertools::Itertools;
    use json_ld::IriBuf;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::provider::credential_formatter::json_ld::json_ld_processor_options;
    use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::NQuadLines;
    use crate::provider::credential_formatter::json_ld_bbsplus::data_integrity::test_data::{
        context_examples_vocabulary, context_vc2_0,
    };

    #[tokio::test]
    async fn test_skolemize_jsonld() {
        let document = json_syntax::json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential", "ExamplePersonCredential"],
            "issuer": "https://university.example/issuers/14",
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                    "type": "ExampleBachelorDegree",
                    "name": "Bachelor of Science and Arts"
                },
                "alumniOf": {
                    "name": "Example University"
                }
            },
            "credentialSchema": [{
                "id": "https://example.org/examples/degree.json",
                "type": "JsonSchema"
            }]
        });

        let mut loader: HashMap<IriBuf, RemoteDocument> = HashMap::new();
        loader.insert(
            IriBuf::from_str("https://www.w3.org/ns/credentials/v2").unwrap(),
            RemoteDocument::new(None, None, context_vc2_0()),
        );
        loader.insert(
            IriBuf::from_str("https://www.w3.org/ns/credentials/examples/v2").unwrap(),
            RemoteDocument::new(None, None, context_examples_vocabulary()),
        );

        let skolemized = skolemize_compact_json_ld(document, &loader, json_ld_processor_options())
            .await
            .unwrap();

        let compact = skolemized.compact.into_serde_json();

        assert!(
            compact["credentialSubject"]["degree"]["id"]
                .as_str()
                .unwrap()
                .starts_with(URN_CUSTOM_SCHEME_PREFIX)
        );

        assert!(
            compact["credentialSubject"]["alumniOf"]["id"]
                .as_str()
                .unwrap()
                .starts_with(URN_CUSTOM_SCHEME_PREFIX)
        );
    }

    #[tokio::test]
    async fn test_deskolemize_nquads() {
        // document with custom schema for blank nodes
        let document = json_syntax::json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential", "ExamplePersonCredential"],
            "issuer": "https://university.example/issuers/14",
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                    "id": "urn:bnid:uuid_0",
                    "type": "ExampleBachelorDegree",
                    "name": "Bachelor of Science and Arts"
                },
                "alumniOf": {
                    "id": "urn:bnid:uuid_1",
                    "name": "Example University"
                }
            },
            "credentialSchema": [{
                "id": "https://example.org/examples/degree.json",
                "type": "JsonSchema"
            }]
        });

        let mut loader: HashMap<IriBuf, RemoteDocument> = HashMap::new();
        loader.insert(
            IriBuf::from_str("https://www.w3.org/ns/credentials/v2").unwrap(),
            RemoteDocument::new(None, None, context_vc2_0()),
        );
        loader.insert(
            IriBuf::from_str("https://www.w3.org/ns/credentials/examples/v2").unwrap(),
            RemoteDocument::new(None, None, context_examples_vocabulary()),
        );

        let expanded = RemoteDocument::new(None, None, document)
            .expand(&loader)
            .await
            .unwrap();

        let nquads = to_deskolemized_nquads(&expanded);

        let nquads: String = nquads.nquad_lines().sorted().collect();

        assert_eq!(
            nquads,
            r#"<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://www.w3.org/ns/credentials/examples#alumniOf> _:uuid_1 .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://www.w3.org/ns/credentials/examples#degree> _:uuid_0 .
<http://university.example/credentials/3732> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://university.example/credentials/3732> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/credentials/examples#ExampleDegreeCredential> .
<http://university.example/credentials/3732> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/credentials/examples#ExamplePersonCredential> .
<http://university.example/credentials/3732> <https://www.w3.org/2018/credentials#credentialSchema> <https://example.org/examples/degree.json> .
<http://university.example/credentials/3732> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:ebfeb1f712ebc6f1c276e12ec21> .
<http://university.example/credentials/3732> <https://www.w3.org/2018/credentials#issuer> <https://university.example/issuers/14> .
<http://university.example/credentials/3732> <https://www.w3.org/2018/credentials#validFrom> "2010-01-01T19:23:24Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://example.org/examples/degree.json> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#JsonSchema> .
_:uuid_0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/credentials/examples#ExampleBachelorDegree> .
_:uuid_0 <https://schema.org/name> "Bachelor of Science and Arts" .
_:uuid_1 <https://schema.org/name> "Example University" .
"#
        );
    }
}
