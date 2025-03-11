use std::collections::HashSet;
use std::string::FromUtf8Error;

use json_ld::{rdf_types, Loader};
use serde::Serialize;
use sophia_api::quad::Spog;
use sophia_api::term::{Term, TermKind};
use sophia_api::MownStr;
use sophia_c14n::rdfc10;

#[derive(Debug, thiserror::Error)]
pub enum CanonizationError {
    #[error("Document is not a valid JSON: {0}")]
    DocumentParsing(#[from] json_syntax::SerializeError),
    #[error("Document expansion failed: {0}")]
    DocumentExpansion(#[from] json_ld::ToRdfError),
    #[error("c14n normalization failed: {0}")]
    C14nNormalization(#[from] sophia_c14n::C14nError<std::convert::Infallible>),
    #[error("Normalized document contains non UTF-8 characters: {0}")]
    NonUtf8Document(#[from] FromUtf8Error),
}

pub(super) async fn canonize(
    document: impl Serialize,
    loader: &impl Loader,
    options: json_ld::Options,
) -> Result<String, CanonizationError> {
    let generator = rdf_types::generator::Blank::new();
    let document = json_syntax::to_value(document)?;

    let document = json_ld::RemoteDocument::new(None, None, document);
    let mut rdf =
        json_ld::JsonLdProcessor::to_rdf_using(&document, generator, loader, options).await?;

    let quads: HashSet<Spog<TermAdapter>> = rdf
        .cloned_quads()
        .map(|quad| {
            let (subject, predicate, object, maybe_graph) = quad.into_parts();
            (
                [subject.into_term(), predicate.into_term(), object].map(TermAdapter),
                maybe_graph.map(|graph| TermAdapter(graph.into_term())),
            )
        })
        .collect();

    let mut buf = Vec::<u8>::new();
    rdfc10::normalize(&quads, &mut buf)?;

    Ok(String::from_utf8(buf)?)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct TermAdapter(pub rdf_types::Term);

impl Term for TermAdapter {
    type BorrowTerm<'x> = &'x Self;

    fn kind(&self) -> TermKind {
        match self.0 {
            rdf_types::Term::Id(rdf_types::Id::Blank(_)) => TermKind::BlankNode,
            rdf_types::Term::Id(rdf_types::Id::Iri(_)) => TermKind::Iri,
            rdf_types::Term::Literal(_) => TermKind::Literal,
        }
    }

    fn borrow_term(&self) -> Self::BorrowTerm<'_> {
        self
    }

    fn iri(&self) -> Option<sophia_api::term::IriRef<MownStr>> {
        match &self.0 {
            rdf_types::Term::Id(rdf_types::Id::Iri(iri)) => {
                sophia_api::term::IriRef::new(MownStr::from_ref(iri)).ok()
            }
            _ => None,
        }
    }

    fn bnode_id(&self) -> Option<sophia_api::term::BnodeId<MownStr>> {
        match &self.0 {
            rdf_types::Term::Id(rdf_types::Id::Blank(bnode_id)) => {
                sophia_api::term::BnodeId::new(MownStr::from_ref(&bnode_id[2..])).ok()
            }
            _ => None,
        }
    }

    fn lexical_form(&self) -> Option<MownStr> {
        match &self.0 {
            rdf_types::Term::Literal(lit) => Some(MownStr::from_ref(lit.as_value())),
            _ => None,
        }
    }

    fn datatype(&self) -> Option<sophia_api::term::IriRef<MownStr>> {
        match &self.0 {
            rdf_types::Term::Literal(lit) => match lit.as_type() {
                rdf_types::LiteralType::Any(iri) => {
                    sophia_api::term::IriRef::new(MownStr::from_ref(iri)).ok()
                }
                rdf_types::LiteralType::LangString(_) => sophia_api::ns::rdf::langString.iri(),
            },
            _ => None,
        }
    }

    fn language_tag(&self) -> Option<sophia_api::term::LanguageTag<MownStr>> {
        match &self.0 {
            rdf_types::Term::Literal(lit) => match lit.as_type() {
                rdf_types::LiteralType::LangString(tag) => {
                    let tag = MownStr::from_ref(tag.as_str());
                    sophia_api::term::LanguageTag::new(tag).ok()
                }
                rdf_types::LiteralType::Any(_) => None,
            },
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::str::FromStr;

    use json_ld::{IriBuf, RemoteDocument};

    use super::canonize;
    use crate::provider::credential_formatter::json_ld::json_ld_processor_options;

    #[tokio::test]
    async fn test_json_ld_canonization_ok() {
        let doc = json_syntax::json!({
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
            RemoteDocument::new(None, None, v2_context()),
        );
        loader.insert(
            IriBuf::from_str("https://www.w3.org/ns/credentials/examples/v2").unwrap(),
            RemoteDocument::new(None, None, example_context()),
        );

        // Generated on https://json-ld.org/playground/
        let expected = r#"<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://www.w3.org/ns/credentials/examples#alumniOf> _:c14n0 .
<did:example:ebfeb1f712ebc6f1c276e12ec21> <https://www.w3.org/ns/credentials/examples#degree> _:c14n1 .
<http://university.example/credentials/3732> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://university.example/credentials/3732> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/credentials/examples#ExampleDegreeCredential> .
<http://university.example/credentials/3732> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/credentials/examples#ExamplePersonCredential> .
<http://university.example/credentials/3732> <https://www.w3.org/2018/credentials#credentialSchema> <https://example.org/examples/degree.json> .
<http://university.example/credentials/3732> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:ebfeb1f712ebc6f1c276e12ec21> .
<http://university.example/credentials/3732> <https://www.w3.org/2018/credentials#issuer> <https://university.example/issuers/14> .
<http://university.example/credentials/3732> <https://www.w3.org/2018/credentials#validFrom> "2010-01-01T19:23:24Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://example.org/examples/degree.json> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#JsonSchema> .
_:c14n0 <https://schema.org/name> "Example University" .
_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/credentials/examples#ExampleBachelorDegree> .
_:c14n1 <https://schema.org/name> "Bachelor of Science and Arts" .
"#;

        let canonical_doc = canonize(doc, &loader, json_ld_processor_options())
            .await
            .unwrap();
        assert_eq!(canonical_doc, expected)
    }

    #[tokio::test]
    async fn test_proof_canonization_ok() {
        let proof = json_syntax::json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2"
            ],
            "type": "DataIntegrityProof",
            "verificationMethod": "did:key:zUC76eySqgji6uNDaCrsWnmQnwq8pj1MZUDrRGc2BGRu61baZPKPFB7YpHawussp2YohcEMAeMVGHQ9JtKvjxgGTkYSMN53ZfCH4pZ6TGYLawvzy1wE54dS6PQcut9fxdHH32gi#zUC76eySqgji6uNDaCrsWnmQnwq8pj1MZUDrRGc2BGRu61baZPKPFB7YpHawussp2YohcEMAeMVGHQ9JtKvjxgGTkYSMN53ZfCH4pZ6TGYLawvzy1wE54dS6PQcut9fxdHH32gi",
            "cryptosuite": "bbs-2023",
            "proofPurpose": "assertionMethod"
        });

        let mut loader: HashMap<IriBuf, RemoteDocument> = HashMap::new();
        loader.insert(
            IriBuf::from_str("https://www.w3.org/ns/credentials/v2").unwrap(),
            RemoteDocument::new(None, None, v2_context()),
        );

        let canonical_doc = canonize(proof, &loader, json_ld_processor_options())
            .await
            .unwrap();

        assert_eq!(canonical_doc,
        "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .\n\
        _:c14n0 <https://w3id.org/security#cryptosuite> \"bbs-2023\"^^<https://w3id.org/security#cryptosuiteString> .\n\
        _:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .\n\
        _:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC76eySqgji6uNDaCrsWnmQnwq8pj1MZUDrRGc2BGRu61baZPKPFB7YpHawussp2YohcEMAeMVGHQ9JtKvjxgGTkYSMN53ZfCH4pZ6TGYLawvzy1wE54dS6PQcut9fxdHH32gi#zUC76eySqgji6uNDaCrsWnmQnwq8pj1MZUDrRGc2BGRu61baZPKPFB7YpHawussp2YohcEMAeMVGHQ9JtKvjxgGTkYSMN53ZfCH4pZ6TGYLawvzy1wE54dS6PQcut9fxdHH32gi> .\n"
        );
    }

    fn v2_context() -> json_syntax::Value {
        json_syntax::Value::from_str(
            r#"
            {
                "@context": {
                    "@protected": true,

                    "id": "@id",
                    "type": "@type",

                    "description": "https://schema.org/description",
                    "digestMultibase": {
                    "@id": "https://w3id.org/security#digestMultibase",
                    "@type": "https://w3id.org/security#multibase"
                    },
                    "digestSRI": {
                    "@id": "https://www.w3.org/2018/credentials#digestSRI",
                    "@type": "https://www.w3.org/2018/credentials#sriString"
                    },
                    "mediaType": {
                    "@id": "https://schema.org/encodingFormat"
                    },
                    "name": "https://schema.org/name",

                    "VerifiableCredential": {
                    "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
                    "@context": {
                        "@protected": true,

                        "id": "@id",
                        "type": "@type",

                        "confidenceMethod": {
                        "@id": "https://www.w3.org/2018/credentials#confidenceMethod",
                        "@type": "@id"
                        },
                        "credentialSchema": {
                        "@id": "https://www.w3.org/2018/credentials#credentialSchema",
                        "@type": "@id"
                        },
                        "credentialStatus": {
                        "@id": "https://www.w3.org/2018/credentials#credentialStatus",
                        "@type": "@id"
                        },
                        "credentialSubject": {
                        "@id": "https://www.w3.org/2018/credentials#credentialSubject",
                        "@type": "@id"
                        },
                        "description": "https://schema.org/description",
                        "evidence": {
                        "@id": "https://www.w3.org/2018/credentials#evidence",
                        "@type": "@id"
                        },
                        "issuer": {
                        "@id": "https://www.w3.org/2018/credentials#issuer",
                        "@type": "@id"
                        },
                        "name": "https://schema.org/name",
                        "proof": {
                        "@id": "https://w3id.org/security#proof",
                        "@type": "@id",
                        "@container": "@graph"
                        },
                        "refreshService": {
                        "@id": "https://www.w3.org/2018/credentials#refreshService",
                        "@type": "@id"
                        },
                        "relatedResource": {
                        "@id": "https://www.w3.org/2018/credentials#relatedResource",
                        "@type": "@id"
                        },
                        "renderMethod": {
                        "@id": "https://www.w3.org/2018/credentials#renderMethod",
                        "@type": "@id"
                        },
                        "termsOfUse": {
                        "@id": "https://www.w3.org/2018/credentials#termsOfUse",
                        "@type": "@id"
                        },
                        "validFrom": {
                        "@id": "https://www.w3.org/2018/credentials#validFrom",
                        "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                        },
                        "validUntil": {
                        "@id": "https://www.w3.org/2018/credentials#validUntil",
                        "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                        }
                    }
                    },

                    "EnvelopedVerifiableCredential":
                    "https://www.w3.org/2018/credentials#EnvelopedVerifiableCredential",

                    "VerifiablePresentation": {
                    "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
                    "@context": {
                        "@protected": true,

                        "id": "@id",
                        "type": "@type",

                        "holder": {
                        "@id": "https://www.w3.org/2018/credentials#holder",
                        "@type": "@id"
                        },
                        "proof": {
                        "@id": "https://w3id.org/security#proof",
                        "@type": "@id",
                        "@container": "@graph"
                        },
                        "termsOfUse": {
                        "@id": "https://www.w3.org/2018/credentials#termsOfUse",
                        "@type": "@id"
                        },
                        "verifiableCredential": {
                        "@id": "https://www.w3.org/2018/credentials#verifiableCredential",
                        "@type": "@id",
                        "@container": "@graph",
                        "@context": null
                        }
                    }
                    },

                    "EnvelopedVerifiablePresentation":
                    "https://www.w3.org/2018/credentials#EnvelopedVerifiablePresentation",

                    "JsonSchemaCredential":
                    "https://www.w3.org/2018/credentials#JsonSchemaCredential",

                    "JsonSchema": {
                    "@id": "https://www.w3.org/2018/credentials#JsonSchema",
                    "@context": {
                        "@protected": true,

                        "id": "@id",
                        "type": "@type",

                        "jsonSchema": {
                        "@id": "https://www.w3.org/2018/credentials#jsonSchema",
                        "@type": "@json"
                        }
                    }
                    },

                    "BitstringStatusListCredential":
                    "https://www.w3.org/ns/credentials/status#BitstringStatusListCredential",

                    "BitstringStatusList": {
                    "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusList",
                    "@context": {
                        "@protected": true,

                        "id": "@id",
                        "type": "@type",

                        "encodedList": {
                        "@id": "https://www.w3.org/ns/credentials/status#encodedList",
                        "@type": "https://w3id.org/security#multibase"
                        },
                        "statusMessage": {
                        "@id": "https://www.w3.org/ns/credentials/status#statusMessage",
                        "@context": {
                            "@protected": true,

                            "id": "@id",
                            "type": "@type",

                            "message": "https://www.w3.org/ns/credentials/status#message",
                            "status": "https://www.w3.org/ns/credentials/status#status"
                        }
                        },
                        "statusPurpose":
                        "https://www.w3.org/ns/credentials/status#statusPurpose",
                        "statusReference": {
                        "@id": "https://www.w3.org/ns/credentials/status#statusReference",
                        "@type": "@id"
                        },
                        "statusSize": {
                        "@id": "https://www.w3.org/ns/credentials/status#statusSize",
                        "@type": "https://www.w3.org/2001/XMLSchema#positiveInteger"
                        },
                        "ttl": "https://www.w3.org/ns/credentials/status#ttl"
                    }
                    },

                    "BitstringStatusListEntry": {
                    "@id":
                        "https://www.w3.org/ns/credentials/status#BitstringStatusListEntry",
                    "@context": {
                        "@protected": true,

                        "id": "@id",
                        "type": "@type",

                        "statusListCredential": {
                        "@id":
                            "https://www.w3.org/ns/credentials/status#statusListCredential",
                        "@type": "@id"
                        },
                        "statusListIndex":
                        "https://www.w3.org/ns/credentials/status#statusListIndex",
                        "statusPurpose":
                        "https://www.w3.org/ns/credentials/status#statusPurpose"
                    }
                    },

                    "DataIntegrityProof": {
                    "@id": "https://w3id.org/security#DataIntegrityProof",
                    "@context": {
                        "@protected": true,

                        "id": "@id",
                        "type": "@type",

                        "challenge": "https://w3id.org/security#challenge",
                        "created": {
                        "@id": "http://purl.org/dc/terms/created",
                        "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                        },
                        "cryptosuite": {
                        "@id": "https://w3id.org/security#cryptosuite",
                        "@type": "https://w3id.org/security#cryptosuiteString"
                        },
                        "domain": "https://w3id.org/security#domain",
                        "expires": {
                        "@id": "https://w3id.org/security#expiration",
                        "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                        },
                        "nonce": "https://w3id.org/security#nonce",
                        "previousProof": {
                        "@id": "https://w3id.org/security#previousProof",
                        "@type": "@id"
                        },
                        "proofPurpose": {
                        "@id": "https://w3id.org/security#proofPurpose",
                        "@type": "@vocab",
                        "@context": {
                            "@protected": true,

                            "id": "@id",
                            "type": "@type",

                            "assertionMethod": {
                            "@id": "https://w3id.org/security#assertionMethod",
                            "@type": "@id",
                            "@container": "@set"
                            },
                            "authentication": {
                            "@id": "https://w3id.org/security#authenticationMethod",
                            "@type": "@id",
                            "@container": "@set"
                            },
                            "capabilityDelegation": {
                            "@id": "https://w3id.org/security#capabilityDelegationMethod",
                            "@type": "@id",
                            "@container": "@set"
                            },
                            "capabilityInvocation": {
                            "@id": "https://w3id.org/security#capabilityInvocationMethod",
                            "@type": "@id",
                            "@container": "@set"
                            },
                            "keyAgreement": {
                            "@id": "https://w3id.org/security#keyAgreementMethod",
                            "@type": "@id",
                            "@container": "@set"
                            }
                        }
                        },
                        "proofValue": {
                        "@id": "https://w3id.org/security#proofValue",
                        "@type": "https://w3id.org/security#multibase"
                        },
                        "verificationMethod": {
                        "@id": "https://w3id.org/security#verificationMethod",
                        "@type": "@id"
                        }
                    }
                    },

                    "...": {
                    "@id": "https://www.iana.org/assignments/jwt#..."
                    },
                    "_sd": {
                    "@id": "https://www.iana.org/assignments/jwt#_sd",
                    "@type": "@json"
                    },
                    "_sd_alg": {
                    "@id": "https://www.iana.org/assignments/jwt#_sd_alg"
                    },
                    "aud": {
                    "@id": "https://www.iana.org/assignments/jwt#aud",
                    "@type": "@id"
                    },
                    "cnf": {
                    "@id": "https://www.iana.org/assignments/jwt#cnf",
                    "@context": {
                        "@protected": true,

                        "kid": {
                        "@id": "https://www.iana.org/assignments/jwt#kid",
                        "@type": "@id"
                        },
                        "jwk": {
                        "@id": "https://www.iana.org/assignments/jwt#jwk",
                        "@type": "@json"
                        }
                    }
                    },
                    "exp": {
                    "@id": "https://www.iana.org/assignments/jwt#exp",
                    "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
                    },
                    "iat": {
                    "@id": "https://www.iana.org/assignments/jwt#iat",
                    "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
                    },
                    "iss": {
                    "@id": "https://www.iana.org/assignments/jose#iss",
                    "@type": "@id"
                    },
                    "jku": {
                    "@id": "https://www.iana.org/assignments/jose#jku",
                    "@type": "@id"
                    },
                    "kid": {
                    "@id": "https://www.iana.org/assignments/jose#kid",
                    "@type": "@id"
                    },
                    "nbf": {
                    "@id": "https://www.iana.org/assignments/jwt#nbf",
                    "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
                    },
                    "sub": {
                    "@id": "https://www.iana.org/assignments/jose#sub",
                    "@type": "@id"
                    },
                    "x5u": {
                    "@id": "https://www.iana.org/assignments/jose#x5u",
                    "@type": "@id"
                    }
                }
            }"#,
        )
        .unwrap()
    }

    fn example_context() -> json_syntax::Value {
        json_syntax::Value::from_str(
            r#"{
                "@context": {
                    "@vocab": "https://www.w3.org/ns/credentials/examples#"
                }
            }"#,
        )
        .unwrap()
    }
}
