use std::sync::Arc;

use serde_json::json;
use similar_asserts::assert_eq;

use crate::provider::credential_formatter::json_ld::context::caching_loader::ContextCache;
use crate::provider::credential_formatter::json_ld::{json_ld_processor_options, rdf_canonize};
use crate::provider::http_client::MockHttpClient;
use crate::util::test_utilities::prepare_caching_loader;

#[tokio::test]
async fn test_canonize_any() {
    let json = json!(
        {
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
                  "size": 5.5,
                  "sailName": "Kihei",
                  "year": 2023
                },
                {
                  "size": 6.1,
                  "sailName": "Lahaina",
                  "year": 2023
                },
                {
                  "size": 7.0,
                  "sailName": "Lahaina",
                  "year": 2020
                },
                {
                  "size": 7.8,
                  "sailName": "Lahaina",
                  "year": 2023
                }
              ],
              "boards": [
                {
                  "boardName": "CompFoil170",
                  "brand": "Wailea",
                  "year": 2022
                },
                {
                  "boardName": "Kanaha Custom",
                  "brand": "Wailea",
                  "year": 2019
                }
              ]
            }
          }
    );

    let result = rdf_canonize(
        &json,
        &ContextCache::new(
            prepare_caching_loader(None),
            Arc::new(MockHttpClient::new()),
        ),
        json_ld_processor_options(),
    )
    .await
    .unwrap();
    assert_eq!(result, CANONICAL);
}

static CANONICAL: &str = "_:c14n0 <https://windsurf.grotto-networking.com/selective#boardName> \"CompFoil170\" .
_:c14n0 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .
_:c14n0 <https://windsurf.grotto-networking.com/selective#year> \"2022\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n1 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .
_:c14n1 <https://windsurf.grotto-networking.com/selective#size> \"7.8E0\"^^<http://www.w3.org/2001/XMLSchema#double> .
_:c14n1 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n2 <https://windsurf.grotto-networking.com/selective#boardName> \"Kanaha Custom\" .
_:c14n2 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .
_:c14n2 <https://windsurf.grotto-networking.com/selective#year> \"2019\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n3 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .
_:c14n3 <https://windsurf.grotto-networking.com/selective#size> \"7\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n3 <https://windsurf.grotto-networking.com/selective#year> \"2020\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n4 <https://windsurf.grotto-networking.com/selective#sailName> \"Kihei\" .
_:c14n4 <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .
_:c14n4 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n5 <https://windsurf.grotto-networking.com/selective#boards> _:c14n0 .
_:c14n5 <https://windsurf.grotto-networking.com/selective#boards> _:c14n2 .
_:c14n5 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .
_:c14n5 <https://windsurf.grotto-networking.com/selective#sails> _:c14n1 .
_:c14n5 <https://windsurf.grotto-networking.com/selective#sails> _:c14n3 .
_:c14n5 <https://windsurf.grotto-networking.com/selective#sails> _:c14n4 .
_:c14n5 <https://windsurf.grotto-networking.com/selective#sails> _:c14n6 .
_:c14n6 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .
_:c14n6 <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .
_:c14n6 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:c14n7 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:c14n7 <https://www.w3.org/2018/credentials#credentialSubject> _:c14n5 .
_:c14n7 <https://www.w3.org/2018/credentials#issuer> <https://vc.example/windsurf/racecommittee> .
";

#[tokio::test]
async fn test_canonize_any_example_8() {
    let json = json!(
          {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
            "type": ["VerifiableCredential", "AlumniCredential"],
            "name": "Alumni Credential",
            "description": "A minimum viable example of an Alumni Credential.",
            "issuer": "https://vc.example/issuers/5678",
            "validFrom": "2023-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:abcdefgh",
                "alumniOf": "The School of Examples"
            }
        }
    );

    let result = rdf_canonize(
        &json,
        &ContextCache::new(
            prepare_caching_loader(None),
            Arc::new(MockHttpClient::new()),
        ),
        json_ld_processor_options(),
    )
    .await
    .unwrap();
    assert_eq!(result, CANONICAL_EXAMPLE_8);
}

static CANONICAL_EXAMPLE_8: &str = "<did:example:abcdefgh> <https://www.w3.org/ns/credentials/examples#alumniOf> \"The School of Examples\" .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/credentials/examples#AlumniCredential> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://schema.org/description> \"A minimum viable example of an Alumni Credential.\" .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://schema.org/name> \"Alumni Credential\" .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:abcdefgh> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#issuer> <https://vc.example/issuers/5678> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#validFrom> \"2023-01-01T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
";

#[tokio::test]
async fn test_canonize_any_example_8_proof() {
    let json = json!(
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-rdfc-2022",
        "created": "2023-02-24T23:36:38Z",
        "verificationMethod": "https://vc.example/issuers/5678#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
        "proofPurpose": "assertionMethod",
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2"
        ]
      }
    );

    let result = rdf_canonize(
        &json,
        &ContextCache::new(
            prepare_caching_loader(None),
            Arc::new(MockHttpClient::new()),
        ),
        json_ld_processor_options(),
    )
    .await
    .unwrap();
    assert_eq!(result, CANONICAL_EXAMPLE_8_PROOF);
}

static CANONICAL_EXAMPLE_8_PROOF: &str = "_:c14n0 <http://purl.org/dc/terms/created> \"2023-02-24T23:36:38Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:c14n0 <https://w3id.org/security#cryptosuite> \"eddsa-rdfc-2022\"^^<https://w3id.org/security#cryptosuiteString> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <https://vc.example/issuers/5678#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2> .
";
