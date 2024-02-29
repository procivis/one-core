use serde_json::json;

use crate::provider::credential_formatter::json_ld;

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

    let result = json_ld::canonize_any(&json).await.unwrap();
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
