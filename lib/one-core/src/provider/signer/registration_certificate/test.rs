// ETSI TS 119 475 v1.1.1, Annex C
const PAYLOAD: &str = r#"
{
  "name": "Example GmbH",
  "purpose": [
    {
      "lang": "en-US",
      "value": "Required for checking the minimum age"
    },
    {
      "lang": "de-DE",
      "value": "Benötigt für die Überprüfung des Mindestalters"
    }
  ],
  "info_uri": "https://example.com",
  "country": "DE",
  "sub": {
    "legal_name": "Example GmbH",
    "id": "LEIXG-529900T8BM49AURSDO55"
  },
  "privacy_policy": "https://example-company.com/en/privacy-policy",
  "policy_id": [
    "0.4.0.19475.3.1"
  ],
  "certificate_policy": "https://registrat.example.com/certificate-policy",
  "credentials": [
    {
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [
          "https://credentials.example.com/identity_credential"
        ]
      },
      "claims": [
        { "path": ["given_name"] },
        { "path": ["family_name"] },
        { "path": ["address", "street_address"] }
      ]
    },
    {
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [
          "https://othercredentials.example/mdl"
        ]
      },
      "claims": [
        { "path": ["given_name"] },
        { "path": ["family_name"] },
        { "path": ["address", "street_address"] }
      ]
    }
  ],
  "entitlements": [
    "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"
  ],
  "provided_attestations": [
    {
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [
          ""
        ]
      }
    }
  ],
  "public_body": false,
  "service": [[
    {
      "lang": "en-US",
      "value": "Bundesagentur für Sprunginnovationen"
    },
    {
      "lang": "de-DE",
      "value": "Federal Agency for Breakthrough Innovations"
    }
  ]],
  "act": {
    "sub": "DE:EX-987654381"
  }
}
"#;

#[test]
fn deserialize_example_registration_certificate() {
    serde_json::from_str::<super::model::Payload>(PAYLOAD).unwrap();
}

#[test]
fn deserialize_subject_cannot_have_legal_and_natural_names() {
    const DOCUMENT: &str = r#"{"id": "XYZ", "first_name": "Janusz", "last_name": "Tytanowy", "legal_name": "Januszex sp. z o.o"}"#;
    assert!(
        serde_json::from_str::<super::model::Subject>(DOCUMENT)
            .unwrap_err()
            .is_data()
    );
}

#[test]
fn deserialize_subject_natural_person_must_have_first_name() {
    const DOCUMENT: &str = r#"{"id": "XYZ", "last_name": "Tytanowy"}"#;
    assert!(
        serde_json::from_str::<super::model::Subject>(DOCUMENT)
            .unwrap_err()
            .is_data()
    );
}

#[test]
fn deserialize_subject_natural_person_must_have_last_name() {
    const DOCUMENT: &str = r#"{"id": "XYZ", "first_name": "Janusz"}"#;
    assert!(
        serde_json::from_str::<super::model::Subject>(DOCUMENT)
            .unwrap_err()
            .is_data()
    );
}

#[test]
fn deserialize_serialize_entitlement() {
    const ENTITLEMENTS: &[&str] = &[
        "\"id-etsi-wrpa-entitlement 1\"",
        "\"https://uri.etsi.org/19475/Entitlement/Service_Provider\"",
        "\"id-etsi-wrpa-entitlement 2\"",
        "\"https://uri.etsi.org/19475/Entitlement/QEAA_Provider\"",
        "\"id-etsi-wrpa-entitlement 3\"",
        "\"https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider\"",
        "\"id-etsi-wrpa-entitlement 4\"",
        "\"https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider\"",
        "\"id-etsi-wrpa-entitlement 5\"",
        "\"https://uri.etsi.org/19475/Entitlement/PID_Provider\"",
        "\"id-etsi-wrpa-entitlement 6\"",
        "\"https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider\"",
        "\"id-etsi-wrpa-entitlement 7\"",
        "\"https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider\"",
        "\"id-etsi-wrpa-entitlement 8\"",
        "\"https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider\"",
        "\"id-etsi-wrpa-entitlement 9\"",
        "\"https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider\"",
        "\"id-etsi-wrpa-entitlement 10\"",
        "\"https://uri.etsi.org/19475/Entitlement/ESIG_ESeal_Creation_Provider\"",
    ];

    for input in ENTITLEMENTS {
        let deserialized: super::model::Entitlement = serde_json::from_str(input).unwrap();
        let serialized = serde_json::to_string(&deserialized).unwrap();
        similar_asserts::assert_eq!(serialized.as_str(), *input);
    }
}

#[test]
fn deserialize_claim_value_ok() {
    const DOCUMENT: &str = r#"{"path": ["first", "second"], "values": ["string", 10, -40, false]}"#;
    serde_json::from_str::<super::model::Claim>(DOCUMENT).unwrap();
}

#[test]
fn deserialize_claim_value_invalid() {
    const DOCUMENT: &str = r#"{"path": [], "values": [21.37]}"#;
    assert!(
        serde_json::from_str::<super::model::Claim>(DOCUMENT)
            .unwrap_err()
            .is_data()
    );
}
