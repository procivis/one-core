//! Clause 5.2 — Wallet-Relying Party Registration Certificate (WRPRC).
//!
//! Spec: <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use url::Url;

use super::{Credential, Entitlement, MultiLangString};

/// Clause 5.2.4, the custom claims of the WRPRC JWT.
#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub name: String,
    pub sub_ln: Option<String>,
    pub sub_gn: Option<String>,
    pub sub_fn: Option<String>,
    pub country: String,
    pub registry_uri: Url,
    #[serde(rename = "srv_description")]
    pub service_descriptions: Vec<Vec<MultiLangString>>,
    pub entitlements: Vec<Entitlement>,
    pub privacy_policy: Url,
    pub info_uri: Url,
    pub supervisory_authority: SupervisoryAuthority,
    pub policy_id: Vec<String>,
    pub certificate_policy: Url,
    pub status: Status,
    pub provides_attestations: Option<Vec<Credential>>,
    pub credentials: Option<Vec<Credential>>,
    pub purpose: Option<Vec<MultiLangString>>,
    pub intended_use_id: Option<String>,
    pub public_body: Option<bool>,
    pub support_uri: Url,
    #[serde(alias = "act")]
    pub intermediary: Option<Intermediary>,
}

/// Clause 5.2.4, the wallet-relying party the WRPRC is issued to.
///
/// Serialized flattened into the [`Payload`] as `sub_ln` / `sub_gn` / `sub_fn`,
/// this is the shape the registry provides.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, untagged)]
pub enum Subject {
    LegalPerson {
        id: String,
        legal_name: String,
    },
    NaturalPerson {
        id: String,
        given_name: String,
        family_name: String,
    },
}

impl Subject {
    pub fn id(&self) -> &str {
        match self {
            Subject::LegalPerson { id, .. } => id.as_str(),
            Subject::NaturalPerson { id, .. } => id.as_str(),
        }
    }
}

/// Clause 5.2.4, the data protection authority supervising the relying party.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(as = EudiSupervisoryAuthority))]
#[serde(deny_unknown_fields)]
pub struct SupervisoryAuthority {
    pub email: String,
    pub phone: String,
    pub uri: String,
}

/// Clause 5.2.4, the revocation status of the WRPRC.
///
/// The contents are the token status list claim as defined by the revocation
/// mechanism in use, and are therefore not interpreted here.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Status {
    pub status_list: HashMap<String, serde_json::Value>,
}

/// Clause 5.2.4, the intermediary acting on behalf of the relying party.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Intermediary {
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(
        rename = "name",
        alias = "sname",
        skip_serializing_if = "Option::is_none"
    )]
    pub common_name: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;

    // ETSI TS 119 475 v1.2.1 (2026-03), annex C
    // (without "sub" and "iat")
    const PAYLOAD: &str = r#"
{
  "name": "Example Company",
  "sub_ln": "Example Company GmbH",
  "country": "DE",
  "registry_uri": "https://registrar.com",
  "srv_description": [
    [
      {
        "lang": "en-US",
        "value": "Awesome Service by Example Company"
      },
      {
        "lang": "de-DE",
        "value": "Super Dienst von Example Company"
      }
    ]
  ],
  "entitlements": [
    "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"
  ],
  "privacy_policy": "https://example.com/privacy-policy",
  "info_uri": "https://example.com/info",
  "support_uri": "https://example.com/support",
  "supervisory_authority": {
    "email": "supervisory@dpa.com",
    "phone": "+49 123 4567890",
    "uri": "https://dpa.com/supervisory-authority"
  },
  "policy_id": [
    "0.4.0.19475.3.1"
  ],
  "certificate_policy": "https://registrar.com/certificate-policy",
  "status": {
    "status_list": {
      "idx": 0,
      "uri": "https://example.com/statuslists/1"
    }
  },
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
  "credentials": [
    {
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [
          "urn:eudi:pid:de:1"
        ]
      },
      "claim": [
        {
          "path": [
            "age_equal_or_over",
            "18"
          ]
        }
      ]
    },
    {
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.eudi.pid.1"
      },
      "claim": [
        {
          "path": [
            "eu.europa.ec.eudi.pid.1",
            "age_over_18"
          ]
        }
      ]
    }
  ],
  "provides_attestations": [
    {
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [
          "https://example.com/attestations/age_over_18"
        ]
      }
    }
  ],
  "intermediary": {
    "sub": "LEIXG-INTERMEDIARY-1234567890",
    "name": "Intermediary Services Ltd."
  }
}
"#;

    #[test]
    fn deserialize_example_registration_certificate() {
        serde_json::from_str::<Payload>(PAYLOAD).unwrap();
    }

    /// Re-serializing must produce a document that parses back into the same
    /// payload. Note this is not a byte-for-byte round trip: `Url` normalizes
    /// an empty path to `/`.
    #[test]
    fn serialize_example_registration_certificate_round_trip() {
        let payload: Payload = serde_json::from_str(PAYLOAD).unwrap();
        let serialized = serde_json::to_value(&payload).unwrap();
        similar_asserts::assert_eq!(payload, serde_json::from_value(serialized).unwrap());
    }

    #[test]
    fn serialize_intermediary_claim() {
        let payload: Payload = serde_json::from_str(PAYLOAD).unwrap();

        let serialized = serde_json::to_value(&payload).unwrap();

        similar_asserts::assert_eq!(
            serialized["intermediary"]["sub"],
            "LEIXG-INTERMEDIARY-1234567890"
        );
        assert!(serialized.get("act").is_none());
    }

    #[test]
    fn deserialize_intermediary_from_act_and_legacy_claim() {
        let mut document: serde_json::Value = serde_json::from_str(PAYLOAD).unwrap();
        let legacy: Payload = serde_json::from_value(document.clone()).unwrap();

        let object = document.as_object_mut().unwrap();
        let intermediary = object.remove("intermediary").unwrap();
        object.insert("act".to_string(), intermediary);
        let act: Payload = serde_json::from_value(document).unwrap();

        assert!(act.intermediary.is_some());
        similar_asserts::assert_eq!(legacy.intermediary, act.intermediary);
    }

    #[test]
    fn deserialize_intermediary_common_name_from_sname() {
        let intermediary: Intermediary =
            serde_json::from_str(r#"{"sub": "LEIXG-1", "sname": "Intermediary Ltd."}"#).unwrap();

        similar_asserts::assert_eq!(
            intermediary.common_name,
            Some("Intermediary Ltd.".to_string())
        );
    }

    #[test]
    fn deserialize_subject_cannot_have_legal_and_natural_names() {
        const DOCUMENT: &str = r#"{"id": "XYZ", "first_name": "Janusz", "last_name": "Tytanowy", "legal_name": "Januszex sp. z o.o"}"#;
        assert!(
            serde_json::from_str::<Subject>(DOCUMENT)
                .unwrap_err()
                .is_data()
        );
    }

    #[test]
    fn deserialize_subject_natural_person_must_have_first_name() {
        const DOCUMENT: &str = r#"{"id": "XYZ", "last_name": "Tytanowy"}"#;
        assert!(
            serde_json::from_str::<Subject>(DOCUMENT)
                .unwrap_err()
                .is_data()
        );
    }

    #[test]
    fn deserialize_subject_natural_person_must_have_last_name() {
        const DOCUMENT: &str = r#"{"id": "XYZ", "first_name": "Janusz"}"#;
        assert!(
            serde_json::from_str::<Subject>(DOCUMENT)
                .unwrap_err()
                .is_data()
        );
    }
}
