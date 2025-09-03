//! Digital Credentials Query Language (DCQL) implementation
//!
//! This crate provides Rust data structures for representing DCQL queries
//! as defined in the OpenID4VP specification.
//!
//! Reference: https://openid.net/specs/openid-4-verifiable-presentations-1_0-29.html#section-6

use std::fmt::Debug;

use bon::Builder;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod builder;
mod display;
pub mod mapper;
pub mod matching;
/// Digital Credentials Query Language (DCQL) query structure
///
/// This is a simplified model of the DCQL query structure as defined in
/// https://openid.net/specs/openid-4-verifiable-presentations-1_0-29.html#section-6
/// Following fields are not supported
/// - credential_sets
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder)]
pub struct DcqlQuery {
    pub credentials: Vec<CredentialQuery>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialQueryId(String);

/// Credential query structure
///
/// The following fields defined in the specification are not supported
/// - trusted_authorities
/// - require_cryptographic_holder_binding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder)]
#[builder(start_fn(vis = ""))]
pub struct CredentialQuery {
    #[builder(into)]
    pub id: CredentialQueryId,
    pub format: CredentialFormat,
    #[builder(getter)]
    pub meta: CredentialMeta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimQuery>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<ClaimQueryId>>>,
    /// Trusted authorities to be considered when evaluating issuer trust.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthority>>,
    #[builder(default = false, setters(vis = "", name = "set_multiple_internal"))]
    #[serde(default = "default_false")]
    pub multiple: bool,
}

fn default_false() -> bool {
    false
}

/// Format-specific metadata for credential queries
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialMeta {
    MsoMdoc { doctype_value: String },
    SdJwtVc { vct_values: Vec<String> },
    W3cVc { type_values: Vec<Vec<String>> },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClaimQueryId(String);

/// Individual claim query within a credential query
///
/// The following fields defined in the specification are not supported
/// - values
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder)]
pub struct ClaimQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(into)]
    pub id: Option<ClaimQueryId>,
    #[builder(into)]
    pub path: ClaimPath,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<ClaimValue>>,
    // Custom field to mark if a claim is required or optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    // MDOC specific field, as per draft 29, section b.2.4
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialFormat {
    #[serde(rename = "jwt_vc_json")]
    JwtVc,
    #[serde(rename = "ldp_vc")]
    LdpVc,
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,
    #[serde(rename = "dc+sd-jwt")]
    SdJwt,
    #[serde(rename = "vc+sd-jwt")]
    W3cSdJwt,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Builder)]
#[serde(transparent)]
pub struct ClaimPath {
    pub segments: Vec<PathSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathSegment {
    /// Property of object with specific name
    PropertyName(String),
    /// 0-based index into an array
    ArrayIndex(usize),
    /// Select all elements of an array
    ArrayAll,
}

/// Trusted authorities as defined in DCQL section 6.1.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TrustedAuthority {
    /// ETSI Trusted List – values contain one or more Trusted List identifiers
    EtsiTl { values: Vec<String> },

    /// OpenID Federation – values contain one or more entity identifiers
    OpenidFederation { values: Vec<String> },

    /// AuthorityKeyIdentifier base64url values
    #[serde(rename = "aki")]
    AuthorityKeyId { values: Vec<String> },

    /// Unknown / custom authority type, preserving original type string and values.
    #[serde(untagged)]
    Custom { r#type: String, values: Vec<String> },
}

/// Possible claim value to match credentials against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimValue {
    /// String value
    String(String),
    /// Integer value
    /// Note: DCQL does _not_ support floating point numbers
    Integer(isize),
    /// Boolean value
    Boolean(bool),
}

#[derive(Clone, Debug, Error)]
pub enum DcqlError {
    #[error("missing id on claim query for claim with path {path}")]
    MissingClaimQueryId { path: ClaimPath },
    #[error("unknown claim query id {id}")]
    UnknownClaimQueryId { id: ClaimQueryId },
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use similar_asserts::assert_eq;

    use crate::*;

    #[test]
    fn test_claim_path() {
        let query: PathSegment = serde_json::from_value(json!("test".to_string())).unwrap();
        assert_eq!(query, PathSegment::PropertyName("test".to_string()));

        let query: PathSegment = serde_json::from_value(json!(5)).unwrap();
        assert_eq!(query, PathSegment::ArrayIndex(5));

        let query: PathSegment = serde_json::from_value(Value::Null).unwrap();
        assert_eq!(query, PathSegment::ArrayAll);

        let path = json!(["abc", 5, "blub", null]);
        let query: ClaimPath = serde_json::from_value(path).unwrap();
        assert_eq!(
            query,
            ClaimPath::from(vec![
                "abc".into(),
                5.into(),
                "blub".into(),
                PathSegment::ArrayAll
            ])
        );

        let full_json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name", 0]},
                        {"path": ["address", null, "street_address"]}
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(full_json).unwrap();
        assert_eq!(
            query
                .credentials
                .first()
                .unwrap()
                .claims
                .as_ref()
                .unwrap()
                .get(1)
                .unwrap()
                .path,
            ClaimPath::from(vec!["family_name".into(), PathSegment::ArrayIndex(0)])
        );
    }

    #[test]
    fn test_claim_path_failures() {
        let result = serde_json::from_value::<PathSegment>(json!(-5));
        assert!(result.is_err());

        let result = serde_json::from_value::<PathSegment>(json!(5.58));
        assert!(result.is_err());
    }

    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-29.html#appendix-D-1
    #[test]
    fn test_dcql_query_parsing() {
        let json = json!({
            "credentials": [
                {
                    "id": "my_credential",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.7367.1.mVRC"
                    },
                    "claims": [
                        {"path": ["org.iso.7367.1", "vehicle_holder"]},
                        {"path": ["org.iso.18013.5.1", "first_name"]}
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();

        // Verify the structure was parsed correctly
        assert_eq!(query.credentials.len(), 1);

        let credential = &query.credentials[0];
        assert_eq!(credential.id, "my_credential".into());
        assert_eq!(credential.format, CredentialFormat::MsoMdoc);

        // Verify meta data
        match &credential.meta {
            CredentialMeta::MsoMdoc { doctype_value } => {
                assert_eq!(doctype_value, "org.iso.7367.1.mVRC");
            }
            _ => panic!("Expected MsoMdoc meta type"),
        }

        // Verify claims
        assert_eq!(credential.claims.as_ref().unwrap().len(), 2);

        let first_claim = &credential.claims.as_ref().unwrap()[0];
        assert_eq!(
            first_claim.path,
            vec!["org.iso.7367.1", "vehicle_holder"].into()
        );
        assert!(first_claim.id.is_none());
        assert!(first_claim.required.is_none());
        assert!(first_claim.intent_to_retain.is_none());

        let second_claim = &credential.claims.as_ref().unwrap()[1];
        assert_eq!(
            second_claim.path,
            vec!["org.iso.18013.5.1", "first_name"].into()
        );
        assert!(second_claim.id.is_none());
        assert!(second_claim.required.is_none());
        assert!(second_claim.intent_to_retain.is_none());

        // Verify optional fields are None
        assert!(credential.claim_sets.is_none());
    }

    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-29.html#appendix-D-3
    #[test]
    fn test_dcql_multiple_credentials_parsing() {
        let json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name"]},
                        {"path": ["address", "street_address"]}
                    ]
                },
                {
                    "id": "mdl",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.7367.1.mVRC"
                    },
                    "claims": [
                        {"path": ["org.iso.7367.1", "vehicle_holder"]},
                        {"path": ["org.iso.18013.5.1", "first_name"]}
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();

        // Verify we have two credentials
        assert_eq!(query.credentials.len(), 2);

        // Verify first credential (SD-JWT VC)
        let pid_credential = &query.credentials[0];
        assert_eq!(pid_credential.id, "pid".into());
        assert_eq!(pid_credential.format, CredentialFormat::SdJwt);

        match &pid_credential.meta {
            CredentialMeta::SdJwtVc { vct_values } => {
                assert_eq!(vct_values.len(), 1);
                assert_eq!(
                    vct_values[0],
                    "https://credentials.example.com/identity_credential"
                );
            }
            _ => panic!("Expected SdJwtVc meta type for pid credential"),
        }

        // Verify SD-JWT VC claims
        assert_eq!(pid_credential.claims.as_ref().unwrap().len(), 3);
        assert_eq!(
            pid_credential.claims.as_ref().unwrap()[0].path,
            vec!["given_name"].into()
        );
        assert_eq!(
            pid_credential.claims.as_ref().unwrap()[1].path,
            vec!["family_name"].into()
        );
        assert_eq!(
            pid_credential.claims.as_ref().unwrap()[2].path,
            vec!["address", "street_address"].into()
        );

        // Verify second credential (mso_mdoc)
        let mdl_credential = &query.credentials[1];
        assert_eq!(mdl_credential.id, "mdl".into());
        assert_eq!(mdl_credential.format, CredentialFormat::MsoMdoc);

        match &mdl_credential.meta {
            CredentialMeta::MsoMdoc { doctype_value } => {
                assert_eq!(doctype_value, "org.iso.7367.1.mVRC");
            }
            _ => panic!("Expected MsoMdoc meta type for mdl credential"),
        }

        // Verify mso_mdoc claims
        assert_eq!(mdl_credential.claims.as_ref().unwrap().len(), 2);
        assert_eq!(
            mdl_credential.claims.as_ref().unwrap()[0].path,
            vec!["org.iso.7367.1", "vehicle_holder"].into()
        );
        assert_eq!(
            mdl_credential.claims.as_ref().unwrap()[1].path,
            vec!["org.iso.18013.5.1", "first_name"].into()
        );

        // Verify optional fields are None for both credentials
        for credential in &query.credentials {
            assert!(credential.claim_sets.is_none());
        }
    }

    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-29.html#appendix-D-10.2
    #[test]
    fn test_dcql_with_claim_sets_parsing() {
        let json = json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"id": "a", "path": ["last_name"]},
                        {"id": "b", "path": ["postal_code"]},
                        {"id": "c", "path": ["locality"]},
                        {"id": "d", "path": ["region"]},
                        {"id": "e", "path": ["date_of_birth"]}
                    ],
                    "claim_sets": [
                        ["a", "c", "d", "e"],
                        ["a", "b", "e"]
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();

        // Verify we have one credential
        assert_eq!(query.credentials.len(), 1);

        let credential = &query.credentials[0];
        assert_eq!(credential.id, "pid".into());
        assert_eq!(credential.format, CredentialFormat::SdJwt);

        // Verify metadata
        match &credential.meta {
            CredentialMeta::SdJwtVc { vct_values } => {
                assert_eq!(vct_values.len(), 1);
                assert_eq!(
                    vct_values[0],
                    "https://credentials.example.com/identity_credential"
                );
            }
            _ => panic!("Expected SdJwtVc meta type"),
        }

        // Verify claims with IDs
        assert_eq!(credential.claims.as_ref().unwrap().len(), 5);

        let expected_claims = [
            ("a", vec!["last_name"]),
            ("b", vec!["postal_code"]),
            ("c", vec!["locality"]),
            ("d", vec!["region"]),
            ("e", vec!["date_of_birth"]),
        ];

        for (i, (expected_id, expected_path)) in expected_claims.into_iter().enumerate() {
            let claim = &credential.claims.as_ref().unwrap()[i];
            assert_eq!(claim.id.as_ref().unwrap(), &ClaimQueryId::from(expected_id));
            assert_eq!(claim.path, ClaimPath::from(expected_path));
            assert!(claim.required.is_none());
            assert!(claim.intent_to_retain.is_none());
        }

        // Verify claim_sets
        assert!(credential.claim_sets.is_some());
        let claim_sets = credential.claim_sets.as_ref().unwrap();
        assert_eq!(claim_sets.len(), 2);

        // First claim set: ["a", "c", "d", "e"]
        assert_eq!(
            claim_sets[0],
            vec!["a", "c", "d", "e"]
                .into_iter()
                .map(Into::<ClaimQueryId>::into)
                .collect::<Vec<_>>()
        );

        // Second claim set: ["a", "b", "e"]
        assert_eq!(
            claim_sets[1],
            vec!["a", "b", "e"]
                .into_iter()
                .map(Into::<ClaimQueryId>::into)
                .collect::<Vec<_>>()
        );
    }

    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-D-12
    #[test]
    fn test_dcql_query_value_parsing() {
        let json = json!({
          "credentials": [
            {
              "id": "my_credential",
              "format": "dc+sd-jwt",
              "meta": {
                "vct_values": [ "https://credentials.example.com/identity_credential" ]
              },
              "claims": [
                  {
                    "path": ["last_name"],
                    "values": ["Doe"]
                  },
                  {"path": ["first_name"]},
                  {"path": ["address", "street_address"]},
                  {
                    "path": ["postal_code"],
                    "values": ["90210", "90211"]
                  }
              ]
            }
          ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();

        // Verify the structure was parsed correctly
        assert_eq!(query.credentials.len(), 1);

        let credential = &query.credentials[0];
        assert_eq!(credential.id, "my_credential".into());
        assert_eq!(credential.format, CredentialFormat::SdJwt);

        // Verify meta data
        match &credential.meta {
            CredentialMeta::SdJwtVc { vct_values } => {
                assert_eq!(
                    vct_values,
                    &["https://credentials.example.com/identity_credential"]
                );
            }
            _ => panic!("Expected SdJwtVc meta type"),
        }

        // Verify claims
        assert_eq!(credential.claims.as_ref().unwrap().len(), 4);

        let first_claim = &credential.claims.as_ref().unwrap()[0];
        assert_eq!(first_claim.path, vec!["last_name"].into());
        assert_eq!(first_claim.values, Some(vec!["Doe".into()]));
        assert!(first_claim.id.is_none());
        assert!(first_claim.required.is_none());
        assert!(first_claim.intent_to_retain.is_none());

        let second_claim = &credential.claims.as_ref().unwrap()[1];
        assert_eq!(second_claim.path, vec!["first_name"].into());
        assert_eq!(second_claim.values, None);
        assert!(second_claim.id.is_none());
        assert!(second_claim.required.is_none());
        assert!(second_claim.intent_to_retain.is_none());

        // Verify optional fields are None
        assert!(credential.claim_sets.is_none());

        let fourth_claim = &credential.claims.as_ref().unwrap()[3];
        assert_eq!(fourth_claim.path, vec!["postal_code"].into());
        assert_eq!(
            fourth_claim.values,
            Some(vec!["90210".into(), "90211".into()])
        );
        assert!(fourth_claim.id.is_none());
        assert!(fourth_claim.required.is_none());
        assert!(fourth_claim.intent_to_retain.is_none());
    }

    #[test]
    fn test_dcql_query_custom_fields() {
        let json = json!({
            "credentials": [
                {
                    "id": "my_credential",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.7367.1.mVRC"
                    },
                    "claims": [
                        {
                            "path": ["org.iso.7367.1", "vehicle_holder"],
                            "required": true,
                            "intent_to_retain": true
                        },
                        {
                            "path": ["org.iso.18013.5.1", "first_name"],
                            "required": false,
                            "intent_to_retain": false
                        }
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();

        // Verify the structure was parsed correctly
        assert_eq!(query.credentials.len(), 1);

        let credential = &query.credentials[0];
        assert_eq!(credential.id, "my_credential".into());
        assert_eq!(credential.format, CredentialFormat::MsoMdoc);

        // Verify meta data
        match &credential.meta {
            CredentialMeta::MsoMdoc { doctype_value } => {
                assert_eq!(doctype_value, "org.iso.7367.1.mVRC");
            }
            _ => panic!("Expected MsoMdoc meta type"),
        }

        // Verify claims
        assert_eq!(credential.claims.as_ref().unwrap().len(), 2);

        let first_claim = &credential.claims.as_ref().unwrap()[0];
        assert_eq!(
            first_claim.path,
            vec!["org.iso.7367.1", "vehicle_holder"].into()
        );
        assert!(first_claim.id.is_none());
        assert_eq!(first_claim.required, Some(true));
        assert_eq!(first_claim.intent_to_retain, Some(true));

        let second_claim = &credential.claims.as_ref().unwrap()[1];
        assert_eq!(
            second_claim.path,
            vec!["org.iso.18013.5.1", "first_name"].into()
        );
        assert!(second_claim.id.is_none());
        assert_eq!(second_claim.required, Some(false));
        assert_eq!(second_claim.intent_to_retain, Some(false));

        // Verify optional fields are None
        assert!(credential.claim_sets.is_none());
    }

    #[test]
    fn test_trusted_authorities_parsing() {
        let json = json!({
            "credentials": [
                {
                    "id": "ta_test",
                    "format": "jwt_vc_json",
                    "meta": {
                        "type_values": [["IDCredential"]]
                    },
                    "trusted_authorities": [
                        {
                          "type": "openid_federation",
                          "values": ["https://trustanchor.example.com"]
                        },
                        {
                          "type": "etsi_tl",
                          "values": ["https://lotl.example.com"]
                        }                        ,
                        {
                          "type": "aki",
                          "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"]
                        },
                        {
                          "type": "custom",
                          "values": ["some-id"]
                        }
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).expect("should parse");

        let ta = &query.credentials[0]
            .trusted_authorities
            .as_ref()
            .expect("present");

        let ta0 = &ta[0];
        let TrustedAuthority::OpenidFederation { values } = ta0 else {
            panic!("expected OpenidFederation");
        };
        assert_eq!(values, &vec!["https://trustanchor.example.com".to_string()]);

        let ta1 = &ta[1];
        let TrustedAuthority::EtsiTl { values } = ta1 else {
            panic!("expected EtsiTl");
        };
        assert_eq!(values, &vec!["https://lotl.example.com".to_string()]);

        let ta2 = &ta[2];
        let TrustedAuthority::AuthorityKeyId { values } = ta2 else {
            panic!("expected AuthorityKeyId");
        };
        assert_eq!(values, &vec!["s9tIpPmhxdiuNkHMEWNpYim8S8Y".to_string()]);

        let ta3 = &ta[3];
        let TrustedAuthority::Custom { r#type, values } = ta3 else {
            panic!("expected Custom");
        };
        assert_eq!(r#type, "custom");
        assert_eq!(values, &vec!["some-id".to_string()]);
    }

    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-29.html#appendix-B.1.3.1.4
    #[test]
    fn test_dcql_w3c_vc_metadata() {
        let json = json!({
            "credentials": [
                {
                    "id": "example_jwt_vc",
                    "format": "jwt_vc_json",
                    "meta": {
                        "type_values": [["IDCredential"]]
                    },
                    "claims": [
                        {"path": ["credentialSubject", "family_name"]},
                        {"path": ["credentialSubject", "given_name"]}
                    ]
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();

        // Verify the structure was parsed correctly
        assert_eq!(query.credentials.len(), 1);

        let credential = &query.credentials[0];
        assert_eq!(credential.id, "example_jwt_vc".into());
        assert_eq!(credential.format, CredentialFormat::JwtVc);

        // Verify meta data
        match &credential.meta {
            CredentialMeta::W3cVc { type_values } => {
                assert_eq!(type_values.len(), 1);
                assert_eq!(type_values[0], vec!["IDCredential"]);
            }
            _ => panic!("Expected W3cVc meta type"),
        }

        // Verify claims
        assert_eq!(credential.claims.as_ref().unwrap().len(), 2);

        let first_claim = &credential.claims.as_ref().unwrap()[0];
        assert_eq!(
            first_claim.path,
            vec!["credentialSubject", "family_name"].into()
        );
        assert!(first_claim.id.is_none());
        assert!(first_claim.required.is_none());
        assert!(first_claim.intent_to_retain.is_none());

        let second_claim = &credential.claims.as_ref().unwrap()[1];
        assert_eq!(
            second_claim.path,
            vec!["credentialSubject", "given_name"].into()
        );
        assert!(second_claim.id.is_none());
        assert!(second_claim.required.is_none());
        assert!(second_claim.intent_to_retain.is_none());

        // Verify optional fields are None
        assert!(credential.claim_sets.is_none());
    }

    #[test]
    fn test_no_claims_parsing() {
        let json = json!({
            "credentials": [
                {
                    "id": "my_credential",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.7367.1.mVRC"
                    }
                }
            ]
        });

        let query: DcqlQuery = serde_json::from_value(json).unwrap();

        // Verify the structure was parsed correctly
        assert_eq!(query.credentials.len(), 1);

        let credential = &query.credentials[0];
        assert_eq!(credential.id, "my_credential".into());
        assert_eq!(credential.format, CredentialFormat::MsoMdoc);

        // Verify meta data
        match &credential.meta {
            CredentialMeta::MsoMdoc { doctype_value } => {
                assert_eq!(doctype_value, "org.iso.7367.1.mVRC");
            }
            _ => panic!("Expected MsoMdoc meta type"),
        }
    }

    #[test]
    fn test_dcql_query_parsing_invalid_values() {
        let invalid_values = [json!({}), json!([]), json!(null), json!(0.85)];

        for invalid_value in &invalid_values {
            let json = json!({
              "credentials": [
                {
                  "id": "my_credential",
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": [ "https://credentials.example.com/identity_credential" ]
                  },
                  "claims": [
                      {
                        "path": ["last_name"],
                        "values": [invalid_value]
                      }
                  ]
                }
              ]
            });

            let result = serde_json::from_value::<DcqlQuery>(json);
            assert!(result.is_err());
        }
    }
}
