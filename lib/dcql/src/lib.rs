//! Digital Credentials Query Language (DCQL) implementation
//!
//! This crate provides Rust data structures for representing DCQL queries
//! as defined in the OpenID4VP specification.
//!
//! Reference: https://openid.net/specs/openid-4-verifiable-presentations-1_0-29.html#section-6

use serde::{Deserialize, Serialize};

/// Digital Credentials Query Language (DCQL) query structure
///
/// This is a simplified model of the DCQL query structure as defined in
/// https://openid.net/specs/openid-4-verifiable-presentations-1_0-29.html#section-6
/// Following fields are not supported
/// - credential_sets
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcqlQuery {
    pub credentials: Vec<CredentialQuery>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialQueryId(String);

impl<T: ToString> From<T> for CredentialQueryId {
    fn from(value: T) -> Self {
        Self(value.to_string())
    }
}

/// Credential query structure
///
/// The following fields defined in the specification are not supported
/// - multiple
/// - trusted_authorities
/// - require_cryptographic_holder_binding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialQuery {
    pub id: CredentialQueryId,
    pub format: String,
    pub meta: CredentialMeta,
    pub claims: Vec<ClaimQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,
}

/// Format-specific metadata for credential queries
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialMeta {
    MsoMdoc { doctype_value: String },
    SdJwtVc { vct_values: Vec<String> },
    W3cVc { type_values: Vec<Vec<String>> },
}

/// Individual claim query within a credential query
///
/// The following fields defined in the specification are not supported
/// - values
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub path: Vec<String>,
    // Custom field to mark if a claim is required or optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    // MDOC specific field, as per draft 29, section b.2.4
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_to_retain: Option<bool>,
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

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
        assert_eq!(credential.format, "mso_mdoc");

        // Verify meta data
        match &credential.meta {
            CredentialMeta::MsoMdoc { doctype_value } => {
                assert_eq!(doctype_value, "org.iso.7367.1.mVRC");
            }
            _ => panic!("Expected MsoMdoc meta type"),
        }

        // Verify claims
        assert_eq!(credential.claims.len(), 2);

        let first_claim = &credential.claims[0];
        assert_eq!(first_claim.path, vec!["org.iso.7367.1", "vehicle_holder"]);
        assert!(first_claim.id.is_none());
        assert!(first_claim.required.is_none());
        assert!(first_claim.intent_to_retain.is_none());

        let second_claim = &credential.claims[1];
        assert_eq!(second_claim.path, vec!["org.iso.18013.5.1", "first_name"]);
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
        assert_eq!(pid_credential.format, "dc+sd-jwt");

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
        assert_eq!(pid_credential.claims.len(), 3);
        assert_eq!(pid_credential.claims[0].path, vec!["given_name"]);
        assert_eq!(pid_credential.claims[1].path, vec!["family_name"]);
        assert_eq!(
            pid_credential.claims[2].path,
            vec!["address", "street_address"]
        );

        // Verify second credential (mso_mdoc)
        let mdl_credential = &query.credentials[1];
        assert_eq!(mdl_credential.id, "mdl".into());
        assert_eq!(mdl_credential.format, "mso_mdoc");

        match &mdl_credential.meta {
            CredentialMeta::MsoMdoc { doctype_value } => {
                assert_eq!(doctype_value, "org.iso.7367.1.mVRC");
            }
            _ => panic!("Expected MsoMdoc meta type for mdl credential"),
        }

        // Verify mso_mdoc claims
        assert_eq!(mdl_credential.claims.len(), 2);
        assert_eq!(
            mdl_credential.claims[0].path,
            vec!["org.iso.7367.1", "vehicle_holder"]
        );
        assert_eq!(
            mdl_credential.claims[1].path,
            vec!["org.iso.18013.5.1", "first_name"]
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
        assert_eq!(credential.format, "dc+sd-jwt");

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
        assert_eq!(credential.claims.len(), 5);

        let expected_claims = [
            ("a", vec!["last_name"]),
            ("b", vec!["postal_code"]),
            ("c", vec!["locality"]),
            ("d", vec!["region"]),
            ("e", vec!["date_of_birth"]),
        ];

        for (i, (expected_id, expected_path)) in expected_claims.iter().enumerate() {
            let claim = &credential.claims[i];
            assert_eq!(claim.id.as_ref().unwrap(), expected_id);
            assert_eq!(claim.path, *expected_path);
            assert!(claim.required.is_none());
            assert!(claim.intent_to_retain.is_none());
        }

        // Verify claim_sets
        assert!(credential.claim_sets.is_some());
        let claim_sets = credential.claim_sets.as_ref().unwrap();
        assert_eq!(claim_sets.len(), 2);

        // First claim set: ["a", "c", "d", "e"]
        assert_eq!(claim_sets[0], vec!["a", "c", "d", "e"]);

        // Second claim set: ["a", "b", "e"]
        assert_eq!(claim_sets[1], vec!["a", "b", "e"]);
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
        assert_eq!(credential.format, "mso_mdoc");

        // Verify meta data
        match &credential.meta {
            CredentialMeta::MsoMdoc { doctype_value } => {
                assert_eq!(doctype_value, "org.iso.7367.1.mVRC");
            }
            _ => panic!("Expected MsoMdoc meta type"),
        }

        // Verify claims
        assert_eq!(credential.claims.len(), 2);

        let first_claim = &credential.claims[0];
        assert_eq!(first_claim.path, vec!["org.iso.7367.1", "vehicle_holder"]);
        assert!(first_claim.id.is_none());
        assert_eq!(first_claim.required, Some(true));
        assert_eq!(first_claim.intent_to_retain, Some(true));

        let second_claim = &credential.claims[1];
        assert_eq!(second_claim.path, vec!["org.iso.18013.5.1", "first_name"]);
        assert!(second_claim.id.is_none());
        assert_eq!(second_claim.required, Some(false));
        assert_eq!(second_claim.intent_to_retain, Some(false));

        // Verify optional fields are None
        assert!(credential.claim_sets.is_none());
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
        assert_eq!(credential.format, "jwt_vc_json");

        // Verify meta data
        match &credential.meta {
            CredentialMeta::W3cVc { type_values } => {
                assert_eq!(type_values.len(), 1);
                assert_eq!(type_values[0], vec!["IDCredential"]);
            }
            _ => panic!("Expected W3cVc meta type"),
        }

        // Verify claims
        assert_eq!(credential.claims.len(), 2);

        let first_claim = &credential.claims[0];
        assert_eq!(first_claim.path, vec!["credentialSubject", "family_name"]);
        assert!(first_claim.id.is_none());
        assert!(first_claim.required.is_none());
        assert!(first_claim.intent_to_retain.is_none());

        let second_claim = &credential.claims[1];
        assert_eq!(second_claim.path, vec!["credentialSubject", "given_name"]);
        assert!(second_claim.id.is_none());
        assert!(second_claim.required.is_none());
        assert!(second_claim.intent_to_retain.is_none());

        // Verify optional fields are None
        assert!(credential.claim_sets.is_none());
    }
}
