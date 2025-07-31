use crate::provider::credential_formatter::model::{DetailCredential, IdentifierDetails};

// TODO
// remove this and find a better solution in ONE-3520
// We check for the presence of the `id` claim in two places.
// SD-JWT LVVCs have the secured credential as the `id` claim.
// JSON-LD (BBS+) LVVCs have the LVVC as the credential subject.
pub fn is_lvvc_credential(credential: &DetailCredential) -> bool {
    (credential.subject.is_some()
        || credential.claims.id.is_some()
        || credential.claims.claims.contains_key("id"))
        && (credential.claims.claims.contains_key("status")
            || credential.claims.claims.contains_key("LvvcSubject"))
}

pub fn get_lvvc_credential_subject(credential: &DetailCredential) -> Option<&str> {
    match credential.subject.as_ref() {
        Some(IdentifierDetails::Did(did_value)) => Some(did_value.as_str()),
        _ => credential
            .claims
            .id
            .as_ref()
            .map(|id| id.as_str())
            .or(credential
                .claims
                .claims
                .get("id")
                .and_then(|id| id.as_str())),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use shared_types::DidValue;
    use uuid::Uuid;

    use super::*;
    use crate::provider::credential_formatter::model::{
        CredentialSubject, DetailCredential, IdentifierDetails,
    };

    fn create_test_detail_credential(
        subject: Option<DidValue>,
        claims: CredentialSubject,
    ) -> DetailCredential {
        DetailCredential {
            id: Some("id".to_string()),
            issuance_date: None,
            valid_from: None,
            valid_until: None,
            update_at: None,
            invalid_before: None,
            issuer: IdentifierDetails::Did("did:example:123".parse().unwrap()),
            subject: subject.map(IdentifierDetails::Did),
            claims,
            status: vec![],
            credential_schema: None,
        }
    }

    #[test]
    fn test_is_lvvc_id_in_subject() {
        let test_subject_id = "did:example:123".parse().unwrap();

        let claims = CredentialSubject {
            id: None,
            claims: HashMap::from([("status".to_string(), serde_json::Value::Null)]),
        };

        // parsed JSON-LD based LVVCs contain the LVVC as the credential subject
        let credential = create_test_detail_credential(Some(test_subject_id), claims);
        assert!(is_lvvc_credential(&credential));
    }

    #[test]
    fn test_is_lvvc_id_in_claims() {
        let cases = [
            CredentialSubject {
                id: None,
                claims: HashMap::from([
                    (
                        "id".to_string(),
                        serde_json::Value::String(Uuid::new_v4().urn().to_string()),
                    ),
                    ("status".to_string(), serde_json::Value::Null),
                ]),
            },
            CredentialSubject {
                id: Some(Uuid::new_v4().urn().to_string().parse().unwrap()),
                claims: HashMap::from([("status".to_string(), serde_json::Value::Null)]),
            },
        ];

        for claims in cases {
            // parsed JWT based LVVCs contain the LVVC in the claims array claims
            let credential = create_test_detail_credential(None, claims);
            assert!(is_lvvc_credential(&credential));
        }
    }
    #[test]
    fn test_is_lvvc_correctly_rejects() {
        let claims = CredentialSubject {
            id: None,
            claims: HashMap::from([("status".to_string(), serde_json::Value::Null)]),
        };

        // The subject ID is missing both in the claims and the credential subject
        let credential = create_test_detail_credential(None, claims);
        assert!(!is_lvvc_credential(&credential));
    }
}
