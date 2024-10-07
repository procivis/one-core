use crate::provider::credential_formatter::model::DetailCredential;

// TODO
// remove this and find a better solution in ONE-3520
// We check for the presence of the `id` claim in two places.
// SD-JWT LVVCs have the secured credential as the `id` claim.
// JSON-LD (BBS+) LVVCs have the LVVC as the credential subject.
pub fn is_lvvc_credential(credential: &DetailCredential) -> bool {
    (credential.subject.is_some() || credential.claims.values.contains_key("id"))
        && (credential.claims.values.contains_key("status")
            || credential.claims.values.contains_key("LvvcSubject"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use shared_types::DidValue;
    use url::Url;
    use uuid::Uuid;

    use super::*;
    use crate::provider::credential_formatter::model::{CredentialSubject, DetailCredential};

    fn create_test_detail_credential(
        subject: Option<DidValue>,
        claims: CredentialSubject,
    ) -> DetailCredential {
        DetailCredential {
            id: Some("id".to_string()),
            valid_from: None,
            valid_until: None,
            update_at: None,
            invalid_before: None,
            issuer_did: None,
            subject,
            claims,
            status: vec![],
            credential_schema: None,
        }
    }

    #[test]
    fn test_is_lvvc_id_in_subject() {
        let test_subject_id = {
            let id = Uuid::new_v4().urn();
            id.to_string().parse::<Url>().unwrap().into()
        };

        let claims = CredentialSubject {
            values: HashMap::from([("status".to_string(), serde_json::Value::Null)]),
        };

        // parsed JSON-LD based LVVCs contain the LVVC as the credential subject
        let credential = create_test_detail_credential(Some(test_subject_id), claims);
        assert!(is_lvvc_credential(&credential));
    }

    #[test]
    fn test_is_lvvc_id_in_claims() {
        let claims = CredentialSubject {
            values: HashMap::from([
                (
                    "id".to_string(),
                    serde_json::Value::String(Uuid::new_v4().urn().to_string()),
                ),
                ("status".to_string(), serde_json::Value::Null),
            ]),
        };

        // parsed JWT based LVVCs contain the LVVC in the claims array claims
        let credential = create_test_detail_credential(None, claims);
        assert!(is_lvvc_credential(&credential));
    }
    #[test]
    fn test_is_lvvc_correctly_rejects() {
        let claims = CredentialSubject {
            values: HashMap::from([("status".to_string(), serde_json::Value::Null)]),
        };

        // The subject ID is missing both in the claims and the credential subject
        let credential = create_test_detail_credential(None, claims);
        assert!(!is_lvvc_credential(&credential));
    }
}
