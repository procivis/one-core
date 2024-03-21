use std::collections::HashMap;

use crate::provider::credential_formatter::{
    error::FormatterError,
    json_ld::model::LdCredential,
    json_ld_bbsplus::model::GroupEntry,
    model::{CredentialSubject, DetailCredential},
};

use super::model::TransformedEntry;

pub fn to_grouped_entry(entries: Vec<(usize, String)>) -> TransformedEntry {
    TransformedEntry {
        data_type: "Map".to_owned(),
        value: entries
            .into_iter()
            .map(|(index, triple)| GroupEntry {
                index,
                entry: triple,
            })
            .collect(),
    }
}

impl TryFrom<LdCredential> for DetailCredential {
    type Error = FormatterError;

    fn try_from(value: LdCredential) -> Result<Self, Self::Error> {
        let mut claims: HashMap<String, String> = HashMap::new();

        for (_, credential) in value.credential_subject.subject {
            for (key, value) in credential {
                claims.insert(key, value);
            }
        }

        Ok(Self {
            id: Some(value.id),
            issued_at: Some(value.issuance_date),
            expires_at: None,
            invalid_before: None,
            issuer_did: Some(value.issuer),
            subject: Some(value.credential_subject.id),
            claims: CredentialSubject { values: claims },
            status: value.credential_status,
            credential_schema: value.credential_schema,
        })
    }
}
