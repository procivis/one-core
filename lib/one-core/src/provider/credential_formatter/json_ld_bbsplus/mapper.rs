use super::model::TransformedEntry;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::model::LdCredential;
use crate::provider::credential_formatter::json_ld_bbsplus::model::GroupEntry;
use crate::provider::credential_formatter::model::{CredentialSubject, DetailCredential};

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
        if value.credential_subject.len() > 1 {
            return Err(FormatterError::Failed(
                "We currently don't support multiple credential subjects".to_string(),
            ));
        }

        let Some(credential_subject) = value.credential_subject.into_iter().next() else {
            return Err(FormatterError::Failed(
                "Missing credential subject".to_string(),
            ));
        };

        Ok(Self {
            id: value.id.map(|url| url.to_string()),
            valid_from: value.valid_from.or(value.issuance_date),
            valid_until: None,
            update_at: None,
            invalid_before: None,
            issuer_did: Some(value.issuer.to_did_value()),
            subject: credential_subject.id,
            claims: CredentialSubject {
                values: credential_subject.subject,
            },
            status: value.credential_status,
            credential_schema: value.credential_schema.map(|v| v[0].clone()),
        })
    }
}
