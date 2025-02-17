use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::model::LdCredential;

pub(super) fn remove_undisclosed_keys(
    revealed_ld: &mut LdCredential,
    disclosed_keys: &[String],
) -> Result<(), FormatterError> {
    for credential_subject in &mut revealed_ld.credential_subject {
        let mut only_revealed_claims: serde_json::Value =
            serde_json::Value::Object(Default::default());

        let original_claims =
            &serde_json::Value::Object(credential_subject.subject.clone().into_iter().collect());

        for key in disclosed_keys {
            let full_path = format!("/{key}");
            if let Some(value) = original_claims.pointer(&full_path) {
                let pointer = jsonptr::Pointer::parse(&full_path)?;
                pointer.assign(&mut only_revealed_claims, value.to_owned())?;
            }
        }

        credential_subject.subject = only_revealed_claims
            .as_object()
            .ok_or(FormatterError::CouldNotFormat(
                "Could not extract claims".to_string(),
            ))?
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
    }

    Ok(())
}
