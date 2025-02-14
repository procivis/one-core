use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::vcdm::VcdmCredential;

pub(super) fn remove_undisclosed_keys(
    vcdm: &mut VcdmCredential,
    disclosed_keys: &[String],
) -> Result<(), FormatterError> {
    for credential_subject in &mut vcdm.credential_subject {
        let mut only_revealed_claims: serde_json::Value =
            serde_json::Value::Object(Default::default());

        let original_claims =
            &serde_json::Value::Object(credential_subject.claims.clone().into_iter().collect());

        for key in disclosed_keys {
            let full_path = format!("/{key}");
            if let Some(value) = original_claims.pointer(&full_path) {
                let pointer = jsonptr::Pointer::parse(&full_path)?;
                pointer.assign(&mut only_revealed_claims, value.to_owned())?;
            }
        }

        credential_subject.claims = only_revealed_claims
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
