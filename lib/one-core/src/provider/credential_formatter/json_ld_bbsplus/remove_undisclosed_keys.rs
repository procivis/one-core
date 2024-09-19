use std::collections::HashMap;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::model::LdCredential;

pub(super) fn remove_undisclosed_keys(
    revealed_ld: &mut LdCredential,
    disclosed_keys: &[String],
) -> Result<(), FormatterError> {
    for credential_subject in &mut revealed_ld.credential_subject {
        let mut result: HashMap<String, serde_json::Value> = HashMap::new();

        for (key, value) in &credential_subject.subject {
            let mut object = serde_json::Value::Object(Default::default());

            for key in disclosed_keys {
                let full_path = format!("/{key}");
                if let Some(value) = value.pointer(&full_path) {
                    let pointer = jsonptr::Pointer::parse(&full_path)?;
                    pointer.assign(&mut object, value.to_owned())?;
                }
            }

            result.insert(key.to_owned(), object);
        }

        credential_subject.subject = result;
    }

    Ok(())
}
