use std::collections::HashMap;

use crate::provider::credential_formatter::error::FormatterError;

pub(super) fn nest_claims(
    claims: impl IntoIterator<Item = (String, String, Option<String>)>,
) -> Result<HashMap<String, serde_json::Value>, FormatterError> {
    let mut data = serde_json::Value::Object(Default::default());

    for (full_path, value, _) in claims {
        let pointer = jsonptr::Pointer::try_from(format!("/{full_path}"))?;
        pointer.assign(&mut data, value)?;
    }

    Ok(data
        .as_object()
        .ok_or(FormatterError::JsonMapping(
            "data is not an Object".to_string(),
        ))?
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_format_nested_vc_jwt() {
        let claims = vec![
            ("name".to_string(), "John".to_string(), None),
            ("location/x".to_string(), "1".to_string(), None),
            ("location/y".to_string(), "2".to_string(), None),
        ];
        let expected = HashMap::from([
            (
                "location".to_string(),
                json!({
                  "x": "1",
                  "y": "2"
                }),
            ),
            ("name".to_string(), json!("John")),
        ]);

        assert_eq!(expected, nest_claims(claims).unwrap());
    }
}
