use std::collections::HashMap;

use crate::provider::credential_formatter::error::FormatterError;

use super::PublishedClaim;

pub(super) fn nest_claims(
    claims: impl IntoIterator<Item = PublishedClaim>,
) -> Result<HashMap<String, serde_json::Value>, FormatterError> {
    let mut data = serde_json::Value::Object(Default::default());

    for claim in claims {
        let pointer = jsonptr::Pointer::try_from(format!("/{}", claim.key))?;
        pointer.assign(&mut data, claim.value)?;
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
            PublishedClaim {
                key: "name".into(),
                value: "John".into(),
                datatype: None,
                array_item: false,
            },
            PublishedClaim {
                key: "location/x".into(),
                value: "1".into(),
                datatype: None,
                array_item: false,
            },
            PublishedClaim {
                key: "location/y".into(),
                value: "2".into(),
                datatype: None,
                array_item: false,
            },
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

    #[test]
    fn test_format_nested_vc_jwt_array() {
        let claims = vec![
            PublishedClaim {
                key: "name".into(),
                value: "John".into(),
                datatype: None,
                array_item: false,
            },
            PublishedClaim {
                key: "location/0".into(),
                value: "1".into(),
                datatype: None,
                array_item: true,
            },
            PublishedClaim {
                key: "location/1".into(),
                value: "2".into(),
                datatype: None,
                array_item: true,
            },
        ];
        let expected = HashMap::from([
            ("location".to_string(), json!(["1", "2"])),
            ("name".to_string(), json!("John")),
        ]);

        assert_eq!(expected, nest_claims(claims).unwrap());
    }
}
