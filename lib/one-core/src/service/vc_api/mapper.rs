use one_providers::credential_formatter::model::{PublishedClaim, PublishedClaimValue};

pub fn value_to_published_claim(
    claim: (String, serde_json::Value),
    path_prefix: &str,
    array_item: bool,
) -> Vec<PublishedClaim> {
    let mut published_claims: Vec<PublishedClaim> = vec![];

    match claim.1 {
        serde_json::Value::Array(values) => {
            for (i, value) in values.iter().enumerate() {
                published_claims.extend(value_to_published_claim(
                    (claim.0.clone(), value.clone()),
                    &format!("{}/{}/{}", path_prefix, claim.0, i),
                    true,
                ));
            }
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                published_claims.extend(value_to_published_claim(
                    (format!("{}/{}", path_prefix, key), value),
                    path_prefix,
                    false,
                ));
            }
        }
        _ => {
            published_claims.push(PublishedClaim {
                key: claim.0,
                value: PublishedClaimValue::String(claim.1.to_string()),
                datatype: None,
                array_item,
            });
        }
    };

    published_claims
}
