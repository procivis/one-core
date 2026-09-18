use similar_asserts::assert_eq;

use crate::provider::credential_formatter::model::{PublishedClaim, PublishedClaimValue};
use crate::provider::credential_formatter::nest_claims;

#[test]
fn test_nest_claims_array_with_more_than_ten_items() {
    let claims = (0..11).map(|i| PublishedClaim {
        key: format!("representative/{i}/name"),
        value: PublishedClaimValue::String(format!("name {i}")),
        datatype: Some("STRING".to_string()),
    });

    let nested = nest_claims(claims).unwrap();

    let representatives = nested["representative"].as_array().unwrap();
    assert_eq!(11, representatives.len());
    for (i, representative) in representatives.iter().enumerate() {
        assert_eq!(
            format!("name {i}"),
            representative["name"].as_str().unwrap()
        );
    }
}
