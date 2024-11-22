use std::sync::Arc;

use mockall::predicate::eq;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::{MockCryptoProvider, MockHasher};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::provider::credential_formatter::model::{
    CredentialData, CredentialPresentation, CredentialSchemaData, CredentialStatus, Issuer,
    PublishedClaim, PublishedClaimValue,
};
use crate::provider::credential_formatter::sdjwt::disclosures::{
    extract_claims_from_disclosures, gather_disclosures, get_disclosures_by_claim_name,
    parse_disclosure, sort_published_claims_by_indices, DisclosureArray,
};
use crate::provider::credential_formatter::sdjwt::model::Disclosure;
use crate::provider::credential_formatter::sdjwt::prepare_sd_presentation;
use crate::provider::credential_formatter::sdjwt::verifier::verify_claims;

#[test]
fn test_prepare_sd_presentation() {
    let claim1 = "[\"MTIzYWJj\",\"name\",\"John\"]";
    let claim2 = "[\"MTIzYWJj\",\"age\",\"42\"]";

    let mut hasher = MockHasher::default();
    hasher
        .expect_hash_base64()
        .times(4)
        .with(eq(claim1.as_bytes()))
        .returning(|_| Ok("rZjyxF4zE7fdRmkcUT8Hkr8_IHSBes1z1pZWP2vLBRE".to_string()));
    hasher
        .expect_hash_base64()
        .times(4)
        .with(eq(claim2.as_bytes()))
        .returning(|_| Ok("KGPldlPB395xKJRjK8k2K5UvsEns9QhL7O7JUu59ERk".to_string()));
    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .with(eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIlNESldUIgp9.ewogICJpYXQiOiAxNjk5MjcwMjY2LAogICJleHAiOiAxNzYyMzQyMjY2LAogICJuYmYiOiAxNjk5MjcwMjIxLAogICJpc3MiOiAiZGlkOmlzc3Vlcjp0ZXN0IiwKICAic3ViIjogImRpZDpob2xkZXI6dGVzdCIsCiAgImp0aSI6ICI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLAogICJ2YyI6IHsKICAgICJAY29udGV4dCI6IFsKICAgICAgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwKICAgICAgImh0dHBzOi8vd3d3LnRlc3Rjb250ZXh0LmNvbS92MSIKICAgIF0sCiAgICAidHlwZSI6IFsKICAgICAgIlZlcmlmaWFibGVDcmVkZW50aWFsIiwKICAgICAgIlR5cGUxIgogICAgXSwKICAgICJjcmVkZW50aWFsU3ViamVjdCI6IHsKICAgICAgIl9zZCI6IFsKICAgICAgICAiWVdKak1USXoiLAogICAgICAgICJZV0pqTVRJeiIKICAgICAgXQogICAgfSwKICAgICJjcmVkZW50aWFsU3RhdHVzIjogewogICAgICAiaWQiOiAiZGlkOnN0YXR1czppZCIsCiAgICAgICJ0eXBlIjogIlRZUEUiLAogICAgICAic3RhdHVzUHVycG9zZSI6ICJQVVJQT1NFIiwKICAgICAgIkZpZWxkMSI6ICJWYWwxIgogICAgfQogIH0sCiAgIl9zZF9hbGciOiAic2hhLTI1NiIKfQ";

    let key_name = "WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0";
    let key_age = "WyJNVEl6WVdKaiIsImFnZSIsIjQyIl0";

    let token = format!("{jwt_token}.QUJD~{key_name}~{key_age}");

    // Take name and age
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["name".to_string(), "age".to_string()],
    };

    let result = prepare_sd_presentation(presentation, &crypto);
    assert!(result.is_ok_and(|token| token.contains(key_name) && token.contains(key_age)));

    // Take name
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["name".to_string()],
    };

    let result = prepare_sd_presentation(presentation, &crypto);
    assert!(result.is_ok_and(|token| token.contains(key_name) && !token.contains(key_age)));

    // Take age
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["age".to_string()],
    };

    let result = prepare_sd_presentation(presentation, &crypto);
    assert!(result.is_ok_and(|token| !token.contains(key_name) && token.contains(key_age)));

    // Take none
    let presentation = CredentialPresentation {
        token,
        disclosed_keys: vec![],
    };

    let result = prepare_sd_presentation(presentation, &crypto);
    assert!(result.is_ok_and(|token| !token.contains(key_name) && !token.contains(key_age)));
}

#[test]
fn test_gather_disclosures_and_objects_without_nesting() {
    let algorithm = "sha-256";

    let street_address_disclosure = ("street_address", "Schulstr. 12");
    let hashed_b64_street_address_disclosure = "9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM";

    let locality_disclosure = ("locality", "Schulpforta");
    let hashed_b64_locality_disclosure = "6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0";

    let region_disclosure = ("region", "Sachsen-Anhalt");
    let hashed_b64_region_disclosure = "KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88";

    let country_disclosure = ("country", "DE");
    let hashed_b64_country_disclosure = "WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM";

    let mut hasher = MockHasher::default();
    hasher.expect_hash_base64().returning(move |input| {
        let input = DisclosureArray::from(std::str::from_utf8(input).unwrap());
        if input.key.eq(street_address_disclosure.0) {
            Ok(hashed_b64_street_address_disclosure.to_string())
        } else if input.key.eq(locality_disclosure.0) {
            Ok(hashed_b64_locality_disclosure.to_string())
        } else if input.key.eq(region_disclosure.0) {
            Ok(hashed_b64_region_disclosure.to_string())
        } else if input.key.eq(country_disclosure.0) {
            Ok(hashed_b64_country_disclosure.to_string())
        } else {
            panic!("Unexpected input")
        }
    });
    let hasher = Arc::new(hasher);

    let mut crypto = MockCryptoProvider::default();
    crypto
        .expect_get_hasher()
        .with(eq(algorithm))
        .returning(move |_| Ok(hasher.clone()));

    let test_json = json!({
        "street_address": "Schulstr. 12",
        "locality": "Schulpforta",
        "region": "Sachsen-Anhalt",
        "country": "DE"
    });

    let (disclosures, result) = gather_disclosures(&test_json, algorithm, &crypto).unwrap();
    let disclosures: Vec<_> = disclosures
        .iter()
        .map(|val| DisclosureArray::from_b64(val))
        .collect();
    let expected_disclosures = &[
        street_address_disclosure,
        locality_disclosure,
        region_disclosure,
        country_disclosure,
    ];
    let expected_result = vec![
        hashed_b64_street_address_disclosure,
        hashed_b64_locality_disclosure,
        hashed_b64_region_disclosure,
        hashed_b64_country_disclosure,
    ];

    assert!(expected_disclosures.iter().all(|expected| {
        disclosures
            .iter()
            .any(|disc| disc.key == expected.0 && disc.value.to_string().contains(expected.1))
    }));
    assert_eq!(expected_result, result);
}

#[test]
fn test_gather_disclosures_and_objects_with_nesting() {
    let algorithm = "sha-256";

    let street_address_disclosure = ("street_address", "Schulstr. 12");
    let hashed_b64_street_address_disclosure = "9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM";

    let locality_disclosure = ("locality", "Schulpforta");
    let hashed_b64_locality_disclosure = "6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0";

    let region_disclosure = ("region", "Sachsen-Anhalt");
    let hashed_b64_region_disclosure = "KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88";

    let country_disclosure = ("country", "DE");
    let hashed_b64_country_disclosure = "WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM";

    let address_disclosure = ("address", "{\"_sd\":[\"9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM\",\"6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0\",\"KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88\",\"WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM\"]}");
    let hashed_b64_address_disclosure = "HvrKX6fPV0v9K_yCVFBiLFHsMaxcD_114Em6VT8x1lg";

    let mut hasher = MockHasher::default();
    hasher.expect_hash_base64().returning(move |input| {
        let input = DisclosureArray::from(std::str::from_utf8(input).unwrap());
        if input.key.eq(street_address_disclosure.0) {
            Ok(hashed_b64_street_address_disclosure.to_string())
        } else if input.key.eq(locality_disclosure.0) {
            Ok(hashed_b64_locality_disclosure.to_string())
        } else if input.key.eq(region_disclosure.0) {
            Ok(hashed_b64_region_disclosure.to_string())
        } else if input.key.eq(country_disclosure.0) {
            Ok(hashed_b64_country_disclosure.to_string())
        } else if input.key.eq(address_disclosure.0) {
            Ok(hashed_b64_address_disclosure.to_string())
        } else {
            panic!("Unexpected input")
        }
    });
    let hasher = Arc::new(hasher);

    // let mut seq = Sequence::new();
    let mut crypto = MockCryptoProvider::default();
    crypto
        .expect_get_hasher()
        .with(eq(algorithm))
        .returning(move |_| Ok(hasher.clone()));

    let test_json = json!({
        "address": {
            "street_address": "Schulstr. 12",
            "locality": "Schulpforta",
            "region": "Sachsen-Anhalt",
            "country": "DE"
        }
    });

    let (disclosures, result) = gather_disclosures(&test_json, algorithm, &crypto).unwrap();
    let disclosures: Vec<_> = disclosures
        .iter()
        .map(|val| DisclosureArray::from_b64(val))
        .collect();
    let expected_disclosures = &[
        street_address_disclosure,
        locality_disclosure,
        region_disclosure,
        country_disclosure,
        address_disclosure,
    ];

    assert!(expected_disclosures.iter().all(|expected| {
        disclosures
            .iter()
            .any(|disc| disc.key == expected.0 && disc.value.to_string().contains(expected.1))
    }));

    let expected_result = vec![hashed_b64_address_disclosure];
    assert_eq!(expected_result, result);
}

#[test]
fn test_parse_disclosure() {
    let mut easy_disclosure = Disclosure {
        salt: "123".to_string(),
        key: "456".to_string(),
        value: serde_json::Value::String("789".to_string()),
        original_disclosure: r#"["123","456","789"]"#.to_string(),
        base64_encoded_disclosure: "not passed".to_string(),
    };
    let easy_disclosure_no_spaces = r#"["123","456","789"]"#;
    assert_eq!(
        easy_disclosure,
        parse_disclosure(easy_disclosure_no_spaces, "not passed").unwrap()
    );

    let easy_disclosure_with_spaces = r#"      [ "123", "456", "789"]  "#;
    easy_disclosure.original_disclosure = easy_disclosure_with_spaces.to_string();
    assert_eq!(
        easy_disclosure,
        parse_disclosure(easy_disclosure_with_spaces, "not passed").unwrap()
    );

    let easy_but_different_spacing = "      [ \"123\"  \n , \"456\" , \"789\" \t\t   ]  ";
    easy_disclosure.original_disclosure = easy_but_different_spacing.to_string();
    assert_eq!(
        easy_disclosure,
        parse_disclosure(easy_but_different_spacing, "not passed").unwrap()
    );
}

fn generic_disclosures() -> Vec<Disclosure> {
    vec![
        Disclosure {
            salt: "cTgNF-AtESuivLBdhN0t8A".to_string(),
            key: "str".to_string(),
            value: serde_json::Value::String("stronk".to_string()),
            original_disclosure: "[\"cTgNF-AtESuivLBdhN0t8A\",\"str\",\"stronk\"]".to_string(),
            base64_encoded_disclosure: "WyJjVGdORi1BdEVTdWl2TEJkaE4wdDhBIiwic3RyIiwic3Ryb25rIl0".to_string()
        },
        Disclosure {
            salt: "nEP135SkAyOTnMA67CNTAA".to_string(),
            key: "another".to_string(),
            value: serde_json::Value::String("week".to_string()),
            original_disclosure: "[\"nEP135SkAyOTnMA67CNTAA\",\"another\",\"week\"]".to_string(),
            base64_encoded_disclosure: "WyJuRVAxMzVTa0F5T1RuTUE2N0NOVEFBIiwiYW5vdGhlciIsIndlZWsiXQ".to_string()
        },
        Disclosure {
            salt: "xtyBeqglpTfvXrqQzsXMFw".to_string(),
            key: "obj".to_string(),
            value: json!({
              "_sd": [
                "hNm6iOV--i33lAvTeuH_rYQBwx8g_mtDQ9T7QLNdH8s",
                "gXsBjCI5V6KfQrjmDlKXttwD5v-HoRwHH_BW_uWsu6U"
              ]
            }),
            original_disclosure: "[\"xtyBeqglpTfvXrqQzsXMFw\",\"obj\",{\"_sd\":[\"hNm6iOV--i33lAvTeuH_rYQBwx8g_mtDQ9T7QLNdH8s\",\"gXsBjCI5V6KfQrjmDlKXttwD5v-HoRwHH_BW_uWsu6U\"]}]".to_string(),
            base64_encoded_disclosure:"WyJ4dHlCZXFnbHBUZnZYcnFRenNYTUZ3Iiwib2JqIix7Il9zZCI6WyJoTm02aU9WLS1pMzNsQXZUZXVIX3JZUUJ3eDhnX210RFE5VDdRTE5kSDhzIiwiZ1hzQmpDSTVWNktmUXJqbURsS1h0dHdENXYtSG9Sd0hIX0JXX3VXc3U2VSJdfV0".to_string(),
        }
    ]
}

#[test]
fn test_verify_claims_nested_success() {
    let hasher = SHA256 {};

    let hashed_claims = vec!["bvvBS7QQFb8-9K8PVvZ4W3iJNfafA51YUF6wNOW807I".to_string()];
    let disclosures = generic_disclosures();

    verify_claims(&hashed_claims, &disclosures, &hasher).unwrap();

    let hashed_claims_containing_unknown_hash = vec![
        "DECOYHASH2".to_string(),
        "bvvBS7QQFb8-9K8PVvZ4W3iJNfafA51YUF6wNOW807I".to_string(),
        "DECOYHASH1".to_string(),
    ];
    verify_claims(
        &hashed_claims_containing_unknown_hash,
        &disclosures,
        &hasher,
    )
    .unwrap();

    let missing_disclosure = disclosures[1..3].to_vec();
    assert!(verify_claims(&hashed_claims, &missing_disclosure, &hasher).is_ok());
}

#[test]
fn test_extract_claims_from_disclosures() {
    let hasher = SHA256 {};

    let disclosures = generic_disclosures();
    let first_two_disclosures = disclosures[0..2].to_vec();

    assert_eq!(
        extract_claims_from_disclosures(&first_two_disclosures, &hasher).unwrap(),
        json!({
            "str": "stronk",
            "another": "week"
        })
    );

    assert_eq!(
        extract_claims_from_disclosures(&disclosures, &hasher).unwrap(),
        json!({
            "obj": {
                "str": "stronk",
                "another": "week"
            }
        })
    );

    let additional_level = Disclosure {
        salt: "pggVbYzzu6oOGXrmNVGPHP".to_string(),
        key: "root".to_string(),
        value: json!({
          "_sd": [
            "bvvBS7QQFb8-9K8PVvZ4W3iJNfafA51YUF6wNOW807I"
          ]
        }),
        original_disclosure: "[\"pggVbYzzu6oOGXrmNVGPHP\",\"root\",{\"_sd\":[\"bvvBS7QQFb8-9K8PVvZ4W3iJNfafA51YUF6wNOW807I\"]}]".to_string(),
        base64_encoded_disclosure:"WyJwZ2dWYll6enU2b09HWHJtTlZHUEhQIiwicm9vdCIseyJfc2QiOlsiYnZ2QlM3UVFGYjgtOUs4UFZ2WjRXM2lKTmZhZkE1MVlVRjZ3Tk9XODA3SSJdfV0".to_string(),
    };
    assert_eq!(
        extract_claims_from_disclosures(&[disclosures, vec![additional_level]].concat(), &hasher)
            .unwrap(),
        json!({
            "root": {
                "obj": {
                    "str": "stronk",
                    "another": "week"
                }
            }
        })
    );
}

#[test]
fn test_get_disclosures_by_claim_name() {
    let hasher = SHA256 {};

    let disclosures = generic_disclosures();

    let expected = vec![disclosures[0].to_owned()];
    let result = get_disclosures_by_claim_name("str", &disclosures, &hasher).unwrap();
    assert_eq!(expected, result);

    let expected = vec![disclosures[1].to_owned()];
    let result = get_disclosures_by_claim_name("another", &disclosures, &hasher).unwrap();
    assert_eq!(expected, result);

    let expected = vec![
        disclosures[0].to_owned(),
        disclosures[1].to_owned(),
        disclosures[2].to_owned(),
    ];
    let result = get_disclosures_by_claim_name("obj", &disclosures, &hasher).unwrap();
    assert_eq!(expected, result);

    let expected = vec![disclosures[0].to_owned(), disclosures[2].to_owned()];
    let result = get_disclosures_by_claim_name("obj/str", &disclosures, &hasher).unwrap();
    assert_eq!(expected, result);

    let expected = vec![disclosures[1].to_owned(), disclosures[2].to_owned()];
    let result = get_disclosures_by_claim_name("obj/another", &disclosures, &hasher).unwrap();
    assert_eq!(expected, result);

    let root_contains_obj_disclosures = vec![
        disclosures[0].to_owned(),
        disclosures[1].to_owned(),
        disclosures[2].to_owned(),
        Disclosure {
            salt: "xtyBeqglpTfvXrqQzsXMFw".to_string(),
            key: "root".to_string(),
            value: json!({
              "_sd": [
                "bvvBS7QQFb8-9K8PVvZ4W3iJNfafA51YUF6wNOW807I"
              ]
          }),
            original_disclosure: "[\"xtyBeqglpTfvXrqQzsXMFw\",\"obj\",{\"_sd\":[\"bvvBS7QQFb8-9K8PVvZ4W3iJNfafA51YUF6wNOW807I\"]}]".to_string(),
            base64_encoded_disclosure: "WyJ4dHlCZXFnbHBUZnZYcnFRenNYTUZ3Iiwib2JqIix7Il9zZCI6WyJidnZCUzdRUUZiOC05SzhQVnZaNFczaUpOZmFmQTUxWVVGNndOT1c4MDdJIl19XQ".to_string(),
        }];

    let expected = vec![
        root_contains_obj_disclosures[1].to_owned(),
        root_contains_obj_disclosures[2].to_owned(),
        root_contains_obj_disclosures[3].to_owned(),
    ];
    let result =
        get_disclosures_by_claim_name("root/obj/another", &root_contains_obj_disclosures, &hasher)
            .unwrap();
    assert_eq!(expected, result);
}

fn generate_published_claim(key: &str) -> PublishedClaim {
    PublishedClaim {
        key: key.to_string(),
        value: PublishedClaimValue::String("irrelevant for tests".to_string()),
        datatype: Some("STRING".to_string()),
        array_item: false,
    }
}

#[test]
fn test_sort_claims_by_indices() {
    let indices = vec![
        generate_published_claim("root/object_array/0/field2"),
        generate_published_claim("root/object_array/1/field2"),
        generate_published_claim("root/object_array/2/field2"),
        generate_published_claim("root/object_array/4/field2"),
        generate_published_claim("root/object_array/3/field2"),
        generate_published_claim("root/array/0"),
        generate_published_claim("root/array/2"),
        generate_published_claim("root/array/10"),
        generate_published_claim("root/array/1"),
    ];

    let expected = vec![
        generate_published_claim("root/object_array/0/field2"),
        generate_published_claim("root/object_array/1/field2"),
        generate_published_claim("root/object_array/2/field2"),
        generate_published_claim("root/object_array/3/field2"),
        generate_published_claim("root/object_array/4/field2"),
        generate_published_claim("root/array/0"),
        generate_published_claim("root/array/1"),
        generate_published_claim("root/array/2"),
        generate_published_claim("root/array/10"),
    ];

    assert_eq!(expected, sort_published_claims_by_indices(&indices));
}

pub fn get_credential_data(status: Vec<CredentialStatus>, core_base_url: &str) -> CredentialData {
    let id = Some(Uuid::new_v4().to_string());
    let issuance_date = OffsetDateTime::now_utc();
    let valid_for = time::Duration::days(365 * 2);
    let schema = CredentialSchemaData {
        id: Some("http://schema.test/id".to_owned()),
        r#type: Some("TestType".to_owned()),
        context: Some(format!("{core_base_url}/ssi/context/v1/{}", Uuid::new_v4())),
        name: "".to_owned(),
        metadata: None,
    };

    CredentialData {
        id,
        issuance_date,
        valid_for,
        claims: vec![
            PublishedClaim {
                key: "name".into(),
                value: "John".into(),
                datatype: Some("STRING".to_owned()),
                array_item: false,
            },
            PublishedClaim {
                key: "age".into(),
                value: "42".into(),
                datatype: Some("NUMBER".to_owned()),
                array_item: false,
            },
        ],
        issuer_did: Issuer::Url("did:issuer:test".parse().unwrap()),
        status,
        schema,
        name: None,
        description: None,
        terms_of_use: vec![],
        evidence: vec![],
        related_resource: None,
    }
}
