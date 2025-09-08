use std::collections::HashSet;
use std::string::ToString;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_crypto::hasher::sha256::SHA256;
use one_crypto::{Hasher, MockHasher};
use serde_json::{Value, json};
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialPresentation, CredentialSchema, CredentialStatus, HolderBindingCtx,
    Issuer, MockSignatureProvider, PublishedClaim,
};
use crate::provider::credential_formatter::nest_claims;
use crate::provider::credential_formatter::sdjwt::disclosures::{
    DisclosureArray, compute_object_disclosures, parse_disclosure, select_disclosures,
};
use crate::provider::credential_formatter::sdjwt::model::{Disclosure, KeyBindingPayload};
use crate::provider::credential_formatter::sdjwt::prepare_sd_presentation;
use crate::provider::credential_formatter::vcdm::{
    ContextType, VcdmCredential, VcdmCredentialSubject,
};
use crate::service::test_utilities::{dummy_did, dummy_identifier};
use crate::util::jwt::Jwt;

const W3C_USER_CLAIM_PATH: [&str; 2] = ["vc", "credentialSubject"];

#[tokio::test]
async fn test_prepare_sd_presentation() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIlNESldUIgp9.ew0KICAiaWF0IjogMTY5OTI3MDI2NiwNCiAgImV4cCI6IDE3NjIzNDIyNjYsDQogICJuYmYiOiAxNjk5MjcwMjIxLA0KICAiaXNzIjogImRpZDppc3N1ZXI6dGVzdCIsDQogICJzdWIiOiAiZGlkOmhvbGRlcjp0ZXN0IiwNCiAgImp0aSI6ICI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLA0KICAidmMiOiB7DQogICAgIkBjb250ZXh0IjogWw0KICAgICAgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwNCiAgICAgICJodHRwczovL3d3dy50ZXN0Y29udGV4dC5jb20vdjEiDQogICAgXSwNCiAgICAidHlwZSI6IFsNCiAgICAgICJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsDQogICAgICAiVHlwZTEiDQogICAgXSwNCiAgICAiY3JlZGVudGlhbFN1YmplY3QiOiB7DQogICAgICAiX3NkIjogWw0KICAgICAgICAiQk9UMzVNWUp3NW85S2k3RDBXcUpYdi13SjAxZHF6LWxRdE9xaHdNaXZxbyIsDQogICAgICAgICJIWm5Nc3p5Q2REZEwxakhuVnJOWmR0ZnY4YkpUdGducGtTX2xJekgyNHk4Ig0KICAgICAgXQ0KICAgIH0sDQogICAgImNyZWRlbnRpYWxTdGF0dXMiOiB7DQogICAgICAiaWQiOiAiZGlkOnN0YXR1czppZCIsDQogICAgICAidHlwZSI6ICJUWVBFIiwNCiAgICAgICJzdGF0dXNQdXJwb3NlIjogIlBVUlBPU0UiLA0KICAgICAgIkZpZWxkMSI6ICJWYWwxIg0KICAgIH0NCiAgfSwNCiAgIl9zZF9hbGciOiAic2hhLTI1NiINCn0";
    let key_name = "WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0";
    let key_age = "WyJNVEl6WVdKaiIsImFnZSIsIjQyIl0";
    let key_id = "key-id";
    let key_alg = "ES256";
    let token = format!("{jwt_token}.QUJD~{key_name}~{key_age}~");
    let audience = "some-aud";
    let nonce = "nonce";
    let holder_binding_ctx = HolderBindingCtx {
        nonce: nonce.to_string(),
        audience: audience.to_string(),
    };

    let mut signer = MockSignatureProvider::default();
    signer
        .expect_get_key_id()
        .returning(|| Some(key_id.to_string()));
    signer
        .expect_jose_alg()
        .returning(|| Some(key_alg.to_string()));
    signer.expect_sign().returning(|_| Ok(vec![0; 32]));

    // Take name and age
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["name".to_string(), "age".to_string()],
    };

    let result = prepare_sd_presentation(
        presentation,
        &SHA256,
        Some(holder_binding_ctx),
        Some(Box::new(signer)),
        &W3C_USER_CLAIM_PATH
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    assert!(result.contains(key_name) && result.contains(key_age));
    let (_, kb_token) = result.rsplit_once('~').unwrap();
    assert!(kb_token.is_empty());

    // Take name
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["name".to_string()],
    };

    let result = prepare_sd_presentation(
        presentation,
        &SHA256,
        None,
        None,
        &W3C_USER_CLAIM_PATH
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    assert!(result.contains(key_name) && !result.contains(key_age));
    assert!(result.ends_with('~')); // no key binding token appended, if context / authn_fn is missing

    // Take age
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["age".to_string()],
    };

    let result = prepare_sd_presentation(
        presentation,
        &SHA256,
        None,
        None,
        &W3C_USER_CLAIM_PATH
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .await;
    assert!(result.is_ok_and(|token| !token.contains(key_name) && token.contains(key_age)));

    // Take none
    let presentation = CredentialPresentation {
        token,
        disclosed_keys: vec![],
    };

    let result = prepare_sd_presentation(
        presentation,
        &SHA256,
        None,
        None,
        &W3C_USER_CLAIM_PATH
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .await;
    assert!(result.is_ok_and(|token| !token.contains(key_name) && !token.contains(key_age)));
}

/// Tests compatibility with malformed legacy SD-JWT credentials.
/// ONE-6254: Remove when compatibility with legacy SD-JWT credentials is no longer needed
#[tokio::test]
async fn test_prepare_sd_presentation_malformed() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIlNESldUIgp9.ew0KICAiaWF0IjogMTY5OTI3MDI2NiwNCiAgImV4cCI6IDE3NjIzNDIyNjYsDQogICJuYmYiOiAxNjk5MjcwMjIxLA0KICAiaXNzIjogImRpZDppc3N1ZXI6dGVzdCIsDQogICJzdWIiOiAiZGlkOmhvbGRlcjp0ZXN0IiwNCiAgImp0aSI6ICI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLA0KICAidmMiOiB7DQogICAgIkBjb250ZXh0IjogWw0KICAgICAgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwNCiAgICAgICJodHRwczovL3d3dy50ZXN0Y29udGV4dC5jb20vdjEiDQogICAgXSwNCiAgICAidHlwZSI6IFsNCiAgICAgICJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsDQogICAgICAiVHlwZTEiDQogICAgXSwNCiAgICAiY3JlZGVudGlhbFN1YmplY3QiOiB7DQogICAgICAiX3NkIjogWw0KICAgICAgICAiQk9UMzVNWUp3NW85S2k3RDBXcUpYdi13SjAxZHF6LWxRdE9xaHdNaXZxbyIsDQogICAgICAgICJIWm5Nc3p5Q2REZEwxakhuVnJOWmR0ZnY4YkpUdGducGtTX2xJekgyNHk4Ig0KICAgICAgXQ0KICAgIH0sDQogICAgImNyZWRlbnRpYWxTdGF0dXMiOiB7DQogICAgICAiaWQiOiAiZGlkOnN0YXR1czppZCIsDQogICAgICAidHlwZSI6ICJUWVBFIiwNCiAgICAgICJzdGF0dXNQdXJwb3NlIjogIlBVUlBPU0UiLA0KICAgICAgIkZpZWxkMSI6ICJWYWwxIg0KICAgIH0NCiAgfSwNCiAgIl9zZF9hbGciOiAic2hhLTI1NiINCn0";
    let key_name = "WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0";
    let key_age = "WyJNVEl6WVdKaiIsImFnZSIsIjQyIl0";
    let key_id = "key-id";
    let key_alg = "ES256";
    // malformed: no trailing ~
    let token = format!("{jwt_token}.QUJD~{key_name}~{key_age}");
    let audience = "some-aud";
    let nonce = "nonce";
    let holder_binding_ctx = HolderBindingCtx {
        nonce: nonce.to_string(),
        audience: audience.to_string(),
    };

    let mut signer = MockSignatureProvider::default();
    signer
        .expect_get_key_id()
        .returning(|| Some(key_id.to_string()));
    signer
        .expect_jose_alg()
        .returning(|| Some(key_alg.to_string()));
    signer.expect_sign().returning(|_| Ok(vec![0; 32]));

    // Take name and age
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["name".to_string(), "age".to_string()],
    };

    let result = prepare_sd_presentation(
        presentation,
        &SHA256,
        Some(holder_binding_ctx),
        Some(Box::new(signer)),
        &W3C_USER_CLAIM_PATH
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    assert!(result.contains(key_name) && result.contains(key_age));
    let (_, kb_token) = result.rsplit_once('~').unwrap();
    assert!(kb_token.is_empty());

    // Take name
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["name".to_string()],
    };

    let result = prepare_sd_presentation(
        presentation,
        &SHA256,
        None,
        None,
        &W3C_USER_CLAIM_PATH
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    assert!(result.contains(key_name) && !result.contains(key_age));
    assert!(result.ends_with('~')); // no key binding token appended, if context / authn_fn is missing

    // Take age
    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["age".to_string()],
    };

    let result = prepare_sd_presentation(
        presentation,
        &SHA256,
        None,
        None,
        &W3C_USER_CLAIM_PATH
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .await;
    assert!(result.is_ok_and(|token| !token.contains(key_name) && token.contains(key_age)));

    // Take none
    let presentation = CredentialPresentation {
        token,
        disclosed_keys: vec![],
    };

    let result = prepare_sd_presentation(
        presentation,
        &SHA256,
        None,
        None,
        &W3C_USER_CLAIM_PATH
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .await;
    assert!(result.is_ok_and(|token| !token.contains(key_name) && !token.contains(key_age)));
}

#[tokio::test]
async fn test_prepare_sd_presentation_with_kb() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIlNESldUIgp9.eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5MjcwMjIxLCJpc3MiOiJkaWQ6aXNzdWVyOnRlc3QiLCJzdWIiOiJkaWQ6aG9sZGVyOnRlc3QiLCJqdGkiOiI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiMTh3SExlSWdXOXdWTjZWRDFUeGdwcXkyTHN6WWtNZjZKOG5qVkFpYnZoTSIsInkiOiItVjRkUzRVYUxNZ1BfNGZZNGo4aXI3Y2wxVFhsRmRBZ2N4NTVvN1RrY1NBIn19LCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnRlc3Rjb250ZXh0LmNvbS92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVHlwZTEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbIkhabk1zenlDZERkTDFqSG5Wck5aZHRmdjhiSlR0Z25wa1NfbEl6SDI0eTgiLCJCT1QzNU1ZSnc1bzlLaTdEMFdxSlh2LXdKMDFkcXotbFF0T3Fod01pdnFvIl19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOnN0YXR1czppZCIsInR5cGUiOiJUWVBFIiwic3RhdHVzUHVycG9zZSI6IlBVUlBPU0UiLCJGaWVsZDEiOiJWYWwxIn19LCJfc2RfYWxnIjoic2hhLTI1NiJ9";
    let key_name = "WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0";
    let key_age = "WyJNVEl6WVdKaiIsImFnZSIsIjQyIl0";
    let key_id = "key-id";
    let key_alg = "ES256";
    let token = format!("{jwt_token}.QUJD~{key_name}~{key_age}~");
    let audience = "some-aud";
    let nonce = "nonce";
    let holder_binding_ctx = HolderBindingCtx {
        nonce: nonce.to_string(),
        audience: audience.to_string(),
    };

    let mut signer = MockSignatureProvider::default();
    signer
        .expect_get_key_id()
        .returning(|| Some(key_id.to_string()));
    signer
        .expect_jose_alg()
        .returning(|| Some(key_alg.to_string()));
    signer.expect_sign().returning(|_| Ok(vec![0; 32]));

    let presentation = CredentialPresentation {
        token: token.clone(),
        disclosed_keys: vec!["name".to_string()],
    };

    // With holder binding context and signer
    let result = prepare_sd_presentation(
        presentation.clone(),
        &SHA256,
        Some(holder_binding_ctx.clone()),
        Some(Box::new(signer)),
        &W3C_USER_CLAIM_PATH
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    assert!(result.contains(key_name));
    let (_, kb_token) = result.rsplit_once('~').unwrap();
    assert!(!kb_token.is_empty());
    assert!(kb_token.ends_with(".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")); // fake sig: vec![0;32]
    let kb_jwt = Jwt::<KeyBindingPayload>::build_from_token(kb_token, None, None)
        .await
        .unwrap();
    assert_eq!(kb_jwt.header.key_id, Some(key_id.to_string()));
    assert_eq!(kb_jwt.header.algorithm, key_alg);
    assert_eq!(kb_jwt.payload.audience.unwrap().first().unwrap(), audience);
    assert_eq!(kb_jwt.payload.custom.nonce, nonce);
    assert_eq!(
        kb_jwt.payload.custom.sd_hash,
        // hash over token + revealed disclosures (which should be ony key_name)
        SHA256
            .hash_base64_url(format!("{jwt_token}.QUJD~{key_name}~").as_bytes())
            .unwrap()
    );

    // Without holder binding context and signer
    let result = prepare_sd_presentation(
        presentation.clone(),
        &SHA256,
        None,
        Some(Box::new(MockSignatureProvider::default())),
        &W3C_USER_CLAIM_PATH
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .await;
    assert!(matches!(result, Err(FormatterError::Failed(_))));

    // With holder binding context and no signer
    let result = prepare_sd_presentation(
        presentation.clone(),
        &SHA256,
        Some(holder_binding_ctx),
        None,
        &W3C_USER_CLAIM_PATH
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .await;
    assert!(matches!(result, Err(FormatterError::Failed(_))));
    // Without holder binding context and no signer
    let result = prepare_sd_presentation(
        presentation.clone(),
        &SHA256,
        None,
        None,
        &W3C_USER_CLAIM_PATH
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .await;
    assert!(matches!(result, Err(FormatterError::Failed(_))));
}

#[test]
fn test_gather_disclosures_and_objects_without_nesting() {
    let street_address_disclosure = ("street_address", "Schulstr. 12");
    let hashed_b64_street_address_disclosure = "9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM";

    let locality_disclosure = ("locality", "Schulpforta");
    let hashed_b64_locality_disclosure = "6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0";

    let region_disclosure = ("region", "Sachsen-Anhalt");
    let hashed_b64_region_disclosure = "KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88";

    let country_disclosure = ("country", "DE");
    let hashed_b64_country_disclosure = "WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM";

    let mut hasher = MockHasher::default();
    hasher.expect_hash_base64_url().returning(move |input| {
        let input = Base64UrlSafeNoPadding::decode_to_vec(input, None).unwrap();
        let input = DisclosureArray::from(std::str::from_utf8(&input).unwrap());
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

    let test_json = json!({
        "street_address": "Schulstr. 12",
        "locality": "Schulpforta",
        "region": "Sachsen-Anhalt",
        "country": "DE"
    });

    let (disclosures, result) = compute_object_disclosures(&test_json, &hasher, true).unwrap();
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
    let expected_result = HashSet::from([
        hashed_b64_street_address_disclosure,
        hashed_b64_locality_disclosure,
        hashed_b64_region_disclosure,
        hashed_b64_country_disclosure,
    ]);

    assert!(expected_disclosures.iter().all(|expected| {
        disclosures
            .iter()
            .any(|disc| disc.key == expected.0 && disc.value.to_string().contains(expected.1))
    }));
    assert_eq!(
        expected_result,
        HashSet::from_iter(result.iter().map(String::as_str))
    );
}

#[test]
fn test_gather_disclosures_and_objects_with_nesting() {
    let street_address_disclosure = ("street_address", json!("Schulstr. 12"));
    let hashed_b64_street_address_disclosure = "9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM";

    let locality_disclosure = ("locality", json!("Schulpforta"));
    let hashed_b64_locality_disclosure = "6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0";

    let region_disclosure = ("region", json!("Sachsen-Anhalt"));
    let hashed_b64_region_disclosure = "KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88";

    let country_disclosure = ("country", json!("DE"));
    let hashed_b64_country_disclosure = "WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM";

    let address_disclosure = (
        "address",
        json!({"_sd":["9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM","6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0","KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88","WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM"]}),
    );
    let hashed_b64_address_disclosure = "HvrKX6fPV0v9K_yCVFBiLFHsMaxcD_114Em6VT8x1lg";

    let mut hasher = MockHasher::default();
    hasher.expect_hash_base64_url().returning(move |input| {
        let input = Base64UrlSafeNoPadding::decode_to_vec(input, None).unwrap();
        let input = DisclosureArray::from(std::str::from_utf8(&input).unwrap());
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

    let test_json = json!({
        "address": {
            "street_address": "Schulstr. 12",
            "locality": "Schulpforta",
            "region": "Sachsen-Anhalt",
            "country": "DE"
        }
    });

    let (disclosures, result) = compute_object_disclosures(&test_json, &hasher, true).unwrap();
    let disclosures: Vec<_> = disclosures
        .iter()
        .map(|val| DisclosureArray::from_b64(val))
        .collect();
    let expected_disclosures = &[
        street_address_disclosure,
        locality_disclosure,
        region_disclosure,
        country_disclosure,
        //address_disclosure,
    ];

    // simple disclosures
    assert!(
        expected_disclosures
            .iter()
            .all(|(expected_key, expected_value)| {
                disclosures
                    .iter()
                    .any(|disc| disc.key == *expected_key && disc.value == *expected_value)
            })
    );

    // _sd array in address disclosure needs to be compared order independent
    assert_eq!(
        HashSet::<Value>::from_iter(
            disclosures
                .iter()
                .find(|disc| disc.key == "address")
                .unwrap()
                .value
                .get("_sd")
                .unwrap()
                .as_array()
                .unwrap()
                .clone()
        ),
        HashSet::from_iter(
            address_disclosure
                .1
                .get("_sd")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .cloned()
        )
    );

    let expected_result = vec![hashed_b64_address_disclosure];
    assert_eq!(expected_result, result);
}

#[test]
fn test_parse_disclosure() {
    let mut easy_disclosure = Disclosure {
        salt: "123".to_string(),
        key: Some("456".to_string()),
        value: serde_json::Value::String("789".to_string()),
        disclosure_array: r#"["123","456","789"]"#.to_string(),
        disclosure: "not passed".to_string(),
    };
    let easy_disclosure_no_spaces = r#"["123","456","789"]"#;
    assert_eq!(
        easy_disclosure,
        parse_disclosure(
            easy_disclosure_no_spaces.to_owned(),
            "not passed".to_owned()
        )
        .unwrap()
    );

    let easy_disclosure_with_spaces = r#"      [ "123", "456", "789"]  "#;
    easy_disclosure.disclosure_array = easy_disclosure_with_spaces.to_string();
    assert_eq!(
        easy_disclosure,
        parse_disclosure(
            easy_disclosure_with_spaces.to_owned(),
            "not passed".to_owned()
        )
        .unwrap()
    );

    let easy_but_different_spacing = "      [ \"123\"  \n , \"456\" , \"789\" \t\t   ]  ";
    easy_disclosure.disclosure_array = easy_but_different_spacing.to_string();
    assert_eq!(
        easy_disclosure,
        parse_disclosure(
            easy_but_different_spacing.to_owned(),
            "not passed".to_owned()
        )
        .unwrap()
    );
}

fn generic_disclosures() -> (Value, Vec<Disclosure>) {
    (json!({
        "_sd": [SHA256
            .hash_base64_url("WyJ4dHlCZXFnbHBUZnZYcnFRenNYTUZ3Iiwib2JqIix7Il9zZCI6WyJoTm02aU9WLS1pMzNsQXZUZXVIX3JZUUJ3eDhnX210RFE5VDdRTE5kSDhzIiwiZ1hzQmpDSTVWNktmUXJqbURsS1h0dHdENXYtSG9Sd0hIX0JXX3VXc3U2VSJdfV0".as_bytes())
            .unwrap()],
    }),
     vec![
         Disclosure {
             salt: "cTgNF-AtESuivLBdhN0t8A".to_string(),
             key: Some("str".to_string()),
             value: serde_json::Value::String("stronk".to_string()),
             disclosure_array: "[\"cTgNF-AtESuivLBdhN0t8A\",\"str\",\"stronk\"]".to_string(),
             disclosure: "WyJjVGdORi1BdEVTdWl2TEJkaE4wdDhBIiwic3RyIiwic3Ryb25rIl0".to_string()
         },
         Disclosure {
             salt: "nEP135SkAyOTnMA67CNTAA".to_string(),
             key: Some("another".to_string()),
             value: serde_json::Value::String("week".to_string()),
             disclosure_array: "[\"nEP135SkAyOTnMA67CNTAA\",\"another\",\"week\"]".to_string(),
             disclosure: "WyJuRVAxMzVTa0F5T1RuTUE2N0NOVEFBIiwiYW5vdGhlciIsIndlZWsiXQ".to_string()
         },
         Disclosure {
             salt: "xtyBeqglpTfvXrqQzsXMFw".to_string(),
             key: Some("obj".to_string()),
             value: json!({
              "_sd": [
                "54nR6daXsl_LDczSaZc48coL-UHR72WyIpzz6AkDUyA",
                "9RzaXaJF3BCDitmMRNhHqzbRIRc6pbfS-7YbM_PObk8"
              ]
            }),
             disclosure_array: "[\"xtyBeqglpTfvXrqQzsXMFw\",\"obj\",{\"_sd\":[\"hNm6iOV--i33lAvTeuH_rYQBwx8g_mtDQ9T7QLNdH8s\",\"gXsBjCI5V6KfQrjmDlKXttwD5v-HoRwHH_BW_uWsu6U\"]}]".to_string(),
             disclosure: "WyJ4dHlCZXFnbHBUZnZYcnFRenNYTUZ3Iiwib2JqIix7Il9zZCI6WyJoTm02aU9WLS1pMzNsQXZUZXVIX3JZUUJ3eDhnX210RFE5VDdRTE5kSDhzIiwiZ1hzQmpDSTVWNktmUXJqbURsS1h0dHdENXYtSG9Sd0hIX0JXX3VXc3U2VSJdfV0".to_string(),
         }
     ])
}

#[test]
fn test_select_disclosures_nested() {
    let (payload, disclosures) = generic_disclosures();
    let expected = HashSet::<String>::from_iter([
        disclosures[0].disclosure.to_string(),
        disclosures[2].disclosure.to_string(),
    ]);
    let result = select_disclosures(&["obj/str".into()], &payload, disclosures, &SHA256).unwrap();
    assert_eq!(expected, HashSet::from_iter(result));
}

#[test]
fn test_select_disclosures_root() {
    let (payload, disclosures) = generic_disclosures();
    let expected =
        HashSet::<String>::from_iter(disclosures.iter().map(|d| d.disclosure.to_string()));

    let result = select_disclosures(&["obj".into()], &payload, disclosures, &SHA256).unwrap();
    assert_eq!(expected, HashSet::from_iter(result));
}

#[test]
fn test_select_disclosures_nested_structure_with_similar_nodes() {
    let payload = json!({
        "_sd": [
            SHA256
            .hash_base64_url("WyJ4dHlCZXFnbHBUZnZYcnFRenNYTUZ3Iiwib2JqMSIseyJfc2QiOlsiaF8xNjhQSFpwVDg4bUo0Mkl6cFJZMEpyMWdXb1FDTUxHUVRENDNQeGxRayJdfV0".as_bytes())
            .unwrap(),
            SHA256
            .hash_base64_url("WyJwZ2dWYll6enU2b09HWHJtTlZHUEhQIiwib2JqMiIseyJfc2QiOlsiT1lyLUUydzYwWWt1R21UcWZ4WjFrclljelZQUW5ONEQyWnJXQk5RNzNlNCJdfV0".as_bytes())
            .unwrap()
        ]
    });
    let disclosures = vec![
        Disclosure {
            salt: "cTgNF-AtESuivLBdhN0t8A".to_string(),
            key: Some("value".to_string()),
            value: Value::String("x".to_string()),
            disclosure_array: "[\"cTgNF-AtESuivLBdhN0t8A\",\"value\",\"x\"]".to_string(),
            disclosure: "WyJjVGdORi1BdEVTdWl2TEJkaE4wdDhBIiwidmFsdWUiLCJ4Il0".to_string()
        },
        Disclosure {
            salt: "xtyBeqglpTfvXrqQzsXMFw".to_string(),
            key: Some("obj1".to_string()),
            value: json!({
              "_sd": [
                "h_168PHZpT88mJ42IzpRY0Jr1gWoQCMLGQTD43PxlQk",
              ]
            }),
            disclosure_array: "[\"xtyBeqglpTfvXrqQzsXMFw\",\"obj1\",{\"_sd\":[\"h_168PHZpT88mJ42IzpRY0Jr1gWoQCMLGQTD43PxlQk\"]}]".to_string(),
            disclosure: "WyJ4dHlCZXFnbHBUZnZYcnFRenNYTUZ3Iiwib2JqMSIseyJfc2QiOlsiaF8xNjhQSFpwVDg4bUo0Mkl6cFJZMEpyMWdXb1FDTUxHUVRENDNQeGxRayJdfV0".to_string(),
        },
        Disclosure {
            salt: "nEP135SkAyOTnMA67CNTAA".to_string(),
            key: Some("value".to_string()),
            value: Value::String("y".to_string()),
            disclosure_array: "[\"nEP135SkAyOTnMA67CNTAA\",\"value\",\"y\"]".to_string(),
            disclosure: "WyJuRVAxMzVTa0F5T1RuTUE2N0NOVEFBIiwidmFsdWUiLCJ5Il0".to_string()
        },
        Disclosure {
            salt: "pggVbYzzu6oOGXrmNVGPHP".to_string(),
            key: Some("obj2".to_string()),
            value: json!({
              "_sd": [
                "OYr-E2w60YkuGmTqfxZ1krYczVPQnN4D2ZrWBNQ73e4"
              ]
            }),
            disclosure_array: "[\"pggVbYzzu6oOGXrmNVGPHP\",\"obj2\",{\"_sd\":[\"OYr-E2w60YkuGmTqfxZ1krYczVPQnN4D2ZrWBNQ73e4\"]}]".to_string(),
            disclosure: "WyJwZ2dWYll6enU2b09HWHJtTlZHUEhQIiwib2JqMiIseyJfc2QiOlsiT1lyLUUydzYwWWt1R21UcWZ4WjFrclljelZQUW5ONEQyWnJXQk5RNzNlNCJdfV0".to_string(),
        }
    ];
    let expected = HashSet::<String>::from_iter([
        disclosures[0].disclosure.to_string(),
        disclosures[1].disclosure.to_string(),
    ]);

    let result =
        select_disclosures(&["obj1/value".into()], &payload, disclosures, &SHA256).unwrap();

    assert_eq!(expected, HashSet::from_iter(result));
}

#[test]
fn test_select_disclosures_returns_empty_when_disclosed_key_not_found_in_disclosures() {
    let (payload, disclosures) = generic_disclosures();

    let disclosures = select_disclosures(&["abcd".into()], &payload, disclosures, &SHA256).unwrap();
    assert!(disclosures.is_empty());
}

pub fn get_credential_data(status: CredentialStatus, core_base_url: &str) -> CredentialData {
    let issuance_date = OffsetDateTime::now_utc();
    let valid_for = time::Duration::days(365 * 2);

    let schema_context: ContextType = format!("{core_base_url}/ssi/context/v1/{}", Uuid::new_v4())
        .parse::<Url>()
        .unwrap()
        .into();
    let schema = CredentialSchema {
        id: "http://schema.test/id".to_owned(),
        r#type: "TestType".to_owned(),
        metadata: None,
    };

    let holder_did: DidValue = "did:example:123".parse().unwrap();

    let claims = vec![
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
    ];
    let issuer_did = Issuer::Url("did:issuer:test".parse().unwrap());
    let credential_subject =
        VcdmCredentialSubject::new(nest_claims(claims.clone()).unwrap()).unwrap();
    let vcdm = VcdmCredential::new_v2(issuer_did, credential_subject)
        .add_context(schema_context)
        .add_credential_schema(schema)
        .add_credential_status(status)
        .with_valid_from(issuance_date)
        .with_valid_until(issuance_date + valid_for);

    let holder_identifier = Identifier {
        did: Some(Did {
            did: holder_did,
            ..dummy_did()
        }),
        ..dummy_identifier()
    };

    CredentialData {
        vcdm,
        claims,
        holder_identifier: Some(holder_identifier),
        holder_key_id: Some("did-vm-id".to_string()),
        issuer_certificate: None,
    }
}
