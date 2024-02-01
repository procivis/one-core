use std::collections::HashMap;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use time::Duration;

use super::JWTFormatter;

use crate::provider::credential_formatter::{
    jwt::model::JWTPayload,
    jwt_formatter::{
        model::{VC, VP},
        Params,
    },
    model::{CredentialPresentation, CredentialStatus},
    test_utilities::test_credential_detail_response_dto,
    CredentialFormatter, MockAuth, MockTokenVerifier,
};

#[tokio::test]
async fn test_format_credential() {
    let leeway = 45u64;

    let sd_formatter = JWTFormatter {
        params: Params { leeway },
    };

    let credential_details = test_credential_detail_response_dto();

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = sd_formatter
        .format_credentials(
            &credential_details,
            Some(CredentialStatus {
                id: "STATUS_ID".to_string(),
                r#type: "TYPE".to_string(),
                status_purpose: "PURPOSE".to_string(),
                additional_fields: HashMap::from([("Field1".to_owned(), "Val1".to_owned())]),
            }),
            &"holder_did".parse().unwrap(),
            "algorithm",
            vec!["Context1".to_string()],
            vec!["Type1".to_string()],
            Box::new(auth_fn),
        )
        .await;

    assert!(result.is_ok());

    let token = result.unwrap();

    let jwt_parts: Vec<&str> = token.splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(r#"{"alg":"algorithm","typ":"JWT"}"#).unwrap()
    );
    assert_eq!(
        jwt_parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"ABC"#).unwrap()
    );

    let payload: JWTPayload<VC> = serde_json::from_str(
        &String::from_utf8(Base64UrlSafeNoPadding::decode_to_vec(jwt_parts[1], None).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(
        payload.expires_at,
        Some(payload.issued_at.unwrap() + Duration::days(365 * 2)),
    );
    assert_eq!(
        payload.invalid_before,
        Some(payload.issued_at.unwrap() - Duration::seconds(leeway as i64)),
    );

    assert_eq!(payload.issuer, Some(String::from("Issuer DID")));
    assert_eq!(payload.subject, Some(String::from("holder_did")));

    let vc = payload.custom.vc;

    assert!(vc
        .credential_subject
        .values
        .iter()
        .all(|claim| ["name", "age"].contains(&claim.0.as_str())));

    assert!(vc.context.contains(&String::from("Context1")));
    assert!(vc.r#type.contains(&String::from("Type1")));

    assert_eq!(vc.credential_status.as_ref().unwrap().id, "STATUS_ID");
    assert_eq!(vc.credential_status.as_ref().unwrap().r#type, "TYPE");
    assert_eq!(
        vc.credential_status.as_ref().unwrap().status_purpose,
        "PURPOSE"
    );
    assert_eq!(
        vc.credential_status
            .as_ref()
            .unwrap()
            .additional_fields
            .get("Field1"),
        Some(&"Val1".to_string())
    );
}

#[tokio::test]
async fn test_extract_credentials() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTkzNTQyMjgsI\
        mV4cCI6MTc2MjQyNjIyOCwibmJmIjoxNjk5MzU0MTgzLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVy\
        X2RpZCIsImp0aSI6IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7IkBjb250ZXh\
        0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiQ29udGV4dDEiXSwidHlwZSI6Wy\
        JWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlR5cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFnZSI6IjQyIiwib\
        mFtZSI6IkpvaG4ifSwiY3JlZGVudGlhbFN0YXR1cyI6eyJpZCI6IlNUQVRVU19JRCIsInR5cGUiOiJUWVBFIiwi\
        c3RhdHVzUHVycG9zZSI6IlBVUlBPU0UiLCJGaWVsZDEiOiJWYWwxIn19fQ";

    let token = format!("{jwt_token}.QUJD");

    let leeway = 45u64;

    let jwt_formatter = JWTFormatter {
        params: Params { leeway },
    };

    let mut verify_mock = MockTokenVerifier::new();

    verify_mock
        .expect_verify()
        .withf(
            move |issuer_did_value, _key_id, algorithm, token, signature| {
                assert_eq!("Issuer DID", issuer_did_value.as_ref().unwrap().as_str());
                assert_eq!("algorithm", algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _, _| Ok(()));

    let result = jwt_formatter
        .extract_credentials(&token, Box::new(verify_mock))
        .await;

    let credentials = result.unwrap();

    assert_eq!(credentials.issuer_did, Some("Issuer DID".parse().unwrap()),);
    assert_eq!(credentials.subject, Some("holder_did".parse().unwrap()));

    assert_eq!(credentials.status.as_ref().unwrap().id, "STATUS_ID");
    assert_eq!(credentials.status.as_ref().unwrap().r#type, "TYPE");
    assert_eq!(
        credentials.status.as_ref().unwrap().status_purpose,
        "PURPOSE"
    );
    assert_eq!(
        credentials
            .status
            .as_ref()
            .unwrap()
            .additional_fields
            .get("Field1"),
        Some(&"Val1".to_string())
    );

    assert_eq!(credentials.claims.values.get("name").unwrap(), "John");
    assert_eq!(credentials.claims.values.get("age").unwrap(), "42");
}

#[tokio::test]
async fn test_format_credential_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.\
        eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5Mjcw\
        MjIxLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVyX2RpZCIsImp0aSI6\
        IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7IkBj\
        b250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3Yx\
        IiwiQ29udGV4dDEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlR5\
        cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJZV0pqTVRJeiIsIllX\
        SmpNVEl6Il19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiU1RBVFVTX0lEIiwi\
        dHlwZSI6IlRZUEUiLCJzdGF0dXNQdXJwb3NlIjoiUFVSUE9TRSIsIkZpZWxkMSI6\
        IlZhbDEifX0sIl9zZF9hbGciOiJzaGEtMjU2In0.QUJD";

    let jwt_formatter = JWTFormatter {
        params: Params { leeway: 45 },
    };

    // Both
    let credential_presentation = CredentialPresentation {
        token: jwt_token.to_owned(),
        disclosed_keys: vec!["name".to_string(), "age".to_string()],
    };

    let result = jwt_formatter.format_credential_presentation(credential_presentation);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), jwt_token);

    // Just name
    let credential_presentation = CredentialPresentation {
        token: jwt_token.to_owned(),
        disclosed_keys: vec!["name".to_string()],
    };

    let result = jwt_formatter.format_credential_presentation(credential_presentation);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), jwt_token);
}

#[tokio::test]
async fn test_format_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.\
        eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5Mjcw\
        MjIxLCJpc3MiOiJJc3N1ZXIgRElEIiwic3ViIjoiaG9sZGVyX2RpZCIsImp0aSI6\
        IjlhNDE0YTYwLTllNmItNDc1Ny04MDExLTlhYTg3MGVmNDc4OCIsInZjIjp7IkBj\
        b250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3Yx\
        IiwiQ29udGV4dDEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlR5\
        cGUxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJZV0pqTVRJeiIsIllX\
        SmpNVEl6Il19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiU1RBVFVTX0lEIiwi\
        dHlwZSI6IlRZUEUiLCJzdGF0dXNQdXJwb3NlIjoiUFVSUE9TRSIsIkZpZWxkMSI6\
        IlZhbDEifX0sIl9zZF9hbGciOiJzaGEtMjU2In0.QUJD";

    let leeway = 45u64;

    let jwt_formatter = JWTFormatter {
        params: Params { leeway },
    };

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = jwt_formatter
        .format_presentation(
            &[jwt_token.to_owned()],
            &"holder_did".parse().unwrap(),
            "algorithm",
            Box::new(auth_fn),
            None,
        )
        .await;

    assert!(result.is_ok());

    let presentation_token = result.unwrap();

    let jwt_parts: Vec<&str> = presentation_token.splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(r#"{"alg":"algorithm","typ":"JWT"}"#).unwrap()
    );
    assert_eq!(
        jwt_parts[2],
        &Base64UrlSafeNoPadding::encode_to_string(r#"ABC"#).unwrap()
    );

    let payload: JWTPayload<VP> = serde_json::from_str(
        &String::from_utf8(Base64UrlSafeNoPadding::decode_to_vec(jwt_parts[1], None).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(
        payload.expires_at,
        Some(payload.issued_at.unwrap() + Duration::minutes(5)),
    );
    assert_eq!(
        payload.invalid_before,
        Some(payload.issued_at.unwrap() - Duration::seconds(leeway as i64)),
    );

    assert_eq!(payload.issuer, Some(String::from("holder_did")));
    assert_eq!(payload.subject, Some(String::from("holder_did")));

    let vp = payload.custom.vp;

    assert_eq!(vp.verifiable_credential.len(), 1);
    assert_eq!(vp.verifiable_credential[0], jwt_token);
}

#[tokio::test]
async fn test_extract_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTkzNTc1ODIsI\
        mV4cCI6MTY5OTM1Nzg4MiwibmJmIjoxNjk5MzU3NTM3LCJpc3MiOiJob2xkZXJfZGlkIiwic3ViIjoiaG9sZGVy\
        X2RpZCIsImp0aSI6IjY2YWFiNmE2LWQxNWMtNDNkYi1iMDk1LTM5MWE3NWFmYzc4ZSIsInZwIjp7IkBjb250ZXh\
        0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZV\
        ByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSmhiR2R2Y21sMGFHMGlMQ\
        0owZVhBaU9pSlRSRXBYVkNKOS5leUpwWVhRaU9qRTJPVGt5TnpBeU5qWXNJbVY0Y0NJNk1UYzJNak0wTWpJMk5p\
        d2libUptSWpveE5qazVNamN3TWpJeExDSnBjM01pT2lKSmMzTjFaWElnUkVsRUlpd2ljM1ZpSWpvaWFHOXNaR1Z\
        5WDJScFpDSXNJbXAwYVNJNklqbGhOREUwWVRZd0xUbGxObUl0TkRjMU55MDRNREV4TFRsaFlUZzNNR1ZtTkRjNE\
        9DSXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV\
        1JsYm5ScFlXeHpMM1l4SWl3aVEyOXVkR1Y0ZERFaVhTd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdW\
        dWRHbGhiQ0lzSWxSNWNHVXhJbDBzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lsOXpaQ0k2V3lKWlYwcHF\
        UVlJKZWlJc0lsbFhTbXBOVkVsNklsMTlMQ0pqY21Wa1pXNTBhV0ZzVTNSaGRIVnpJanA3SW1sa0lqb2lVMVJCVk\
        ZWVFgwbEVJaXdpZEhsd1pTSTZJbFJaVUVVaUxDSnpkR0YwZFhOUWRYSndiM05sSWpvaVVGVlNVRTlUUlNJc0lrW\
        nBaV3hrTVNJNklsWmhiREVpZlgwc0lsOXpaRjloYkdjaU9pSnphR0V0TWpVMkluMC5RVUpEIl19fQ";
    let presentation_token = format!("{jwt_token}.QUJD");

    let leeway = 45u64;

    let jwt_formatter = JWTFormatter {
        params: Params { leeway },
    };

    let mut verify_mock = MockTokenVerifier::new();

    verify_mock
        .expect_verify()
        .withf(
            move |issuer_did_value, _key_id, algorithm, token, signature| {
                assert_eq!("holder_did", issuer_did_value.as_ref().unwrap().as_str());
                assert_eq!("algorithm", algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _, _| Ok(()));

    let result = jwt_formatter
        .extract_presentation(&presentation_token, Box::new(verify_mock))
        .await;

    assert!(result.is_ok());

    let presentation = result.unwrap();

    assert_eq!(
        presentation.expires_at,
        Some(presentation.issued_at.unwrap() + Duration::minutes(5)),
    );

    assert_eq!(presentation.credentials.len(), 1);
    assert_eq!(presentation.issuer_did, Some("holder_did".parse().unwrap()));
}

#[test]
fn test_get_capabilities() {
    let jwt_formatter = JWTFormatter {
        params: Params { leeway: 123u64 },
    };

    assert_eq!(0, jwt_formatter.get_capabilities().features.len());
}
