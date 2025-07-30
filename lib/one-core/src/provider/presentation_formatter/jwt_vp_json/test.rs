use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use mockall::predicate::eq;
use similar_asserts::assert_eq;
use time::Duration;

use crate::config::core_config::{FormatType, KeyAlgorithmType, VerificationProtocolType};
use crate::provider::credential_formatter::common::MockAuth;
use crate::provider::credential_formatter::model::{
    IdentifierDetails, MockTokenVerifier, PublicKeySource,
};
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::jwt_vp_json::model::{VP, VerifiableCredential};
use crate::provider::presentation_formatter::jwt_vp_json::{JwtVpPresentationFormatter, Params};
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, ExtractPresentationCtx, FormattedPresentation,
};
use crate::util::jwt::model::JWTPayload;

#[tokio::test]
async fn test_extract_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJKV1QifQ.ewogICJpYXQiOiAxNjk5MzU3NTgyLAogICJleHAiOiAxNjk5MzU3ODgyLAogICJuYmYiOiAxNjk5MzU3NTM3LAogICJpc3MiOiAiZGlkOmlzc3VlcjoxMjMiLAogICJzdWIiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJqdGkiOiAiNjZhYWI2YTYtZDE1Yy00M2RiLWIwOTUtMzkxYTc1YWZjNzhlIiwKICAidnAiOiB7CiAgICAiQGNvbnRleHQiOiBbCiAgICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICAgIF0sCiAgICAidHlwZSI6IFsKICAgICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgICBdLAogICAgInZlcmlmaWFibGVDcmVkZW50aWFsIjogWwogICAgICAiZXlKaGJHY2lPaUpoYkdkdmNtbDBhRzBpTENKMGVYQWlPaUpUUkVwWFZDSjkuZXlKcFlYUWlPakUyT1RreU56QXlOallzSW1WNGNDSTZNVGMyTWpNME1qSTJOaXdpYm1KbUlqb3hOams1TWpjd01qSXhMQ0pwYzNNaU9pSkpjM04xWlhJZ1JFbEVJaXdpYzNWaUlqb2lhRzlzWkdWeVgyUnBaQ0lzSW1wMGFTSTZJamxoTkRFMFlUWXdMVGxsTm1JdE5EYzFOeTA0TURFeExUbGhZVGczTUdWbU5EYzRPQ0lzSW5aaklqcDdJa0JqYjI1MFpYaDBJanBiSW1oMGRIQnpPaTh2ZDNkM0xuY3pMbTl5Wnk4eU1ERTRMMk55WldSbGJuUnBZV3h6TDNZeElpd2lRMjl1ZEdWNGRERWlYU3dpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0lsUjVjR1V4SWwwc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJbDl6WkNJNld5SlpWMHBxVFZSSmVpSXNJbGxYU21wTlZFbDZJbDE5TENKamNtVmtaVzUwYVdGc1UzUmhkSFZ6SWpwN0ltbGtJam9pVTFSQlZGVlRYMGxFSWl3aWRIbHdaU0k2SWxSWlVFVWlMQ0p6ZEdGMGRYTlFkWEp3YjNObElqb2lVRlZTVUU5VFJTSXNJa1pwWld4a01TSTZJbFpoYkRFaWZYMHNJbDl6WkY5aGJHY2lPaUp6YUdFdE1qVTJJbjAuUVVKRCIKICAgIF0KICB9Cn0";
    let presentation_token = format!("{jwt_token}.QUJD");

    let leeway = 45u64;

    let jwt_formatter = JwtVpPresentationFormatter {
        params: Params { leeway },
    };

    let mut verify_mock = MockTokenVerifier::new();
    verify_mock
        .expect_verify()
        .withf(
            move |params, algorithm, token, signature| {
                assert!(matches!(params, PublicKeySource::Did {did, ..} if did.to_string() == "did:issuer:123"));
                assert_eq!(KeyAlgorithmType::Eddsa, *algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_, _, _, _| Ok(()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .returning(|_| {
            let mut key_algorithm = MockKeyAlgorithm::default();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some((KeyAlgorithmType::Eddsa, Arc::new(key_algorithm)))
        });
    verify_mock
        .expect_key_algorithm_provider()
        .return_const(Box::new(key_algorithm_provider));

    let result = jwt_formatter
        .extract_presentation(
            &presentation_token,
            Box::new(verify_mock),
            ExtractPresentationCtx {
                verification_protocol_type: VerificationProtocolType::OpenId4VpDraft20,
                nonce: None,
                format_nonce: None,
                issuance_date: None,
                expiration_date: None,
                client_id: None,
                response_uri: None,
                mdoc_session_transcript: None,
                verifier_key: None,
            },
        )
        .await;

    assert!(result.is_ok());

    let presentation = result.unwrap();

    assert_eq!(
        presentation.expires_at,
        Some(presentation.issued_at.unwrap() + Duration::minutes(5)),
    );

    assert_eq!(presentation.credentials.len(), 1);
    assert_eq!(
        presentation.issuer,
        Some(IdentifierDetails::Did("did:issuer:123".parse().unwrap()))
    );
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

    let mut key_algorithm = MockKeyAlgorithm::new();
    key_algorithm
        .expect_issuance_jose_alg_id()
        .returning(|| Some("ES256".to_string()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .with(eq(KeyAlgorithmType::Ecdsa))
        .return_once(|_| Some(Arc::new(key_algorithm)));

    let jwt_formatter = JwtVpPresentationFormatter {
        params: Params { leeway },
    };

    let auth_fn = MockAuth(|_| vec![65u8, 66, 67]);

    let result = jwt_formatter
        .format_presentation(
            vec![CredentialToPresent {
                raw_credential: jwt_token.to_owned(),
                credential_format: FormatType::Jwt,
            }],
            Box::new(auth_fn),
            &"did:example:123".parse().unwrap(),
            Default::default(),
        )
        .await;

    assert!(result.is_ok());

    let FormattedPresentation { vp_token, .. } = result.unwrap();

    let jwt_parts: Vec<&str> = vp_token.splitn(3, '.').collect();

    assert_eq!(
        jwt_parts[0],
        &Base64UrlSafeNoPadding::encode_to_string(r##"{"alg":"ES256","kid":"#key0","typ":"JWT"}"##)
            .unwrap()
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

    assert_eq!(payload.issuer, Some(String::from("did:example:123")));
    assert_eq!(payload.subject, Some(String::from("did:example:123")));

    let vp = payload.custom.vp;

    assert_eq!(vp.verifiable_credential.len(), 1);
    assert_eq!(
        vp.verifiable_credential[0],
        VerifiableCredential::Token(jwt_token.to_string())
    );
}
