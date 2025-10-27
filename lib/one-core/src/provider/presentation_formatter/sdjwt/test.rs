use std::sync::Arc;

use one_crypto::MockCryptoProvider;
use similar_asserts::assert_eq;
use time::Duration;

use super::SdjwtPresentationFormatter;
use crate::config::core_config::{KeyAlgorithmType, VerificationProtocolType};
use crate::proto::http_client::MockHttpClient;
use crate::provider::credential_formatter::model::{
    IdentifierDetails, MockTokenVerifier, PublicKeySource,
};
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::model::ExtractPresentationCtx;

#[tokio::test]
async fn test_extract_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.ewogICJpYXQiOiAxNjk5MzUxODQxLAogICJleHAiOiAxNjk5MzUyMTQxLAogICJuYmYiOiAxNjk5MzUxNzk2LAogICJpc3MiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJzdWIiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJqdGkiOiAiYjRjYzQ5ZDUtOGQwZS00ODFlLWIxZWItOGU0ZThiOTY5NmIxIiwKICAidnAiOiB7CiAgICAiQGNvbnRleHQiOiBbCiAgICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICAgIF0sCiAgICAidHlwZSI6IFsKICAgICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgICBdLAogICAgIl9zZF9qd3QiOiBbCiAgICAgICJleUpoYkdjaU9pSmhiR2R2Y21sMGFHMGlMQ0owZVhBaU9pSlRSRXBYVkNKOS5leUpwWVhRaU9qRTJPVGt5TnpBeU5qWXNJbVY0Y0NJNk1UYzJNak0wTWpJMk5pd2libUptSWpveE5qazVNamN3TWpJeExDSnBjM01pT2lKSmMzTjFaWElnUkVsRUlpd2ljM1ZpSWpvaWFHOXNaR1Z5WDJScFpDSXNJbXAwYVNJNklqbGhOREUwWVRZd0xUbGxObUl0TkRjMU55MDRNREV4TFRsaFlUZzNNR1ZtTkRjNE9DSXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMM1l4SWl3aVEyOXVkR1Y0ZERFaVhTd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSWxSNWNHVXhJbDBzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lsOXpaQ0k2V3lKWlYwcHFUVlJKZWlJc0lsbFhTbXBOVkVsNklsMTlMQ0pqY21Wa1pXNTBhV0ZzVTNSaGRIVnpJanA3SW1sa0lqb2lVMVJCVkZWVFgwbEVJaXdpZEhsd1pTSTZJbFJaVUVVaUxDSnpkR0YwZFhOUWRYSndiM05sSWpvaVVGVlNVRTlUUlNJc0lrWnBaV3hrTVNJNklsWmhiREVpZlgwc0lsOXpaRjloYkdjaU9pSnphR0V0TWpVMkluMC5RVUpEfld5Sk5WRWw2V1ZkS2FpSXNJbTVoYldVaUxDSktiMmh1SWwwfld5Sk5WRWw2V1ZkS2FpSXNJbUZuWlNJc0lqUXlJbDAiCiAgICBdCiAgfQp9";
    let presentation_token = format!("{jwt_token}.QUJD");

    let crypto = MockCryptoProvider::default();

    let sd_formatter =
        SdjwtPresentationFormatter::new(Arc::new(MockHttpClient::new()), Arc::new(crypto));

    let mut verify_mock = MockTokenVerifier::new();
    verify_mock
        .expect_verify()
        .withf(
            move |params, algorithm, token, signature| {
                assert!(matches!(params, PublicKeySource::Did {did, ..} if did.to_string() == "did:holder:123"));
                assert_eq!(KeyAlgorithmType::Eddsa, *algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(vec![65u8, 66, 67], signature);
                true
            },
        )
        .return_once(|_,  _, _, _| Ok(()));

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

    let presentation = sd_formatter
        .extract_presentation(
            &presentation_token,
            Box::new(verify_mock),
            ExtractPresentationCtx {
                verification_protocol_type: VerificationProtocolType::OpenId4VpDraft20,
                nonce: None,
                format_nonce: None,
                issuance_date: None,
                expiration_date: None,
                mdoc_session_transcript: None,
                client_id: None,
                response_uri: None,
                verifier_key: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        presentation.expires_at,
        Some(presentation.issued_at.unwrap() + Duration::minutes(5)),
    );

    assert_eq!(presentation.credentials.len(), 1);
    assert_eq!(
        presentation.issuer,
        Some(IdentifierDetails::Did("did:holder:123".parse().unwrap()))
    );
}
