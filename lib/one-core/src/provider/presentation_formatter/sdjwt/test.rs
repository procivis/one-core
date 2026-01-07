use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use mockall::predicate::eq;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::{Hasher, MockCryptoProvider};
use serde_json::Value;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::Duration;

use super::SdjwtPresentationFormatter;
use crate::config::core_config::{FormatType, KeyAlgorithmType, VerificationProtocolType};
use crate::proto::http_client::MockHttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::JWTPayload;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    IdentifierDetails, MockSignatureProvider, MockTokenVerifier, PublicKeySource,
};
use crate::provider::credential_formatter::sdjwt::model::KeyBindingPayload;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, ExtractPresentationCtx, FormatPresentationCtx,
};

#[tokio::test]
async fn test_format_presentation_with_cnf_success() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIlNESldUIgp9.eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5MjcwMjIxLCJpc3MiOiJkaWQ6aXNzdWVyOnRlc3QiLCJzdWIiOiJkaWQ6aG9sZGVyOnRlc3QiLCJqdGkiOiI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiMTh3SExlSWdXOXdWTjZWRDFUeGdwcXkyTHN6WWtNZjZKOG5qVkFpYnZoTSIsInkiOiItVjRkUzRVYUxNZ1BfNGZZNGo4aXI3Y2wxVFhsRmRBZ2N4NTVvN1RrY1NBIn19LCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnRlc3Rjb250ZXh0LmNvbS92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVHlwZTEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbIkhabk1zenlDZERkTDFqSG5Wck5aZHRmdjhiSlR0Z25wa1NfbEl6SDI0eTgiLCJCT1QzNU1ZSnc1bzlLaTdEMFdxSlh2LXdKMDFkcXotbFF0T3Fod01pdnFvIl19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOnN0YXR1czppZCIsInR5cGUiOiJUWVBFIiwic3RhdHVzUHVycG9zZSI6IlBVUlBPU0UiLCJGaWVsZDEiOiJWYWwxIn19LCJfc2RfYWxnIjoic2hhLTI1NiJ9";
    let key_name = "WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0";
    let token = format!("{jwt_token}.QUJD~{key_name}~");
    let key_id = "key-id";
    let key_alg = "ES256";
    let audience = "some-aud";
    let nonce = "nonce";
    let holder_did: DidValue = "did:holder:test".to_string().try_into().unwrap();

    let mut signer = MockSignatureProvider::default();
    signer
        .expect_jose_alg()
        .returning(|| Some(key_alg.to_string()));
    signer
        .expect_get_key_algorithm()
        .returning(|| Ok(KeyAlgorithmType::Ecdsa));
    signer
        .expect_get_key_id()
        .returning(|| Some(key_id.to_string()));

    // The first signature is for the Key Biding token
    // The second signature is for the wrapping JWT presentation formatter
    signer.expect_sign().times(2).returning(|_| Ok(vec![0; 32]));

    let mut crypto = MockCryptoProvider::default();
    crypto
        .expect_get_hasher()
        .with(eq("sha-256"))
        .returning(|_| Ok(Arc::new(SHA256 {})));

    let sd_formatter = SdjwtPresentationFormatter::new(
        Arc::new(MockHttpClient::new()),
        Arc::new(crypto),
        Arc::new(MockKeyAlgorithmProvider::default()),
    );

    let presentation = sd_formatter
        .format_presentation(
            vec![CredentialToPresent {
                credential_token: token.clone(),
                credential_format: FormatType::SdJwt,
                lvvc_credential_token: None,
            }],
            Box::new(signer),
            &Some(holder_did.clone()),
            FormatPresentationCtx {
                nonce: Some(nonce.to_string()),
                audience: Some(audience.to_string()),
                mdoc_session_transcript: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(presentation.oidc_format, "jwt_vp_json");
    let presented_credential = {
        let jwt_parts: Vec<&str> = presentation.vp_token.splitn(3, '.').collect();

        // The outer envelope is signed
        assert_eq!(
            jwt_parts.last().unwrap(),
            &"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );

        let payload: JWTPayload<Value> = serde_json::from_str(
            &String::from_utf8(Base64UrlSafeNoPadding::decode_to_vec(jwt_parts[1], None).unwrap())
                .unwrap(),
        )
        .unwrap();

        let presented_credentials = payload
            .custom
            .get("vp")
            .unwrap()
            .get("verifiableCredential")
            .unwrap()
            .as_array()
            .unwrap();

        assert_eq!(presented_credentials.len(), 1);
        presented_credentials
            .first()
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    };

    let (_, kb_token) = presented_credential.rsplit_once("~").unwrap();

    assert!(!kb_token.is_empty());
    assert!(kb_token.ends_with(".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")); // fake sig: vec![0;32]
    let kb_jwt = Jwt::<KeyBindingPayload>::build_from_token(kb_token, None, None)
        .await
        .unwrap();

    assert_eq!(kb_jwt.header.key_id, None);
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
}

#[tokio::test]
async fn test_format_presentation_with_cnf_missing_nonce_fails() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIlNESldUIgp9.eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5MjcwMjIxLCJpc3MiOiJkaWQ6aXNzdWVyOnRlc3QiLCJzdWIiOiJkaWQ6aG9sZGVyOnRlc3QiLCJqdGkiOiI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiMTh3SExlSWdXOXdWTjZWRDFUeGdwcXkyTHN6WWtNZjZKOG5qVkFpYnZoTSIsInkiOiItVjRkUzRVYUxNZ1BfNGZZNGo4aXI3Y2wxVFhsRmRBZ2N4NTVvN1RrY1NBIn19LCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnRlc3Rjb250ZXh0LmNvbS92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVHlwZTEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbIkhabk1zenlDZERkTDFqSG5Wck5aZHRmdjhiSlR0Z25wa1NfbEl6SDI0eTgiLCJCT1QzNU1ZSnc1bzlLaTdEMFdxSlh2LXdKMDFkcXotbFF0T3Fod01pdnFvIl19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOnN0YXR1czppZCIsInR5cGUiOiJUWVBFIiwic3RhdHVzUHVycG9zZSI6IlBVUlBPU0UiLCJGaWVsZDEiOiJWYWwxIn19LCJfc2RfYWxnIjoic2hhLTI1NiJ9";
    let key_name = "WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0";
    let token = format!("{jwt_token}.QUJD~{key_name}~");
    let audience = "some-aud";
    let holder_did: DidValue = "did:holder:test".to_string().try_into().unwrap();

    let sd_formatter = SdjwtPresentationFormatter::new(
        Arc::new(MockHttpClient::new()),
        Arc::new(MockCryptoProvider::default()),
        Arc::new(MockKeyAlgorithmProvider::default()),
    );

    let result = sd_formatter
        .format_presentation(
            vec![CredentialToPresent {
                credential_token: token.clone(),
                credential_format: FormatType::SdJwt,
                lvvc_credential_token: None,
            }],
            Box::new(MockSignatureProvider::default()),
            &Some(holder_did),
            FormatPresentationCtx {
                nonce: None,
                audience: Some(audience.to_string()),
                ..Default::default()
            },
        )
        .await;

    assert!(matches!(result, Err(FormatterError::Failed(_))));
}

#[tokio::test]
async fn test_format_presentation_with_cnf_missing_audience_fails() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIlNESldUIgp9.eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5MjcwMjIxLCJpc3MiOiJkaWQ6aXNzdWVyOnRlc3QiLCJzdWIiOiJkaWQ6aG9sZGVyOnRlc3QiLCJqdGkiOiI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJ4IjoiMTh3SExlSWdXOXdWTjZWRDFUeGdwcXkyTHN6WWtNZjZKOG5qVkFpYnZoTSIsInkiOiItVjRkUzRVYUxNZ1BfNGZZNGo4aXI3Y2wxVFhsRmRBZ2N4NTVvN1RrY1NBIn19LCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnRlc3Rjb250ZXh0LmNvbS92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVHlwZTEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbIkhabk1zenlDZERkTDFqSG5Wck5aZHRmdjhiSlR0Z25wa1NfbEl6SDI0eTgiLCJCT1QzNU1ZSnc1bzlLaTdEMFdxSlh2LXdKMDFkcXotbFF0T3Fod01pdnFvIl19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOnN0YXR1czppZCIsInR5cGUiOiJUWVBFIiwic3RhdHVzUHVycG9zZSI6IlBVUlBPU0UiLCJGaWVsZDEiOiJWYWwxIn19LCJfc2RfYWxnIjoic2hhLTI1NiJ9";
    let key_name = "WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0";
    let token = format!("{jwt_token}.QUJD~{key_name}~");
    let nonce = "nonce";
    let holder_did: DidValue = "did:holder:test".to_string().try_into().unwrap();

    let sd_formatter = SdjwtPresentationFormatter::new(
        Arc::new(MockHttpClient::new()),
        Arc::new(MockCryptoProvider::default()),
        Arc::new(MockKeyAlgorithmProvider::default()),
    );

    let result = sd_formatter
        .format_presentation(
            vec![CredentialToPresent {
                credential_token: token.clone(),
                credential_format: FormatType::SdJwt,
                lvvc_credential_token: None,
            }],
            Box::new(MockSignatureProvider::default()),
            &Some(holder_did),
            FormatPresentationCtx {
                nonce: Some(nonce.to_string()),
                audience: None,
                ..Default::default()
            },
        )
        .await;

    assert!(matches!(result, Err(FormatterError::Failed(_))));
}

#[tokio::test]
async fn test_format_presentation_without_cnf_success() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIlNESldUIgp9.eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5MjcwMjIxLCJpc3MiOiJkaWQ6aXNzdWVyOnRlc3QiLCJzdWIiOiJkaWQ6aG9sZGVyOnRlc3QiLCJqdGkiOiI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnRlc3Rjb250ZXh0LmNvbS92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVHlwZTEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbIkhabk1zenlDZERkTDFqSG5Wck5aZHRmdjhiSlR0Z25wa1NfbEl6SDI0eTgiLCJCT1QzNU1ZSnc1bzlLaTdEMFdxSlh2LXdKMDFkcXotbFF0T3Fod01pdnFvIl19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOnN0YXR1czppZCIsInR5cGUiOiJUWVBFIiwic3RhdHVzUHVycG9zZSI6IlBVUlBPU0UiLCJGaWVsZDEiOiJWYWwxIn19LCJfc2RfYWxnIjoic2hhLTI1NiJ9";
    let key_name = "WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0";
    let token = format!("{jwt_token}.QUJD~{key_name}~");
    let key_id = "key-id";
    let key_alg = "ES256";
    let audience = "some-aud";
    let nonce = "nonce";
    let holder_did: DidValue = "did:holder:test".to_string().try_into().unwrap();

    let mut signer = MockSignatureProvider::default();
    signer
        .expect_jose_alg()
        .returning(|| Some(key_alg.to_string()));
    signer
        .expect_get_key_algorithm()
        .returning(|| Ok(KeyAlgorithmType::Ecdsa));
    signer
        .expect_get_key_id()
        .returning(|| Some(key_id.to_string()));

    // We only expect 1 signature for the outer envelope
    signer.expect_sign().once().returning(|_| Ok(vec![0; 32]));

    let mut crypto = MockCryptoProvider::default();
    crypto
        .expect_get_hasher()
        .with(eq("sha-256"))
        .returning(|_| Ok(Arc::new(SHA256 {})));

    let sd_formatter = SdjwtPresentationFormatter::new(
        Arc::new(MockHttpClient::new()),
        Arc::new(crypto),
        Arc::new(MockKeyAlgorithmProvider::default()),
    );

    let presentation = sd_formatter
        .format_presentation(
            vec![CredentialToPresent {
                credential_token: token.clone(),
                credential_format: FormatType::SdJwt,
                lvvc_credential_token: None,
            }],
            Box::new(signer),
            &Some(holder_did.clone()),
            FormatPresentationCtx {
                nonce: Some(nonce.to_string()),
                audience: Some(audience.to_string()),
                mdoc_session_transcript: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(presentation.oidc_format, "jwt_vp_json");
    let presented_credential = {
        let jwt_parts: Vec<&str> = presentation.vp_token.splitn(3, '.').collect();

        // The outer envelope is signed
        assert_eq!(
            jwt_parts.last().unwrap(),
            &"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );

        let payload: JWTPayload<Value> = serde_json::from_str(
            &String::from_utf8(Base64UrlSafeNoPadding::decode_to_vec(jwt_parts[1], None).unwrap())
                .unwrap(),
        )
        .unwrap();

        let presented_credentials = payload
            .custom
            .get("vp")
            .unwrap()
            .get("verifiableCredential")
            .unwrap()
            .as_array()
            .unwrap();

        assert_eq!(presented_credentials.len(), 1);
        presented_credentials
            .first()
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    };

    let (_, kb_token) = presented_credential.rsplit_once("~").unwrap();

    assert!(kb_token.is_empty());
}

#[tokio::test]
async fn test_format_presentation_without_cnf_missing_audience_nonce_succeeds() {
    let jwt_token = "ewogICJhbGciOiAiYWxnb3JpdGhtIiwKICAidHlwIjogIlNESldUIgp9.eyJpYXQiOjE2OTkyNzAyNjYsImV4cCI6MTc2MjM0MjI2NiwibmJmIjoxNjk5MjcwMjIxLCJpc3MiOiJkaWQ6aXNzdWVyOnRlc3QiLCJzdWIiOiJkaWQ6aG9sZGVyOnRlc3QiLCJqdGkiOiI5YTQxNGE2MC05ZTZiLTQ3NTctODAxMS05YWE4NzBlZjQ3ODgiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnRlc3Rjb250ZXh0LmNvbS92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVHlwZTEiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbIkhabk1zenlDZERkTDFqSG5Wck5aZHRmdjhiSlR0Z25wa1NfbEl6SDI0eTgiLCJCT1QzNU1ZSnc1bzlLaTdEMFdxSlh2LXdKMDFkcXotbFF0T3Fod01pdnFvIl19LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOnN0YXR1czppZCIsInR5cGUiOiJUWVBFIiwic3RhdHVzUHVycG9zZSI6IlBVUlBPU0UiLCJGaWVsZDEiOiJWYWwxIn19LCJfc2RfYWxnIjoic2hhLTI1NiJ9";
    let key_name = "WyJNVEl6WVdKaiIsIm5hbWUiLCJKb2huIl0";
    let token = format!("{jwt_token}.QUJD~{key_name}~");
    let key_id = "key-id";
    let key_alg = "ES256";
    let holder_did: DidValue = "did:holder:test".to_string().try_into().unwrap();

    let mut signer = MockSignatureProvider::default();
    signer
        .expect_jose_alg()
        .returning(|| Some(key_alg.to_string()));
    signer
        .expect_get_key_algorithm()
        .returning(|| Ok(KeyAlgorithmType::Ecdsa));
    signer
        .expect_get_key_id()
        .returning(|| Some(key_id.to_string()));

    // We only expect 1 signature for the outer envelope
    signer.expect_sign().once().returning(|_| Ok(vec![0; 32]));

    let mut crypto = MockCryptoProvider::default();
    crypto
        .expect_get_hasher()
        .with(eq("sha-256"))
        .returning(|_| Ok(Arc::new(SHA256 {})));

    let sd_formatter = SdjwtPresentationFormatter::new(
        Arc::new(MockHttpClient::new()),
        Arc::new(crypto),
        Arc::new(MockKeyAlgorithmProvider::default()),
    );

    let presentation = sd_formatter
        .format_presentation(
            vec![CredentialToPresent {
                credential_token: token.clone(),
                credential_format: FormatType::SdJwt,
                lvvc_credential_token: None,
            }],
            Box::new(signer),
            &Some(holder_did),
            FormatPresentationCtx {
                nonce: None,
                audience: None,
                mdoc_session_transcript: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(presentation.oidc_format, "jwt_vp_json");
}

#[tokio::test]
async fn test_extract_presentation() {
    let jwt_token = "eyJhbGciOiJhbGdvcml0aG0iLCJ0eXAiOiJTREpXVCJ9.ewogICJpYXQiOiAxNjk5MzUxODQxLAogICJleHAiOiAxNjk5MzUyMTQxLAogICJuYmYiOiAxNjk5MzUxNzk2LAogICJpc3MiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJzdWIiOiAiZGlkOmhvbGRlcjoxMjMiLAogICJqdGkiOiAiYjRjYzQ5ZDUtOGQwZS00ODFlLWIxZWItOGU0ZThiOTY5NmIxIiwKICAidnAiOiB7CiAgICAiQGNvbnRleHQiOiBbCiAgICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICAgIF0sCiAgICAidHlwZSI6IFsKICAgICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgICBdLAogICAgIl9zZF9qd3QiOiBbCiAgICAgICJleUpoYkdjaU9pSmhiR2R2Y21sMGFHMGlMQ0owZVhBaU9pSlRSRXBYVkNKOS5leUpwWVhRaU9qRTJPVGt5TnpBeU5qWXNJbVY0Y0NJNk1UYzJNak0wTWpJMk5pd2libUptSWpveE5qazVNamN3TWpJeExDSnBjM01pT2lKSmMzTjFaWElnUkVsRUlpd2ljM1ZpSWpvaWFHOXNaR1Z5WDJScFpDSXNJbXAwYVNJNklqbGhOREUwWVRZd0xUbGxObUl0TkRjMU55MDRNREV4TFRsaFlUZzNNR1ZtTkRjNE9DSXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMM1l4SWl3aVEyOXVkR1Y0ZERFaVhTd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSWxSNWNHVXhJbDBzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lsOXpaQ0k2V3lKWlYwcHFUVlJKZWlJc0lsbFhTbXBOVkVsNklsMTlMQ0pqY21Wa1pXNTBhV0ZzVTNSaGRIVnpJanA3SW1sa0lqb2lVMVJCVkZWVFgwbEVJaXdpZEhsd1pTSTZJbFJaVUVVaUxDSnpkR0YwZFhOUWRYSndiM05sSWpvaVVGVlNVRTlUUlNJc0lrWnBaV3hrTVNJNklsWmhiREVpZlgwc0lsOXpaRjloYkdjaU9pSnphR0V0TWpVMkluMC5RVUpEfld5Sk5WRWw2V1ZkS2FpSXNJbTVoYldVaUxDSktiMmh1SWwwfld5Sk5WRWw2V1ZkS2FpSXNJbUZuWlNJc0lqUXlJbDAiCiAgICBdCiAgfQp9";
    let presentation_token = format!("{jwt_token}.QUJD");

    let crypto = MockCryptoProvider::default();

    let sd_formatter = SdjwtPresentationFormatter::new(
        Arc::new(MockHttpClient::new()),
        Arc::new(crypto),
        Arc::new(MockKeyAlgorithmProvider::new()),
    );

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
