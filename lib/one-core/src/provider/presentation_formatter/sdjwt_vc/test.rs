use std::str::FromStr;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use mockall::predicate::eq;
use one_crypto::MockCryptoProvider;
use one_crypto::hasher::sha256::SHA256;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::OffsetDateTime;

use super::SdjwtVCPresentationFormatter;
use crate::config::core_config::{KeyAlgorithmType, VerificationProtocolType};
use crate::provider::credential_formatter::model::{
    IdentifierDetails, MockTokenVerifier, PublicKeySource,
};
use crate::provider::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::model::ExtractPresentationCtx;
use crate::service::certificate::validator::MockCertificateValidator;

const ISSUER_URL: &str = "https://example.com/.well-known/jwt-vc-issuer/issuer";
const ISSUER_URL_RESPONSE: &str = r#"{
                           "issuer":"https://example.com/issuer",
                           "jwks":{
                              "keys":[
                                 {
                                    "kid":"doc-signer-05-25-2022",
                                    "e":"AQAB",
                                    "n":"nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfGHrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyklBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70pRM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKveqXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ",
                                    "kty":"RSA"
                                 }
                              ]
                           }
                        }"#;

#[tokio::test]
async fn test_extract_presentation() {
    // https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-4.2
    let jwt_token = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJraWQiOiAiZG9jLXNpZ25lci0wNS0yNS0yMDIyIn0.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CVkJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNONndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiamRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ";
    let token_signature =
        "2CyX0v3AAFG9y-A_Z46uz9hHsNbr0yWTbDQaajLCrsxo-JxVh4a9dAMFVYZ8GFG2wgj2jKnA42wSgv7xVM64PA";
    let disclosures = "~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImlzX292ZXJfNjUiLCB0cnVlXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE3MzMyMzAxNDAsICJzZF9oYXNoIjogIkhWVjBCcG5FTHlHTnRVVFlCLU5nWHhmN2pvTjZBekprYVdEOUVkNVo1VjgifQ.FJLPPlBB2wOWEYLLtwd7WYlaTpIz0ALlRuskPi0fSYFDEn25gGkXSSJsQxjhryxqN4aLbwMRRfcvDdk1A_eLHQ";
    let presentation_token = format!("{jwt_token}.{token_signature}.{disclosures}");

    let expected_holder_did = DidValue::from_str("did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCJ5IjoiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9").unwrap();
    let expected_issuer_did = "did:jwk:eyJrdHkiOiJSU0EiLCJraWQiOiJkb2Mtc2lnbmVyLTA1LTI1LTIwMjIiLCJlIjoiQVFBQiIsIm4iOiJuajNZSndzTFVGbDlCbXBBYmtPc3dDTlZ4MTdFaDl3TU8tX0FSZVp3QnFmYVdGY2ZHSHJaWHNJVjJWTUNOVk5VOFRwYjRvYlVhU1hjUmNRLVZNc2ZRUEptOUl6Z3RSZEFZOE5OOFhiN1BFY1l5a2xCanZUdHVQYnB6SWFxeWlVZXB6VVhOREZ1QU9Pa3JJb2wzV21mbFBVVWdNS1VMQk4wRVVkMWZwT0Q3MHBSTTBybHBfZ2dfV05VS29XMVYtM2tlWVVKb1hIOU56dEVEbV9EMk1RWGo5ZUdPSko4eVBnR0w4UEFaTUxlMlI3amI5VHhPQ1BERUQ3dFlfVFU0bkZQbHhwdHc1OUE0Mm1sZEVtVmlYc0tRdDYwczFTTGJvYXp4Rkt2ZXFYQ19qcExVdDIyT0M2R1VHNjNwLVJFdy1aT3Izcjg0NXo1MHdNdXppZlFyTUk5YlEifQ";

    let mut crypto = MockCryptoProvider::default();

    crypto
        .expect_get_hasher()
        .once()
        .with(eq("sha-256"))
        .returning(|_| Ok(Arc::new(SHA256 {})));

    let mut http_client = MockHttpClient::new();
    http_client
        .expect_get()
        .once()
        .with(eq(ISSUER_URL))
        .returning(|url| {
            let mut inner_client = MockHttpClient::new();
            inner_client.expect_send().once().returning(|_, _, _, _| {
                Ok(Response {
                    body: ISSUER_URL_RESPONSE.as_bytes().to_vec(),
                    headers: Default::default(),
                    status: StatusCode(200),
                    request: Request {
                        body: None,
                        headers: Default::default(),
                        method: Method::Get,
                        url: ISSUER_URL.to_string(),
                    },
                })
            });

            RequestBuilder::new(Arc::new(inner_client), Method::Get, url)
        });

    let sd_formatter = SdjwtVCPresentationFormatter::new(
        Arc::new(http_client),
        Arc::new(crypto),
        Arc::new(MockCertificateValidator::new()),
        false,
    );

    let mut verify_mock = MockTokenVerifier::new();
    verify_mock
        .expect_verify()
        .withf(
            move |params, algorithm, token, signature| {
                assert!(matches!(params, PublicKeySource::Did {did, ..} if did.to_string() == expected_issuer_did));
                assert_eq!(KeyAlgorithmType::Eddsa, *algorithm);
                assert_eq!(jwt_token.as_bytes(), token);
                assert_eq!(
                    Base64UrlSafeNoPadding::decode_to_vec(token_signature, None).unwrap(),
                    signature
                );
                true
            },
        )
        .return_once(|_,  _, _, _| Ok(()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .with(eq("ES256"))
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

    let result = sd_formatter
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

    assert_eq!(presentation.expires_at, None,);
    assert_eq!(
        presentation.issued_at,
        Some(OffsetDateTime::from_unix_timestamp(1733230140).unwrap())
    );
    assert_eq!(presentation.credentials.len(), 1);
    assert_eq!(
        presentation.issuer,
        Some(IdentifierDetails::Did(expected_holder_did))
    );
    assert_eq!(presentation.nonce, Some("1234567890".to_string()));
}
