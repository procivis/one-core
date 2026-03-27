use std::collections::HashMap;
use std::sync::Arc;

use maplit::hashmap;
use similar_asserts::assert_eq;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::proto::certificate_validator::CertificateValidatorImpl;
use crate::proto::clock::MockClock;
use crate::proto::http_client::{Method, MockHttpClient, Request, Response, StatusCode};
use crate::provider::caching_loader::android_attestation_crl::{
    AndroidAttestationCrlCache, AndroidAttestationCrlResolver,
};
use crate::provider::caching_loader::etsi_lote::EtsiLoteCache;
use crate::provider::caching_loader::x509_crl::{X509CrlCache, X509CrlResolver};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::trust_list_subscriber::TrustListSubscriber;
use crate::provider::trust_list_subscriber::error::TrustListSubscriberError;
use crate::provider::trust_list_subscriber::etsi_lote::resolver::EtsiLoteResolver;
use crate::provider::trust_list_subscriber::etsi_lote::{EtsiLoteSubscriber, LoteContentType};
use crate::service::test_utilities::{dummy_identifier, dummy_key};
use crate::util::test_utilities::mock_http_get_request;

const SPRIND_LOTE_JWS: &str = "eyJhbGciOiJFUzI1NiIsImlhdCI6MTc3MjQ5MzA2NywieDVjIjpbIk1JSUNGekNDQWIyZ0F3SUJBZ0lVUUF4ZXY4eDJCbzRZNWhWbkdoT285VlNkQWNJd0NnWUlLb1pJemowRUF3SXdZVEVMTUFrR0ExVUVCaE1DUkVVeER6QU5CZ05WQkFnTUJrSmxjbXhwYmpFUE1BMEdBMVVFQnd3R1FtVnliR2x1TVJRd0VnWURWUVFLREF0VWNuVnpkQ0JNYVhOMGN6RWFNQmdHQTFVRUF3d1JWSEoxYzNRZ1RHbHpkQ0JUYVdkdVpYSXdIaGNOTWpZd01qQTJNVFF5TWpFNVdoY05Nell3TWpBME1UUXlNakU1V2pCaE1Rc3dDUVlEVlFRR0V3SkVSVEVQTUEwR0ExVUVDQXdHUW1WeWJHbHVNUTh3RFFZRFZRUUhEQVpDWlhKc2FXNHhGREFTQmdOVkJBb01DMVJ5ZFhOMElFeHBjM1J6TVJvd0dBWURWUVFEREJGVWNuVnpkQ0JNYVhOMElGTnBaMjVsY2pCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQk5GRHc5a0VaeHp3ZWxsVzRiNmlUYXhxYThlSEJaTUVzTzg0Q1Y1T0piZEI5ZG1OaUdiNTM5dnh3V2JpbTZ3WHorYzNuNUNVbnN1Z2VvbStubjBHQWxTalV6QlJNQjBHQTFVZERnUVdCQlMxdVhqODF4VHovUHhYWWpsaEtrWkhzNmREVVRBZkJnTlZIU01FR0RBV2dCUzF1WGo4MXhUei9QeFhZamxoS2taSHM2ZERVVEFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJUUNFSnAvWlJ3eFBlZTJFUUpIZFZXQ3RiUjdiWFBwYzJIcjFsdEorL1U0SnNRSWdRWnFJWkFCMzhtNzl6VHhWR2lYUmF1ZzJTaml1NlAxRGJWYldSZVMwazBjPSJdfQ.eyJMaXN0QW5kU2NoZW1lSW5mb3JtYXRpb24iOnsiTG9URVZlcnNpb25JZGVudGlmaWVyIjoxLCJMb1RFU2VxdWVuY2VOdW1iZXIiOjEsIkxvVEVUeXBlIjoiaHR0cDovL3VyaS5ldHNpLm9yZy8xOTYwMi9Mb1RFVHlwZS9SZWdpc3RyYXJzQW5kUmVnaXN0ZXJzTGlzdFByb3ZpZGVyc0xpc3QiLCJTY2hlbWVJbmZvcm1hdGlvblVSSSI6W3sibGFuZyI6ImRlLURFIiwidXJpVmFsdWUiOiJodHRwczovL2V4YW1wbGUuY29tL3ByZXZpb3VzLWxpc3RzIn1dLCJTdGF0dXNEZXRlcm1pbmF0aW9uQXBwcm9hY2giOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1JlZ2lzdHJhcnNBbmRSZWdpc3RlcnNMaXN0UHJvdmlkZXJzTGlzdC9TdGF0dXNEZXRuL0VVLiIsIlNjaGVtZVR5cGVDb21tdW5pdHlSdWxlcyI6W3sibGFuZyI6ImRlLURFIiwidXJpVmFsdWUiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1JlZ2lzdHJhcnNBbmRSZWdpc3RlcnNMaXN0UHJvdmlkZXJzTGlzdC9zY2hlbWVydWxlcy9FVSJ9XSwiU2NoZW1lVGVycml0b3J5IjoiRVUiLCJOZXh0VXBkYXRlIjoiMjAyNi0wMy0wM1QyMzoxMTowNy4xMzNaIiwiU2NoZW1lT3BlcmF0b3JOYW1lIjpbeyJsYW5nIjoiZGUtREUiLCJ2YWx1ZSI6IlNQUklORCBHbWJIIn1dLCJMaXN0SXNzdWVEYXRlVGltZSI6IjIwMjYtMDMtMDJUMjM6MTE6MDcuMTMzWiJ9LCJUcnVzdGVkRW50aXRpZXNMaXN0IjpbeyJUcnVzdGVkRW50aXR5SW5mb3JtYXRpb24iOnsiVEVJbmZvcm1hdGlvblVSSSI6W3sibGFuZyI6ImRlLURFIiwidXJpVmFsdWUiOiJodHRwczovL3d3dy5zcHJpbmQub3JnIn1dLCJURU5hbWUiOlt7ImxhbmciOiJkZS1ERSIsInZhbHVlIjoiU1BSSU5EIEdtYkgifV0sIlRFQWRkcmVzcyI6eyJURUVsZWN0cm9uaWNBZGRyZXNzIjpbeyJsYW5nIjoiZGUtREUiLCJ1cmlWYWx1ZSI6Imh0dHBzOi8vc3ByaW5kLm9yZy9jb250YWN0In1dLCJURVBvc3RhbEFkZHJlc3MiOlt7IkNvdW50cnkiOiJERSIsImxhbmciOiJkZSIsIkxvY2FsaXR5IjoiTGVpcHppZyIsIlBvc3RhbENvZGUiOiIwNDEwMyIsIlN0cmVldEFkZHJlc3MiOiJMYWdlcmhvZnN0cmHDn2UgNCJ9XX19LCJUcnVzdGVkRW50aXR5U2VydmljZXMiOlt7IlNlcnZpY2VJbmZvcm1hdGlvbiI6eyJTZXJ2aWNlVHlwZUlkZW50aWZpZXIiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1N2Y1R5cGUvUmVnaXN0cmFyc0FuZFJlZ2lzdGVyc0xpc3RTb2x1dGlvbi9Jc3N1YW5jZSIsIlNlcnZpY2VOYW1lIjpbeyJsYW5nIjoiZGUtREUiLCJ2YWx1ZSI6IkFjY2VzcyBDZXJ0aWZpY2F0ZSBBdXNzdGVsbHVuZ3NkaWVuc3QgZGVyIFNQUklORCBHbWJIIn1dLCJTZXJ2aWNlRGlnaXRhbElkZW50aXR5Ijp7Ilg1MDlDZXJ0aWZpY2F0ZXMiOlt7InZhbCI6Ik1JSUNMekNDQWRTZ0F3SUJBZ0lVSHlSakU0NjZZQTd0Yzg4OGswM091MlFvZEY0d0NnWUlLb1pJemowRUF3SXdLREVMTUFrR0ExVUVCaE1DUkVVeEdUQVhCZ05WQkFNTUVFZGxjbTFoYmlCU1pXZHBjM1J5WVhJd0hoY05Nall3TVRFMk1URXhOVFUwV2hjTk1qZ3dNVEUyTVRFeE5UVTBXakFvTVFzd0NRWURWUVFHRXdKRVJURVpNQmNHQTFVRUF3d1FSMlZ5YldGdUlGSmxaMmx6ZEhKaGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJNZWZZMlg0aXhmUmtXRXZwOWdyRjJpMjF6NlBLWnNyOHp6QmFKLytHbm90Q2VIMmNKNkd0TGh4WGhIZkpqckVUc01OSUdoVmFKb0hvSGNaVEJISnJmeWpnZHN3Z2Rnd0hRWURWUjBPQkJZRUZLbkNvOW92YmF4VTdzNjVUdWdzeVN3QWc0QXpNQjhHQTFVZEl3UVlNQmFBRktuQ285b3ZiYXhVN3M2NVR1Z3N5U3dBZzRBek1CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Db0dBMVVkRWdRak1DR0dIMmgwZEhCek9pOHZjMkZ1WkdKdmVDNWxkV1JwTFhkaGJHeGxkQzV2Y21jd1JnWURWUjBmQkQ4d1BUQTdvRG1nTjRZMWFIUjBjSE02THk5ellXNWtZbTk0TG1WMVpHa3RkMkZzYkdWMExtOXlaeTl6ZEdGMGRYTXRiV0Z1WVdkbGJXVnVkQzlqY213d0NnWUlLb1pJemowRUF3SURTUUF3UmdJaEFJWTdFUnBSckRSbDBscjVINXV4ako4M0pSNHF1YTJzZlBLeFgrcGw0UXcrQWlFQTJxTDZMWFZPUkEycjJWWmpTRWtuZmNpd0lHN2xhQTEya2pueUdBRDNWL0E9In1dfX19LHsiU2VydmljZUluZm9ybWF0aW9uIjp7IlNlcnZpY2VOYW1lIjpbeyJsYW5nIjoiZGUtREUiLCJ2YWx1ZSI6IkFjY2VzcyBDZXJ0aWZpY2F0ZS1SZXZva2F0aW9uc2RpZW5zdCBkZXIgU1BSSU5EIEdtYkgifV0sIlNlcnZpY2VUeXBlSWRlbnRpZmllciI6Imh0dHA6Ly91cmkuZXRzaS5vcmcvMTk2MDIvU3ZjVHlwZS9SZWdpc3RyYXJzQW5kUmVnaXN0ZXJzTGlzdFNvbHV0aW9uL1Jldm9jYXRpb24iLCJTZXJ2aWNlRGlnaXRhbElkZW50aXR5Ijp7Ilg1MDlDZXJ0aWZpY2F0ZXMiOlt7InZhbCI6Ik1JSUNMekNDQWRTZ0F3SUJBZ0lVSHlSakU0NjZZQTd0Yzg4OGswM091MlFvZEY0d0NnWUlLb1pJemowRUF3SXdLREVMTUFrR0ExVUVCaE1DUkVVeEdUQVhCZ05WQkFNTUVFZGxjbTFoYmlCU1pXZHBjM1J5WVhJd0hoY05Nall3TVRFMk1URXhOVFUwV2hjTk1qZ3dNVEUyTVRFeE5UVTBXakFvTVFzd0NRWURWUVFHRXdKRVJURVpNQmNHQTFVRUF3d1FSMlZ5YldGdUlGSmxaMmx6ZEhKaGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJNZWZZMlg0aXhmUmtXRXZwOWdyRjJpMjF6NlBLWnNyOHp6QmFKLytHbm90Q2VIMmNKNkd0TGh4WGhIZkpqckVUc01OSUdoVmFKb0hvSGNaVEJISnJmeWpnZHN3Z2Rnd0hRWURWUjBPQkJZRUZLbkNvOW92YmF4VTdzNjVUdWdzeVN3QWc0QXpNQjhHQTFVZEl3UVlNQmFBRktuQ285b3ZiYXhVN3M2NVR1Z3N5U3dBZzRBek1CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Db0dBMVVkRWdRak1DR0dIMmgwZEhCek9pOHZjMkZ1WkdKdmVDNWxkV1JwTFhkaGJHeGxkQzV2Y21jd1JnWURWUjBmQkQ4d1BUQTdvRG1nTjRZMWFIUjBjSE02THk5ellXNWtZbTk0TG1WMVpHa3RkMkZzYkdWMExtOXlaeTl6ZEdGMGRYTXRiV0Z1WVdkbGJXVnVkQzlqY213d0NnWUlLb1pJemowRUF3SURTUUF3UmdJaEFJWTdFUnBSckRSbDBscjVINXV4ako4M0pSNHF1YTJzZlBLeFgrcGw0UXcrQWlFQTJxTDZMWFZPUkEycjJWWmpTRWtuZmNpd0lHN2xhQTEya2pueUdBRDNWL0E9In1dfX19XX1dfQ.IzpFGp0TchXMvizip3HffMnmP40WkNsvLRBRUGsu1pKAd5PeMs2klbuEWb22FpQ1UyTUvRobi2xyHewySS6mpA";

const UNTRUSTED_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICADCCAYagAwIBAgIRANMI7LNjmBkq6LyFy5KhIoUwCgYIKoZIzj0EAwIwPzES
MBAGA1UEDAwJU3Ryb25nQm94MSkwJwYDVQQFEyAxNjY4ZjI4M2M2ZGQ3OTgyNTM1
YjViNWJiYWU1ODYxZTAeFw0yNDA5MTIyMTQ3MjZaFw0zNDA5MTAyMTQ3MjZaMD8x
EjAQBgNVBAwMCVN0cm9uZ0JveDEpMCcGA1UEBRMgYTVjMTM2YzdkOTM1NjI3ZDVm
ZWUzMjRjY2QzZmViMGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQFPGMUj07/
qx5I9nPl0iivOq5gFTJ+QnflKyMYv7rrzaCe04ydj54NXXWgtaBOdUfiuZPUtqv7
luDQT6l7GAENo2MwYTAdBgNVHQ4EFgQU1KgfEPcAZG7u233No9Jc3katBEowHwYD
VR0jBBgwFoAURtwIzTltMRWBmDiz54wXB2lgqogwDwYDVR0TAQH/BAUwAwEB/zAO
BgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDaAAwZQIxANFoE7Ezv6jFOjiyoFT3
/sO7yFaPcwEBF+v6ff6eF0y3ySZArOiROOiji0rUbc5mSwIwC4O/UTP7WvksjGe1
IZvI/gYu+lOExQYHZebjfhtcl545ckTRmtGMKmBpoJr+8Vdr
-----END CERTIFICATE-----
"#;
const TRUSTED_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICLzCCAdSgAwIBAgIUHyRjE466YA7tc888k03Ou2QodF4wCgYIKoZIzj0EAwIw
KDELMAkGA1UEBhMCREUxGTAXBgNVBAMMEEdlcm1hbiBSZWdpc3RyYXIwHhcNMjYw
MTE2MTExNTU0WhcNMjgwMTE2MTExNTU0WjAoMQswCQYDVQQGEwJERTEZMBcGA1UE
AwwQR2VybWFuIFJlZ2lzdHJhcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMef
Y2X4ixfRkWEvp9grF2i21z6PKZsr8zzBaJ/+GnotCeH2cJ6GtLhxXhHfJjrETsMN
IGhVaJoHoHcZTBHJrfyjgdswgdgwHQYDVR0OBBYEFKnCo9ovbaxU7s65TugsySwA
g4AzMB8GA1UdIwQYMBaAFKnCo9ovbaxU7s65TugsySwAg4AzMBIGA1UdEwEB/wQI
MAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMCoGA1UdEgQjMCGGH2h0dHBzOi8vc2Fu
ZGJveC5ldWRpLXdhbGxldC5vcmcwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cHM6Ly9z
YW5kYm94LmV1ZGktd2FsbGV0Lm9yZy9zdGF0dXMtbWFuYWdlbWVudC9jcmwwCgYI
KoZIzj0EAwIDSQAwRgIhAIY7ERpRrDRl0lr5H5uxjJ83JR4qua2sfPKxX+pl4Qw+
AiEA2qL6LXVORA2r2VZjSEknfciwIG7laA12kjnyGAD3V/A=
-----END CERTIFICATE-----
"#;

const TRUSTED_FINGERPRINT: &str =
    "7421221cb1da97b3edb4ad2ccb4d00cbdced1e1316bf6768e677218cdb246d3e";

#[tokio::test]
async fn validate_subscription_success() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(time, &reference);

    let result = subscriber
        .validate_subscription(
            &reference,
            Some(TrustListRoleEnum::NationalRegistryRegistrar),
        )
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn validate_subscription_unknown_role() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(time, &reference);

    let result = subscriber.validate_subscription(&reference, None).await;
    assert!(matches!(
        result,
        Err(TrustListSubscriberError::UnknownTrustListRole)
    ));
}

#[tokio::test]
async fn resolve_unsupported_identifier_type() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(time, &reference);

    let result = subscriber
        .resolve_entries(&reference, &[dummy_identifier()])
        .await;
    assert!(matches!(
        result,
        Err(TrustListSubscriberError::UnsupportedIdentifierType(_))
    ));
}

#[tokio::test]
async fn validate_subscription_expired() {
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(crate::clock::now_utc(), &reference);

    let result = subscriber
        .validate_subscription(&reference, None)
        .await
        .err()
        .unwrap();
    assert_eq!(result.error_code(), ErrorCode::BR_0354);
}

#[tokio::test]
async fn resolve_untrusted_identifier() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(time, &reference);

    let identifier_id = Uuid::new_v4().into();
    let now = crate::clock::now_utc();
    let identifier = Identifier {
        id: identifier_id,
        created_date: now,
        last_modified: now,
        name: "".to_string(),
        r#type: IdentifierType::Certificate,
        is_remote: false,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: None,
        did: None,
        key: None,
        certificates: Some(vec![Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation_id: None,
            created_date: now,
            last_modified: now,
            expiry_date: now,
            name: "".to_string(),
            chain: UNTRUSTED_CERT.to_string(),
            fingerprint: "unknown fingerprint".to_string(),
            state: CertificateState::Active,
            key: Some(dummy_key()),
        }]),
    };

    let result = subscriber
        .resolve_entries(&reference, &[identifier])
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn resolve_trusted_identifier() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(time, &reference);

    let identifier_id = Uuid::new_v4().into();
    let now = crate::clock::now_utc();
    let identifier = Identifier {
        id: identifier_id,
        created_date: now,
        last_modified: now,
        name: "".to_string(),
        r#type: IdentifierType::Certificate,
        is_remote: false,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: None,
        did: None,
        key: None,
        certificates: Some(vec![Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation_id: None,
            created_date: now,
            last_modified: now,
            expiry_date: now,
            name: "".to_string(),
            chain: TRUSTED_CERT.to_string(),
            fingerprint: TRUSTED_FINGERPRINT.to_string(),
            state: CertificateState::Active,
            key: Some(dummy_key()),
        }]),
    };

    let result = subscriber
        .resolve_entries(&reference, &[identifier])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert!(result.contains_key(&identifier_id));
}

fn setup_subscriber(time: OffsetDateTime, reference: &Url) -> EtsiLoteSubscriber {
    let mut clock = MockClock::new();
    // test vector still valid
    clock.expect_now_utc().returning(move || time);
    let clock = Arc::new(clock);
    let mut client = MockHttpClient::new();
    mock_http_get_request(
        &mut client,
        reference.to_string(),
        Response {
            body: SPRIND_LOTE_JWS.as_bytes().to_vec(),
            headers: hashmap! { "Content-Type".to_string() => "application/jwt".to_string() },
            status: StatusCode(200),
            request: Request {
                body: None,
                headers: Default::default(),
                method: Method::Get,
                url: reference.to_string(),
                timeout: None,
            },
        },
    );
    let client = Arc::new(client);
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(|r#type| match r#type {
            KeyAlgorithmType::Ecdsa => Some(Arc::new(Ecdsa)),
            _ => None,
        });
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .returning(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa))));
    let key_algorithm_provider = Arc::new(key_algorithm_provider);
    let cache_storage = Arc::new(InMemoryStorage::new(HashMap::new()));

    let certificate_validator = CertificateValidatorImpl::new(
        key_algorithm_provider.clone(),
        Arc::new(X509CrlCache::new(
            Arc::new(X509CrlResolver::new(Some(client.clone()))),
            cache_storage.clone(),
            100,
            Duration::days(1),
            Duration::days(1),
        )),
        clock.clone(),
        Duration::seconds(0),
        Arc::new(AndroidAttestationCrlCache::new(
            Arc::new(AndroidAttestationCrlResolver::new(client.clone())),
            cache_storage.clone(),
            100,
            Duration::days(1),
            Duration::days(1),
        )),
    );
    let resolver = EtsiLoteResolver::new(
        clock,
        client,
        Arc::new(MockDidMethodProvider::new()),
        key_algorithm_provider,
        Arc::new(certificate_validator),
        LoteContentType::Jwt,
        Duration::seconds(0),
    );
    let cache = EtsiLoteCache::new(
        Arc::new(resolver),
        cache_storage,
        100,
        Duration::seconds(60),
        Duration::seconds(60),
    );

    EtsiLoteSubscriber::new(cache)
}
