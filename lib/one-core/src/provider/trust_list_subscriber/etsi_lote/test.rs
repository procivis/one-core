use std::collections::HashMap;
use std::sync::Arc;

use ct_codecs::Decoder as _;
use maplit::hashmap;
use mockall::predicate::{always, eq, ne};
use similar_asserts::assert_eq;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use crate::clock::run_with_mocked_time_async;
use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::identifier::{Identifier, IdentifierData, IdentifierState};
use crate::model::relation::RelatedVec;
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::proto::certificate_validator::{MockCertificateValidator, ParsedCertificate};
use crate::proto::http_client::{Method, MockHttpClient, Request, Response, StatusCode};
use crate::proto::xades::{MockXAdESProto, XAdES};
use crate::provider::caching_loader::etsi_lote::EtsiLoteCache;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::trust_list_subscriber::TrustListSubscriber;
use crate::provider::trust_list_subscriber::error::TrustListSubscriberError;
use crate::provider::trust_list_subscriber::etsi_lote::resolver::EtsiLoteResolver;
use crate::provider::trust_list_subscriber::etsi_lote::{EtsiLoteSubscriber, LoteContentType};
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::test_utilities::{dummy_identifier, dummy_key, dummy_organisation};
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

    let subscriber = setup_subscriber(&reference);

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .validate_subscription(
                &reference,
                Some(TrustListRoleEnum::NationalRegistryRegistrar),
            )
            .await
    })
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn validate_subscription_roleless_when_no_role_derivable() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(&reference);

    // A LoTE with no derivable role is a roleless subscription; the role is then
    // re-derived per entity at resolve time.
    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .validate_subscription(&reference, None)
            .await
            .unwrap()
    })
    .await;

    assert_eq!(result.role, None);
}

#[tokio::test]
async fn resolve_unsupported_identifier_type() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(&reference);

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .resolve_entries(&reference, &[dummy_identifier()])
            .await
    })
    .await;

    assert!(matches!(
        result,
        Err(TrustListSubscriberError::UnsupportedIdentifierType(_))
    ));
}

#[tokio::test]
async fn validate_subscription_expired() {
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(&reference);

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

    let subscriber = setup_subscriber(&reference);

    let identifier_id = Uuid::new_v4().into();
    let now = crate::clock::now_utc();
    let identifier = Identifier {
        id: identifier_id,
        created_date: now,
        last_modified: now,
        name: "".to_string(),
        data: IdentifierData::Certificate(RelatedVec::from(vec![Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation: dummy_organisation(None).into(),
            created_date: now,
            last_modified: now,
            deleted_at: None,
            expiry_date: now,
            name: "".to_string(),
            chain: UNTRUSTED_CERT.to_string(),
            fingerprint: "unknown fingerprint".to_string(),
            state: CertificateState::Active,
            roles: vec![],
            key: Some(dummy_key().into()),
        }])),
        is_remote: false,
        state: IdentifierState::Active,
        deleted_at: None,
        autogenerated: false,
        organisation: dummy_organisation(None).into(),
        trust_information: Default::default(),
        logo: None,
        translations: Default::default(),
    };

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .resolve_entries(&reference, &[identifier])
            .await
            .unwrap()
    })
    .await;

    assert_eq!(result, HashMap::new());
}

#[tokio::test]
async fn resolve_trusted_identifier() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(&reference);

    let identifier_id = Uuid::new_v4().into();
    let now = crate::clock::now_utc();
    let identifier = Identifier {
        id: identifier_id,
        created_date: now,
        last_modified: now,
        name: "".to_string(),
        data: IdentifierData::Certificate(RelatedVec::from(vec![Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation: dummy_organisation(None).into(),
            created_date: now,
            last_modified: now,
            deleted_at: None,
            expiry_date: now,
            name: "".to_string(),
            chain: TRUSTED_CERT.to_string(),
            fingerprint: TRUSTED_FINGERPRINT.to_string(),
            state: CertificateState::Active,
            roles: vec![],
            key: Some(dummy_key().into()),
        }])),
        is_remote: false,
        state: IdentifierState::Active,
        deleted_at: None,
        autogenerated: false,
        organisation: dummy_organisation(None).into(),
        trust_information: Default::default(),
        logo: None,
        translations: Default::default(),
    };

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .resolve_entries(&reference, &[identifier])
            .await
            .unwrap()
    })
    .await;

    assert_eq!(result.len(), 1);
    assert!(result.contains_key(&identifier_id));
}

fn setup_subscriber(reference: &Url) -> EtsiLoteSubscriber {
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
        .with(eq(KeyAlgorithmType::Ecdsa))
        .returning(|_| Ok(Arc::new(Ecdsa)));
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .returning(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa))));
    let key_algorithm_provider = Arc::new(key_algorithm_provider);
    let cache_storage = Arc::new(InMemoryStorage::new(HashMap::new()));

    let mut certificate_validator = MockCertificateValidator::new();
    let certificate = {
        let mut handle = MockSignaturePublicKeyHandle::new();
        handle.expect_verify().returning(|_, _| Ok(()));
        ParsedCertificate {
            attributes: CertificateX509AttributesDTO {
                serial_number: "1F:24:63:13:8E:BA:60:0E:ED:73:CF:3C:93:4D:CE:BB:64:28:74:5E"
                    .to_string(),
                not_before: datetime!(2025-03-01 00:00 UTC),
                not_after: datetime!(2028-03-01 00:00 UTC),
                issuer: "CN=German Registrar, C=DE".to_string(),
                subject: "CN=German Registrar, C=DE".to_string(),
                fingerprint: TRUSTED_FINGERPRINT.to_string(),
                extensions: vec![],
            },
            subject_common_name: None,
            subject_key_identifier: None,
            public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                handle,
            ))),
        }
    };
    certificate_validator
        .expect_parse_pem_chain()
        .with(eq(TRUSTED_CERT), always())
        .returning({
            let certificate = certificate.clone();
            move |_, _| Ok(certificate.clone())
        });
    certificate_validator
        .expect_parse_pem_chain()
        .with(ne(TRUSTED_CERT), always())
        .returning({
            let mut certificate = certificate.clone();
            certificate.attributes.fingerprint = "unknown fingerprint".to_string();
            move |_, _| Ok(certificate.clone())
        });
    certificate_validator
        .expect_validate_chain_against_ca_chain()
        .returning(move |_, _, _, _| Ok(certificate.clone()));

    let certificate_validator = Arc::new(certificate_validator);
    let resolver = EtsiLoteResolver::new(
        client,
        Arc::new(MockDidMethodProvider::new()),
        key_algorithm_provider.clone(),
        certificate_validator.clone(),
        Arc::new(MockXAdESProto::new()),
        LoteContentType::Jwt,
        Duration::seconds(0),
        None,
    );
    let cache = EtsiLoteCache::new(
        Arc::new(resolver),
        cache_storage,
        100,
        Duration::seconds(60),
        Duration::seconds(60),
    );

    EtsiLoteSubscriber::new(cache, certificate_validator, key_algorithm_provider)
}

// XAdES-signed XML LoTE containing the same TRUSTED_CERT entity.
// Generated with the P-256 test key pair from proto::xades::test using
// generate_xml_lote_test_vector (run with --ignored --nocapture).
const LOTE_XML: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<ListOfTrustedEntities xmlns="http://uri.etsi.org/019602/v1#" LOTETag="http://uri.etsi.org/019602/tag#"><ListAndSchemeInformation><LoTEVersionIdentifier>1</LoTEVersionIdentifier><LoTESequenceNumber>1</LoTESequenceNumber><LoTEType>http://uri.etsi.org/19602/LoTEType/EURegistrarsAndRegistersList</LoTEType><SchemeOperatorName><Name xml:lang="en">Test Operator</Name></SchemeOperatorName><StatusDeterminationApproach/><SchemeTerritory>EU</SchemeTerritory><ListIssueDateTime>2026-03-01T00:00:00Z</ListIssueDateTime><NextUpdate><dateTime>2026-06-01T00:00:00Z</dateTime></NextUpdate></ListAndSchemeInformation><TrustedEntitiesList><TrustedEntity><TrustedEntityInformation><TEName><Name xml:lang="de-DE">Test Entity</Name></TEName></TrustedEntityInformation><TrustedEntityServices><TrustedEntityService><ServiceInformation><ServiceName><Name xml:lang="de-DE">Test Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>MIICLzCCAdSgAwIBAgIUHyRjE466YA7tc888k03Ou2QodF4wCgYIKoZIzj0EAwIwKDELMAkGA1UEBhMCREUxGTAXBgNVBAMMEEdlcm1hbiBSZWdpc3RyYXIwHhcNMjYwMTE2MTExNTU0WhcNMjgwMTE2MTExNTU0WjAoMQswCQYDVQQGEwJERTEZMBcGA1UEAwwQR2VybWFuIFJlZ2lzdHJhcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMefY2X4ixfRkWEvp9grF2i21z6PKZsr8zzBaJ/+GnotCeH2cJ6GtLhxXhHfJjrETsMNIGhVaJoHoHcZTBHJrfyjgdswgdgwHQYDVR0OBBYEFKnCo9ovbaxU7s65TugsySwAg4AzMB8GA1UdIwQYMBaAFKnCo9ovbaxU7s65TugsySwAg4AzMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMCoGA1UdEgQjMCGGH2h0dHBzOi8vc2FuZGJveC5ldWRpLXdhbGxldC5vcmcwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cHM6Ly9zYW5kYm94LmV1ZGktd2FsbGV0Lm9yZy9zdGF0dXMtbWFuYWdlbWVudC9jcmwwCgYIKoZIzj0EAwIDSQAwRgIhAIY7ERpRrDRl0lr5H5uxjJ83JR4qua2sfPKxX+pl4Qw+AiEA2qL6LXVORA2r2VZjSEknfciwIG7laA12kjnyGAD3V/A=</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/19602/SvcStatus/active</ServiceStatus><StatusStartingTime>2026-03-01T00:00:00Z</StatusStartingTime></ServiceInformation></TrustedEntityService></TrustedEntityServices></TrustedEntity></TrustedEntitiesList><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="id-7f5552b2-bd88-425b-a42d-64e074b23d31"><ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference Id="r-id-7f5552b2-bd88-425b-a42d-64e074b23d31" URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>ibHwcbENffk1nsVFRhNhhBX9XOKIluQTGocvLekeOBY=</ds:DigestValue></ds:Reference><ds:Reference URI="#xades-id-7f5552b2-bd88-425b-a42d-64e074b23d31" Type="http://uri.etsi.org/01903#SignedProperties"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>Y0OazMA/aZaHQmPILNDLNRnNAaOWjb6NVKO63gg8xLg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue Id="value-id-7f5552b2-bd88-425b-a42d-64e074b23d31">dFO8cosEG/KAgMqgB3BXGpuDuzZAGcgh5mv93DkqahQu054UOXL38EeIoWmfyYeMlwEPZpfWSzujtTpWgDZk+g==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBMTCB2KADAgECAhQSJe8xsm3dMnAInnpRGvwiotSp6jAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1YQWRFUyBUZXN0IENBMCAXDTc1MDEwMTAwMDAwMFoYDzQwOTYwMTAxMDAwMDAwWjAYMRYwFAYDVQQDDA1YQWRFUyBUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcd/LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yeJpCY9SCKvzQjZcIWqfb8o+p1YfQ/EzMII/xbe4/GVQDAKBggqhkjOPQQDAgNIADBFAiEA34ISXnPYu5LRBb0itF0Nlmm4imiZ5YUKZahKnnmmAMQCIBWBr/GnmGAj5aqM+V6HGzhpwlz6d5ocJqb5GY+WhnHb</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#id-7f5552b2-bd88-425b-a42d-64e074b23d31"><xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="xades-id-7f5552b2-bd88-425b-a42d-64e074b23d31"><xades:SignedSignatureProperties><xades:SigningTime>2026-03-29T20:35:02.640504Z</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>Vko5kJdJk0XOYw1G3uHVzAgQ+uPXlHRtH32Qp1K2FSs=</ds:DigestValue></xades:CertDigest><xades:IssuerSerialV2/></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties><xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference="#r-id-7f5552b2-bd88-425b-a42d-64e074b23d31"><xades:MimeType>text/xml</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties></xades:SignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature></ListOfTrustedEntities>"##;

fn setup_subscriber_xml(reference: &Url) -> EtsiLoteSubscriber {
    let mut client = MockHttpClient::new();
    mock_http_get_request(
        &mut client,
        reference.to_string(),
        Response {
            body: LOTE_XML.as_bytes().to_vec(),
            headers: hashmap! { "Content-Type".to_string() => "application/xml; charset=UTF-8".to_string() },
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
        .with(eq(KeyAlgorithmType::Ecdsa))
        .returning(|_| Ok(Arc::new(Ecdsa)));
    let key_algorithm_provider = Arc::new(key_algorithm_provider);
    let cache_storage = Arc::new(InMemoryStorage::new(HashMap::new()));

    // XAdES verification needs a certificate validator that returns
    // the test signing key's public key.
    let ecdsa = Ecdsa;
    let signing_cert_der =
        ct_codecs::Base64::decode_to_vec("MIIBMTCB2KADAgECAhQSJe8xsm3dMnAInnpRGvwiotSp6jAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1YQWRFUyBUZXN0IENBMCAXDTc1MDEwMTAwMDAwMFoYDzQwOTYwMTAxMDAwMDAwWjAYMRYwFAYDVQQDDA1YQWRFUyBUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcd/LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yeJpCY9SCKvzQjZcIWqfb8o+p1YfQ/EzMII/xbe4/GVQDAKBggqhkjOPQQDAgNIADBFAiEA34ISXnPYu5LRBb0itF0Nlmm4imiZ5YUKZahKnnmmAMQCIBWBr/GnmGAj5aqM+V6HGzhpwlz6d5ocJqb5GY+WhnHb", None).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(&signing_cert_der).unwrap();
    let key_handle = ecdsa
        .parse_der(parsed.tbs_certificate.subject_pki.raw)
        .unwrap();

    let mut cert_validator = MockCertificateValidator::new();
    let certificate = {
        let now = OffsetDateTime::now_utc();
        ParsedCertificate {
            attributes: CertificateX509AttributesDTO {
                serial_number: "test".to_string(),
                not_before: now,
                not_after: now,
                issuer: "XAdES Test CA".to_string(),
                subject: "XAdES Test CA".to_string(),
                fingerprint: TRUSTED_FINGERPRINT.to_string(),
                extensions: vec![],
            },
            subject_common_name: Some("XAdES Test CA".to_string()),
            subject_key_identifier: None,
            public_key: key_handle,
        }
    };
    cert_validator
        .expect_parse_pem_chain()
        .with(eq(TRUSTED_CERT), always())
        .returning({
            let certificate = certificate.clone();
            move |_, _| Ok(certificate.clone())
        });
    cert_validator
        .expect_parse_pem_chain()
        .with(ne(TRUSTED_CERT), always())
        .returning({
            let mut certificate = certificate.clone();
            certificate.attributes.fingerprint = "unknown fingerprint".to_string();
            move |_, _| Ok(certificate.clone())
        });
    cert_validator
        .expect_validate_chain_against_ca_chain()
        .returning(move |_, _, _, _| Ok(certificate.clone()));

    let cert_validator = Arc::new(cert_validator);
    let xades = XAdES::new(cert_validator.clone());

    let resolver = EtsiLoteResolver::new(
        client,
        Arc::new(MockDidMethodProvider::new()),
        key_algorithm_provider.clone(),
        cert_validator.clone(),
        Arc::new(xades),
        LoteContentType::Xml,
        Duration::seconds(0),
        None,
    );
    let cache = EtsiLoteCache::new(
        Arc::new(resolver),
        cache_storage,
        100,
        Duration::seconds(60),
        Duration::seconds(60),
    );

    EtsiLoteSubscriber::new(cache, cert_validator, key_algorithm_provider)
}

#[tokio::test]
async fn validate_subscription_xml_success() {
    let time = datetime!(2026-04-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote-xml").unwrap();

    let subscriber = setup_subscriber_xml(&reference);

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .validate_subscription(
                &reference,
                Some(TrustListRoleEnum::NationalRegistryRegistrar),
            )
            .await
    })
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn validate_subscription_xml_expired() {
    // After NextUpdate (2026-06-01) but still valid for XAdES signing time check
    let time = datetime!(2026-07-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote-xml").unwrap();

    let subscriber = setup_subscriber_xml(&reference);

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .validate_subscription(&reference, None)
            .await
            .err()
            .unwrap()
    })
    .await;

    assert_eq!(result.error_code(), ErrorCode::BR_0354);
}

#[tokio::test]
async fn resolve_trusted_identifier_xml() {
    let time = datetime!(2026-04-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote-xml").unwrap();

    let subscriber = setup_subscriber_xml(&reference);

    let identifier_id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();
    let identifier = Identifier {
        id: identifier_id,
        created_date: now,
        last_modified: now,
        name: "".to_string(),
        data: IdentifierData::Certificate(RelatedVec::from(vec![Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation: dummy_organisation(None).into(),
            created_date: now,
            last_modified: now,
            deleted_at: None,
            expiry_date: now,
            name: "".to_string(),
            chain: TRUSTED_CERT.to_string(),
            fingerprint: TRUSTED_FINGERPRINT.to_string(),
            state: CertificateState::Active,
            roles: vec![],
            key: Some(dummy_key().into()),
        }])),
        is_remote: false,
        state: IdentifierState::Active,
        deleted_at: None,
        autogenerated: false,
        organisation: dummy_organisation(None).into(),
        trust_information: Default::default(),
        logo: None,
        translations: Default::default(),
    };

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .resolve_entries(&reference, &[identifier])
            .await
            .unwrap()
    })
    .await;

    assert_eq!(result.len(), 1);
    assert!(result.contains_key(&identifier_id));
}

#[tokio::test]
async fn resolve_untrusted_identifier_xml() {
    let time = datetime!(2026-04-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote-xml").unwrap();

    let subscriber = setup_subscriber_xml(&reference);

    let identifier_id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();
    let identifier = Identifier {
        id: identifier_id,
        created_date: now,
        last_modified: now,
        name: "".to_string(),
        data: IdentifierData::Certificate(RelatedVec::from(vec![Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation: dummy_organisation(None).into(),
            created_date: now,
            last_modified: now,
            deleted_at: None,
            expiry_date: now,
            name: "".to_string(),
            chain: UNTRUSTED_CERT.to_string(),
            fingerprint: "unknown fingerprint".to_string(),
            state: CertificateState::Active,
            roles: vec![],
            key: Some(dummy_key().into()),
        }])),
        is_remote: false,
        state: IdentifierState::Active,
        deleted_at: None,
        autogenerated: false,
        organisation: dummy_organisation(None).into(),
        trust_information: Default::default(),
        logo: None,
        translations: Default::default(),
    };

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .resolve_entries(&reference, &[identifier])
            .await
            .unwrap()
    })
    .await;

    assert!(result.is_empty());
}
