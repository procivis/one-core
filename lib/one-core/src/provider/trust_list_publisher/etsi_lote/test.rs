use std::sync::{Arc, Mutex};

use ct_codecs::Decoder;
use one_crypto::signer::ecdsa::ECDSASigner;
use secrecy::ExposeSecret;
use serde_json::json;
use shared_types::TrustListPublicationId;
use similar_asserts::assert_eq;
use standardized_types::etsi_119_602::{LoTEPayload, LoTEType, MultiLangString};
use time::format_description::well_known::Rfc3339;
use time::macros::datetime;
use uuid::Uuid;

use super::dto::AddEntryParams;
use super::*;
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::common::GetListResponse;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::key::Key;
use crate::proto::clock::DefaultClock;
use crate::proto::jwt::Jwt;
use crate::provider::credential_formatter::model::MockSignatureProvider;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::trust_entry_repository::MockTrustEntryRepository;
use crate::repository::trust_list_publication_repository::MockTrustListPublicationRepository;
use crate::service::test_utilities::{dummy_identifier, dummy_key, dummy_organisation};

fn sample_list_params() -> dto::CreateTrustListParams {
    dto::CreateTrustListParams {
        scheme_operator_name: Some(vec![MultiLangString {
            lang: "en".into(),
            value: "Test Operator".into(),
        }]),
        ..Default::default()
    }
}

fn dummy_certificate(pem: String) -> Certificate {
    Certificate {
        id: Uuid::new_v4().into(),
        identifier_id: Uuid::new_v4().into(),
        organisation_id: None,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        expiry_date: crate::clock::now_utc() + time::Duration::days(365),
        name: "test-cert".into(),
        chain: pem,
        fingerprint: "test".into(),
        state: CertificateState::Active,
        key: None,
    }
}

fn dummy_publication(role: TrustListRoleEnum, metadata: Vec<u8>) -> TrustListPublication {
    TrustListPublication {
        id: TrustListPublicationId::from(Uuid::new_v4()),
        created_date: datetime!(2025-01-01 0:00 UTC),
        last_modified: datetime!(2025-01-01 0:00 UTC),
        name: "test-publication".to_string(),
        role,
        r#type: "ETSI_LOTE".into(),
        metadata,
        deleted_at: None,
        content: Vec::new(),
        sequence_number: 42,
        organisation_id: Uuid::new_v4().into(),
        identifier_id: Uuid::new_v4().into(),
        key_id: None,
        certificate_id: None,
        organisation: None,
        identifier: None,
        key: None,
        certificate: None,
    }
}

fn dummy_entry(metadata: Vec<u8>) -> TrustEntry {
    TrustEntry {
        id: Uuid::new_v4().into(),
        created_date: datetime!(2025-01-01 0:00 UTC),
        last_modified: datetime!(2025-01-01 0:00 UTC),
        status: TrustEntryStatusEnum::Active,
        metadata,
        trust_list_publication_id: Uuid::new_v4().into(),
        identifier_id: Uuid::new_v4().into(),
        trust_list_publication: None,
        identifier: None,
    }
}

fn generate_self_signed_pem() -> String {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test Certificate");
    params.self_signed(&key_pair).unwrap().pem()
}

fn make_signing_mocks() -> (
    MockKeyProvider,
    MockKeyAlgorithmProvider,
    Key,
    Certificate,
    Vec<u8>,
) {
    let (private_key, public_key) = ECDSASigner::generate_key_pair();
    let private_bytes: Vec<u8> = private_key.expose_secret().to_vec();
    let pem = generate_self_signed_pem();

    let key = Key {
        public_key: public_key.clone(),
        key_reference: Some(vec![]),
        storage_type: "INTERNAL".into(),
        key_type: "ECDSA".into(),
        ..dummy_key()
    };
    let certificate = dummy_certificate(pem);

    let ecdsa: Arc<dyn crate::provider::key_algorithm::KeyAlgorithm> = Arc::new(Ecdsa);
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(move |_| Some(ecdsa.clone()));

    let pub_key = public_key.clone();
    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let pk = pub_key.clone();
            let sk = private_bytes.clone();
            let mut mock = MockSignatureProvider::new();
            mock.expect_sign().returning(move |msg| {
                use one_crypto::Signer as _;
                let secret: secrecy::SecretSlice<u8> = sk.clone().into();
                Ok(ECDSASigner.sign(msg, &pk, &secret).unwrap())
            });
            mock.expect_jose_alg()
                .returning(|| Some("ES256".to_string()));
            Ok(Box::new(mock))
        });

    (
        key_provider,
        key_algorithm_provider,
        key,
        certificate,
        public_key,
    )
}

struct MockRepos {
    pub_repo: MockTrustListPublicationRepository,
    entry_repo: MockTrustEntryRepository,
    stored_publication: Arc<Mutex<Option<TrustListPublication>>>,
    stored_content: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn mock_publication_repo(
    key: Key,
    certificate: Certificate,
    publications: Arc<Mutex<Option<TrustListPublication>>>,
    content_log: Arc<Mutex<Vec<Vec<u8>>>>,
) -> MockTrustListPublicationRepository {
    let mut repo = MockTrustListPublicationRepository::new();

    let store = publications.clone();
    repo.expect_create().returning(move |publication| {
        let id = publication.id;
        *store.lock().unwrap() = Some(publication);
        Ok(id)
    });

    let store = publications.clone();
    let store_for_update = publications;
    repo.expect_get().returning(move |_id, _relations| {
        let mut publication = store.lock().unwrap().clone().unwrap();
        publication.key = Some(key.clone());
        publication.certificate = Some(certificate.clone());
        publication.organisation = Some(dummy_organisation(Some(publication.organisation_id)));
        Ok(Some(publication))
    });

    repo.expect_update().returning(move |_id, request| {
        let mut guard = store_for_update.lock().unwrap();
        let publication = guard.as_mut().unwrap();
        if let Some(seq) = request.sequence_number {
            publication.sequence_number = seq;
        }
        if let Some(ref bytes) = request.content {
            content_log.lock().unwrap().push(bytes.clone());
            publication.content = bytes.to_owned();
        }
        publication.last_modified = crate::clock::now_utc();
        Ok(())
    });

    repo
}

fn mock_entry_repo() -> MockTrustEntryRepository {
    let entries: Arc<Mutex<Vec<TrustEntry>>> = Arc::new(Mutex::new(vec![]));
    let mut repo = MockTrustEntryRepository::new();

    let store = entries.clone();
    repo.expect_create().returning(move |entry| {
        let id = entry.id;
        store.lock().unwrap().push(entry);
        Ok(id)
    });

    let store = entries.clone();
    repo.expect_get().returning(move |id, _relations| {
        let entries = store.lock().unwrap();
        Ok(entries.iter().find(|e| e.id == id).cloned())
    });

    let store = entries.clone();
    repo.expect_list().returning(move |_id, _query| {
        let entries = store.lock().unwrap().clone();
        Ok(GetListResponse {
            values: entries,
            total_pages: 1,
            total_items: 0,
        })
    });

    let store = entries.clone();
    repo.expect_update().returning(move |id, request| {
        let mut entries = store.lock().unwrap();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            if let Some(state) = request.status {
                entry.status = state;
            }
            if let Some(metadata) = request.metadata {
                entry.metadata = metadata;
            }
        }
        Ok(())
    });

    repo.expect_delete().returning(move |id| {
        let mut entries = entries.lock().unwrap();
        entries.retain(|e| e.id != id);
        Ok(())
    });

    repo
}

fn make_stateful_repos(key: Key, certificate: Certificate) -> MockRepos {
    let stored_publication = Arc::new(Mutex::new(None));
    let stored_content = Arc::new(Mutex::new(vec![]));

    let pub_repo = mock_publication_repo(
        key,
        certificate,
        stored_publication.clone(),
        stored_content.clone(),
    );
    let entry_repo = mock_entry_repo();

    MockRepos {
        pub_repo,
        entry_repo,
        stored_publication,
        stored_content,
    }
}

fn decode_jws_payload(jws_bytes: &[u8]) -> LoTEPayload {
    let jws = std::str::from_utf8(jws_bytes).unwrap();
    Jwt::<LoTEPayload>::decompose_token(jws)
        .unwrap()
        .payload
        .custom
}

fn make_publisher(
    key_provider: MockKeyProvider,
    key_algorithm_provider: MockKeyAlgorithmProvider,
    pub_repo: MockTrustListPublicationRepository,
    entry_repo: MockTrustEntryRepository,
    identifier_repo: MockIdentifierRepository,
) -> EtsiLotePublisher {
    EtsiLotePublisher {
        method_id: "ETSI_LOTE".into(),
        params: EtsiLoteParams {
            refresh_interval_seconds: time::Duration::seconds(86400),
        },
        clock: Arc::new(DefaultClock),
        key_provider: Arc::new(key_provider),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        trust_list_publication_repository: Arc::new(pub_repo),
        trust_entry_repository: Arc::new(entry_repo),
        identifier_repository: Arc::new(identifier_repo),
    }
}

#[test]
fn test_build_lote_payload_basic() {
    let identifier = Identifier {
        name: "Test Entity".into(),
        r#type: IdentifierType::Certificate,
        certificates: Some(vec![dummy_certificate(generate_self_signed_pem())]),
        ..dummy_identifier()
    };

    let entry_params = AddEntryParams::default();
    let entry_metadata = serde_json::to_vec(&entry_params).unwrap();
    let entry = dummy_entry(entry_metadata);

    let pub_metadata = serde_json::to_vec(&sample_list_params()).unwrap();
    let mut publication = dummy_publication(TrustListRoleEnum::PidProvider, pub_metadata);
    publication.sequence_number = 42;

    // add fractional seconds to the publication date, to make sure it's rounded off
    let now = datetime!(2025-06-15 12:00:00.55 UTC);

    let payload = build_lote_payload(
        &publication,
        "Test Operator",
        &[(entry, identifier)],
        time::Duration::seconds(86400),
        now,
    )
    .unwrap();

    assert_eq!(
        payload.list_and_scheme_information.lote_version_identifier,
        1
    );
    assert_eq!(payload.list_and_scheme_information.lote_sequence_number, 42);
    assert_eq!(
        payload.list_and_scheme_information.lote_type,
        Some(LoTEType::EuPidProvidersList),
    );
    assert_eq!(
        payload.list_and_scheme_information.list_issue_date_time,
        OffsetDateTime::parse("2025-06-15T12:00:00Z", &Rfc3339).unwrap()
    );
    assert_eq!(
        payload.list_and_scheme_information.next_update,
        OffsetDateTime::parse("2025-06-16T12:00:00Z", &Rfc3339).unwrap()
    );
    assert_eq!(
        payload.list_and_scheme_information.scheme_operator_name[0].value,
        "Test Operator"
    );
    assert_eq!(payload.list_and_scheme_information.scheme_territory, "EU");
    assert_eq!(
        payload
            .list_and_scheme_information
            .status_determination_approach,
        LoTEType::EuPidProvidersList
            .status_determination_approach()
            .unwrap()
    );
    assert_eq!(payload.trusted_entities_list.as_ref().unwrap().len(), 1);
    let entity = &payload.trusted_entities_list.as_ref().unwrap()[0];
    assert_eq!(
        entity.trusted_entity_information.te_name[0].value,
        "Test Entity"
    );
    assert!(
        entity.trusted_entity_services[0]
            .service_information
            .service_status
            .is_none()
    );
}

const SPRIND_LOTE_JWS: &str = "eyJhbGciOiJFUzI1NiIsImlhdCI6MTc3MjQ5MzA2NywieDVjIjpbIk1JSUNGekNDQWIyZ0F3SUJBZ0lVUUF4ZXY4eDJCbzRZNWhWbkdoT285VlNkQWNJd0NnWUlLb1pJemowRUF3SXdZVEVMTUFrR0ExVUVCaE1DUkVVeER6QU5CZ05WQkFnTUJrSmxjbXhwYmpFUE1BMEdBMVVFQnd3R1FtVnliR2x1TVJRd0VnWURWUVFLREF0VWNuVnpkQ0JNYVhOMGN6RWFNQmdHQTFVRUF3d1JWSEoxYzNRZ1RHbHpkQ0JUYVdkdVpYSXdIaGNOTWpZd01qQTJNVFF5TWpFNVdoY05Nell3TWpBME1UUXlNakU1V2pCaE1Rc3dDUVlEVlFRR0V3SkVSVEVQTUEwR0ExVUVDQXdHUW1WeWJHbHVNUTh3RFFZRFZRUUhEQVpDWlhKc2FXNHhGREFTQmdOVkJBb01DMVJ5ZFhOMElFeHBjM1J6TVJvd0dBWURWUVFEREJGVWNuVnpkQ0JNYVhOMElGTnBaMjVsY2pCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQk5GRHc5a0VaeHp3ZWxsVzRiNmlUYXhxYThlSEJaTUVzTzg0Q1Y1T0piZEI5ZG1OaUdiNTM5dnh3V2JpbTZ3WHorYzNuNUNVbnN1Z2VvbStubjBHQWxTalV6QlJNQjBHQTFVZERnUVdCQlMxdVhqODF4VHovUHhYWWpsaEtrWkhzNmREVVRBZkJnTlZIU01FR0RBV2dCUzF1WGo4MXhUei9QeFhZamxoS2taSHM2ZERVVEFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJUUNFSnAvWlJ3eFBlZTJFUUpIZFZXQ3RiUjdiWFBwYzJIcjFsdEorL1U0SnNRSWdRWnFJWkFCMzhtNzl6VHhWR2lYUmF1ZzJTaml1NlAxRGJWYldSZVMwazBjPSJdfQ.eyJMaXN0QW5kU2NoZW1lSW5mb3JtYXRpb24iOnsiTG9URVZlcnNpb25JZGVudGlmaWVyIjoxLCJMb1RFU2VxdWVuY2VOdW1iZXIiOjEsIkxvVEVUeXBlIjoiaHR0cDovL3VyaS5ldHNpLm9yZy8xOTYwMi9Mb1RFVHlwZS9SZWdpc3RyYXJzQW5kUmVnaXN0ZXJzTGlzdFByb3ZpZGVyc0xpc3QiLCJTY2hlbWVJbmZvcm1hdGlvblVSSSI6W3sibGFuZyI6ImRlLURFIiwidXJpVmFsdWUiOiJodHRwczovL2V4YW1wbGUuY29tL3ByZXZpb3VzLWxpc3RzIn1dLCJTdGF0dXNEZXRlcm1pbmF0aW9uQXBwcm9hY2giOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1JlZ2lzdHJhcnNBbmRSZWdpc3RlcnNMaXN0UHJvdmlkZXJzTGlzdC9TdGF0dXNEZXRuL0VVLiIsIlNjaGVtZVR5cGVDb21tdW5pdHlSdWxlcyI6W3sibGFuZyI6ImRlLURFIiwidXJpVmFsdWUiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1JlZ2lzdHJhcnNBbmRSZWdpc3RlcnNMaXN0UHJvdmlkZXJzTGlzdC9zY2hlbWVydWxlcy9FVSJ9XSwiU2NoZW1lVGVycml0b3J5IjoiRVUiLCJOZXh0VXBkYXRlIjoiMjAyNi0wMy0wM1QyMzoxMTowNy4xMzNaIiwiU2NoZW1lT3BlcmF0b3JOYW1lIjpbeyJsYW5nIjoiZGUtREUiLCJ2YWx1ZSI6IlNQUklORCBHbWJIIn1dLCJMaXN0SXNzdWVEYXRlVGltZSI6IjIwMjYtMDMtMDJUMjM6MTE6MDcuMTMzWiJ9LCJUcnVzdGVkRW50aXRpZXNMaXN0IjpbeyJUcnVzdGVkRW50aXR5SW5mb3JtYXRpb24iOnsiVEVJbmZvcm1hdGlvblVSSSI6W3sibGFuZyI6ImRlLURFIiwidXJpVmFsdWUiOiJodHRwczovL3d3dy5zcHJpbmQub3JnIn1dLCJURU5hbWUiOlt7ImxhbmciOiJkZS1ERSIsInZhbHVlIjoiU1BSSU5EIEdtYkgifV0sIlRFQWRkcmVzcyI6eyJURUVsZWN0cm9uaWNBZGRyZXNzIjpbeyJsYW5nIjoiZGUtREUiLCJ1cmlWYWx1ZSI6Imh0dHBzOi8vc3ByaW5kLm9yZy9jb250YWN0In1dLCJURVBvc3RhbEFkZHJlc3MiOlt7IkNvdW50cnkiOiJERSIsImxhbmciOiJkZSIsIkxvY2FsaXR5IjoiTGVpcHppZyIsIlBvc3RhbENvZGUiOiIwNDEwMyIsIlN0cmVldEFkZHJlc3MiOiJMYWdlcmhvZnN0cmHDn2UgNCJ9XX19LCJUcnVzdGVkRW50aXR5U2VydmljZXMiOlt7IlNlcnZpY2VJbmZvcm1hdGlvbiI6eyJTZXJ2aWNlVHlwZUlkZW50aWZpZXIiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1N2Y1R5cGUvUmVnaXN0cmFyc0FuZFJlZ2lzdGVyc0xpc3RTb2x1dGlvbi9Jc3N1YW5jZSIsIlNlcnZpY2VOYW1lIjpbeyJsYW5nIjoiZGUtREUiLCJ2YWx1ZSI6IkFjY2VzcyBDZXJ0aWZpY2F0ZSBBdXNzdGVsbHVuZ3NkaWVuc3QgZGVyIFNQUklORCBHbWJIIn1dLCJTZXJ2aWNlRGlnaXRhbElkZW50aXR5Ijp7Ilg1MDlDZXJ0aWZpY2F0ZXMiOlt7InZhbCI6Ik1JSUNMekNDQWRTZ0F3SUJBZ0lVSHlSakU0NjZZQTd0Yzg4OGswM091MlFvZEY0d0NnWUlLb1pJemowRUF3SXdLREVMTUFrR0ExVUVCaE1DUkVVeEdUQVhCZ05WQkFNTUVFZGxjbTFoYmlCU1pXZHBjM1J5WVhJd0hoY05Nall3TVRFMk1URXhOVFUwV2hjTk1qZ3dNVEUyTVRFeE5UVTBXakFvTVFzd0NRWURWUVFHRXdKRVJURVpNQmNHQTFVRUF3d1FSMlZ5YldGdUlGSmxaMmx6ZEhKaGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJNZWZZMlg0aXhmUmtXRXZwOWdyRjJpMjF6NlBLWnNyOHp6QmFKLytHbm90Q2VIMmNKNkd0TGh4WGhIZkpqckVUc01OSUdoVmFKb0hvSGNaVEJISnJmeWpnZHN3Z2Rnd0hRWURWUjBPQkJZRUZLbkNvOW92YmF4VTdzNjVUdWdzeVN3QWc0QXpNQjhHQTFVZEl3UVlNQmFBRktuQ285b3ZiYXhVN3M2NVR1Z3N5U3dBZzRBek1CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Db0dBMVVkRWdRak1DR0dIMmgwZEhCek9pOHZjMkZ1WkdKdmVDNWxkV1JwTFhkaGJHeGxkQzV2Y21jd1JnWURWUjBmQkQ4d1BUQTdvRG1nTjRZMWFIUjBjSE02THk5ellXNWtZbTk0TG1WMVpHa3RkMkZzYkdWMExtOXlaeTl6ZEdGMGRYTXRiV0Z1WVdkbGJXVnVkQzlqY213d0NnWUlLb1pJemowRUF3SURTUUF3UmdJaEFJWTdFUnBSckRSbDBscjVINXV4ako4M0pSNHF1YTJzZlBLeFgrcGw0UXcrQWlFQTJxTDZMWFZPUkEycjJWWmpTRWtuZmNpd0lHN2xhQTEya2pueUdBRDNWL0E9In1dfX19LHsiU2VydmljZUluZm9ybWF0aW9uIjp7IlNlcnZpY2VOYW1lIjpbeyJsYW5nIjoiZGUtREUiLCJ2YWx1ZSI6IkFjY2VzcyBDZXJ0aWZpY2F0ZS1SZXZva2F0aW9uc2RpZW5zdCBkZXIgU1BSSU5EIEdtYkgifV0sIlNlcnZpY2VUeXBlSWRlbnRpZmllciI6Imh0dHA6Ly91cmkuZXRzaS5vcmcvMTk2MDIvU3ZjVHlwZS9SZWdpc3RyYXJzQW5kUmVnaXN0ZXJzTGlzdFNvbHV0aW9uL1Jldm9jYXRpb24iLCJTZXJ2aWNlRGlnaXRhbElkZW50aXR5Ijp7Ilg1MDlDZXJ0aWZpY2F0ZXMiOlt7InZhbCI6Ik1JSUNMekNDQWRTZ0F3SUJBZ0lVSHlSakU0NjZZQTd0Yzg4OGswM091MlFvZEY0d0NnWUlLb1pJemowRUF3SXdLREVMTUFrR0ExVUVCaE1DUkVVeEdUQVhCZ05WQkFNTUVFZGxjbTFoYmlCU1pXZHBjM1J5WVhJd0hoY05Nall3TVRFMk1URXhOVFUwV2hjTk1qZ3dNVEUyTVRFeE5UVTBXakFvTVFzd0NRWURWUVFHRXdKRVJURVpNQmNHQTFVRUF3d1FSMlZ5YldGdUlGSmxaMmx6ZEhKaGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJNZWZZMlg0aXhmUmtXRXZwOWdyRjJpMjF6NlBLWnNyOHp6QmFKLytHbm90Q2VIMmNKNkd0TGh4WGhIZkpqckVUc01OSUdoVmFKb0hvSGNaVEJISnJmeWpnZHN3Z2Rnd0hRWURWUjBPQkJZRUZLbkNvOW92YmF4VTdzNjVUdWdzeVN3QWc0QXpNQjhHQTFVZEl3UVlNQmFBRktuQ285b3ZiYXhVN3M2NVR1Z3N5U3dBZzRBek1CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Db0dBMVVkRWdRak1DR0dIMmgwZEhCek9pOHZjMkZ1WkdKdmVDNWxkV1JwTFhkaGJHeGxkQzV2Y21jd1JnWURWUjBmQkQ4d1BUQTdvRG1nTjRZMWFIUjBjSE02THk5ellXNWtZbTk0TG1WMVpHa3RkMkZzYkdWMExtOXlaeTl6ZEdGMGRYTXRiV0Z1WVdkbGJXVnVkQzlqY213d0NnWUlLb1pJemowRUF3SURTUUF3UmdJaEFJWTdFUnBSckRSbDBscjVINXV4ako4M0pSNHF1YTJzZlBLeFgrcGw0UXcrQWlFQTJxTDZMWFZPUkEycjJWWmpTRWtuZmNpd0lHN2xhQTEya2pueUdBRDNWL0E9In1dfX19XX1dfQ.IzpFGp0TchXMvizip3HffMnmP40WkNsvLRBRUGsu1pKAd5PeMs2klbuEWb22FpQ1UyTUvRobi2xyHewySS6mpA";

#[test]
fn test_parse_and_verify_sprind_lote() {
    use one_crypto::Signer as _;

    let decomposed = Jwt::<LoTEPayload>::decompose_token(SPRIND_LOTE_JWS).unwrap();

    let x5c = decomposed.header.x5c.as_ref().expect("missing x5c");
    let cert_der = ct_codecs::Base64::decode_to_vec(&x5c[0], None).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    let public_key_bytes = cert.public_key().subject_public_key.as_ref();

    ECDSASigner {}
        .verify(
            decomposed.unverified_jwt.as_bytes(),
            &decomposed.signature,
            public_key_bytes,
        )
        .expect("SPRIND LoTE JWS signature verification failed");

    let payload = decomposed.payload.custom;
    let info = &payload.list_and_scheme_information;
    assert_eq!(info.lote_version_identifier, 1);
    assert_eq!(info.lote_sequence_number, 1);
    assert_eq!(
        info.lote_type,
        Some(LoTEType::Other(
            "http://uri.etsi.org/19602/LoTEType/RegistrarsAndRegistersListProvidersList"
                .to_string()
        ))
    );
    assert_eq!(info.scheme_territory, "EU");
    assert_eq!(info.scheme_operator_name[0].value, "SPRIND GmbH");

    let entities = payload.trusted_entities_list.as_ref().unwrap();
    assert_eq!(entities.len(), 1);
    assert_eq!(
        entities[0].trusted_entity_information.te_name[0].value,
        "SPRIND GmbH"
    );
    assert_eq!(entities[0].trusted_entity_services.len(), 2);
}

#[tokio::test]
async fn test_format_trust_list_empty_list() {
    let (key_provider, key_algorithm_provider, key, certificate, _) = make_signing_mocks();

    let pub_metadata = serde_json::to_vec(&sample_list_params()).unwrap();
    let publication = TrustListPublication {
        key: Some(key),
        certificate: Some(certificate),
        ..dummy_publication(TrustListRoleEnum::PidProvider, pub_metadata)
    };

    let publisher = make_publisher(
        key_provider,
        key_algorithm_provider,
        MockTrustListPublicationRepository::new(),
        MockTrustEntryRepository::new(),
        MockIdentifierRepository::new(),
    );

    let jws = publisher
        .format_trust_list(&publication, "Test Operator", &[])
        .await
        .unwrap();

    let payload = decode_jws_payload(&jws);
    assert!(payload.trusted_entities_list.is_none());
}

#[tokio::test]
async fn test_format_trust_list_with_entry() {
    let (key_provider, key_algorithm_provider, key, certificate, _) = make_signing_mocks();

    let pub_metadata = serde_json::to_vec(&sample_list_params()).unwrap();
    let mut publication = TrustListPublication {
        key: Some(key),
        certificate: Some(certificate),
        ..dummy_publication(TrustListRoleEnum::PidProvider, pub_metadata)
    };
    publication.sequence_number = 2;

    let identifier = Identifier {
        name: "Acme PID Provider".into(),
        r#type: IdentifierType::Certificate,
        certificates: Some(vec![dummy_certificate(generate_self_signed_pem())]),
        ..dummy_identifier()
    };
    let entry_params = AddEntryParams::default();
    let entry = dummy_entry(serde_json::to_vec(&entry_params).unwrap());

    let publisher = make_publisher(
        key_provider,
        key_algorithm_provider,
        MockTrustListPublicationRepository::new(),
        MockTrustEntryRepository::new(),
        MockIdentifierRepository::new(),
    );

    let jws = publisher
        .format_trust_list(&publication, "Test Operator", &[(entry, identifier)])
        .await
        .unwrap();

    let payload = decode_jws_payload(&jws);
    assert_eq!(payload.list_and_scheme_information.lote_sequence_number, 2);
    let entities = payload.trusted_entities_list.as_ref().unwrap();
    assert_eq!(entities.len(), 1);
    assert_eq!(
        entities[0].trusted_entity_information.te_name[0].value,
        "Acme PID Provider"
    );
    assert_eq!(entities[0].trusted_entity_services.len(), 2);
    assert!(
        entities[0].trusted_entity_services[0]
            .service_information
            .service_type_identifier
            .contains("PID/Issuance")
    );
    assert!(
        entities[0].trusted_entity_services[1]
            .service_information
            .service_type_identifier
            .contains("PID/Revocation")
    );
}

#[tokio::test]
async fn test_create_trust_list_rejects_identifier_without_certificate() {
    let identifier = dummy_identifier(); // Did type, no certificates
    let identifier_clone = identifier.clone();
    let mut identifier_repo = MockIdentifierRepository::new();
    identifier_repo
        .expect_get()
        .returning(move |_id, _relations| Ok(Some(identifier_clone.clone())));

    let publisher = make_publisher(
        MockKeyProvider::new(),
        MockKeyAlgorithmProvider::new(),
        MockTrustListPublicationRepository::new(),
        MockTrustEntryRepository::new(),
        MockIdentifierRepository::new(),
    );

    let result = publisher
        .create_trust_list(CreateTrustListRequest {
            name: "Test".into(),
            role: TrustListRoleEnum::PidProvider,
            organisation_id: Uuid::new_v4().into(),
            identifier,
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;

    assert!(
        matches!(result, Err(TrustListPublisherError::Nested(_))),
        "expected key selection error, got: {result:?}"
    );
}

#[tokio::test]
async fn test_lifecycle_create_add_update_remove() {
    let (key_provider, key_algorithm_provider, key, certificate, _) = make_signing_mocks();

    let mut cert_with_key = certificate.clone();
    cert_with_key.key = Some(key.clone());

    let identifier = Identifier {
        r#type: IdentifierType::Certificate,
        certificates: Some(vec![cert_with_key]),
        ..dummy_identifier()
    };

    let identifier_for_create = identifier.clone();
    let identifier_for_add_entry = identifier.clone();

    let mut identifier_repo = MockIdentifierRepository::new();
    identifier_repo
        .expect_get()
        .returning(move |_id, _relations| Ok(Some(identifier.clone())));

    let repos = make_stateful_repos(key.clone(), certificate.clone());

    let publisher = make_publisher(
        key_provider,
        key_algorithm_provider,
        repos.pub_repo,
        repos.entry_repo,
        identifier_repo,
    );

    publisher
        .create_trust_list(CreateTrustListRequest {
            name: "EU PID Providers".into(),
            role: TrustListRoleEnum::PidProvider,
            organisation_id: Uuid::new_v4().into(),
            identifier: identifier_for_create,
            key_id: Some(key.id),
            certificate_id: Some(certificate.id),
            params: None,
        })
        .await
        .unwrap();

    {
        let pub_entity = repos.stored_publication.lock().unwrap().clone().unwrap();
        assert_eq!(pub_entity.sequence_number, 1);
        let payload = decode_jws_payload(&pub_entity.content);
        assert!(payload.trusted_entities_list.is_none());
    }

    let publication = repos.stored_publication.lock().unwrap().clone().unwrap();
    let entry_id = publisher
        .add_entry(publication, identifier_for_add_entry, None)
        .await
        .unwrap();

    {
        let pub_entity = repos.stored_publication.lock().unwrap().clone().unwrap();
        assert_eq!(pub_entity.sequence_number, 2);
        let payload = decode_jws_payload(&pub_entity.content);
        assert_eq!(payload.trusted_entities_list.as_ref().unwrap().len(), 1);
        assert_eq!(
            payload.trusted_entities_list.as_ref().unwrap()[0]
                .trusted_entity_information
                .te_name[0]
                .value,
            "identifier"
        );
    }

    let entry = TrustEntry {
        id: entry_id,
        trust_list_publication_id: repos
            .stored_publication
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .id,
        ..dummy_entry(vec![])
    };
    publisher
        .update_entry(entry, Some(TrustEntryStatusEnum::Active), None)
        .await
        .unwrap();

    {
        let pub_entity = repos.stored_publication.lock().unwrap().clone().unwrap();
        assert_eq!(pub_entity.sequence_number, 3);
    }

    let entry = TrustEntry {
        id: entry_id,
        trust_list_publication_id: repos
            .stored_publication
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .id,
        ..dummy_entry(vec![])
    };
    publisher.remove_entry(entry).await.unwrap();

    {
        let pub_entity = repos.stored_publication.lock().unwrap().clone().unwrap();
        assert_eq!(pub_entity.sequence_number, 4);
        let payload = decode_jws_payload(&pub_entity.content);
        assert!(payload.trusted_entities_list.is_none());
    }

    assert_eq!(repos.stored_content.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn test_add_entry_includes_certificate_in_digital_identity() {
    let (key_provider, key_algorithm_provider, key, signing_cert, _public_key) =
        make_signing_mocks();

    let entity_pem = generate_self_signed_pem();
    let entity_cert = dummy_certificate(entity_pem);

    let identifier = Identifier {
        name: "Acme Provider".into(),
        r#type: IdentifierType::Certificate,
        certificates: Some(vec![entity_cert]),
        ..dummy_identifier()
    };
    let identifier_id = identifier.id;
    let identifier_for_add_entry = identifier.clone();

    let stored_entries: Arc<Mutex<Vec<TrustEntry>>> = Arc::new(Mutex::new(vec![]));

    let org_id = shared_types::OrganisationId::from(Uuid::new_v4());
    let pub_metadata = serde_json::to_vec(&sample_list_params()).unwrap();
    let publication = dummy_publication(TrustListRoleEnum::PidProvider, pub_metadata);

    let mut pub_repo = MockTrustListPublicationRepository::new();
    let key_for_get = key;
    let cert_for_get = signing_cert;
    pub_repo.expect_get().returning(move |id, _relations| {
        Ok(Some(TrustListPublication {
            id,
            metadata: serde_json::to_vec(&sample_list_params()).unwrap(),
            role: TrustListRoleEnum::PidProvider,
            organisation_id: org_id,
            key: Some(key_for_get.clone()),
            certificate: Some(cert_for_get.clone()),
            organisation: Some(dummy_organisation(Some(org_id))),
            ..dummy_publication(TrustListRoleEnum::PidProvider, vec![])
        }))
    });
    pub_repo.expect_update().returning(|_, _| Ok(()));

    let mut entry_repo = MockTrustEntryRepository::new();
    let se = stored_entries.clone();
    entry_repo.expect_create().returning(move |entry| {
        let id = entry.id;
        se.lock().unwrap().push(entry);
        Ok(id)
    });
    let se = stored_entries.clone();
    entry_repo.expect_list().returning(move |_, _| {
        Ok(GetListResponse {
            values: se.lock().unwrap().clone(),
            total_pages: 1,
            total_items: 0,
        })
    });

    let mut identifier_repo = MockIdentifierRepository::new();
    identifier_repo
        .expect_get()
        .returning(move |_id, _relations| Ok(Some(identifier.clone())));

    let publisher = make_publisher(
        key_provider,
        key_algorithm_provider,
        pub_repo,
        entry_repo,
        identifier_repo,
    );

    publisher
        .add_entry(publication, identifier_for_add_entry, None)
        .await
        .unwrap();

    let entries = stored_entries.lock().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].identifier_id, identifier_id);

    let stored_params: AddEntryParams = serde_json::from_slice(&entries[0].metadata).unwrap();
    assert!(stored_params.entity.name.is_none());
    assert!(stored_params.service.name.is_none());
}

#[test]
fn test_build_trusted_entity_with_params() {
    let identifier = Identifier {
        name: "Default Name".into(),
        r#type: IdentifierType::Certificate,
        certificates: Some(vec![dummy_certificate(generate_self_signed_pem())]),
        ..dummy_identifier()
    };

    let params = AddEntryParams::try_from(json!({
        "entity": {
            "name": [{"lang": "de", "value": "Benutzerdefinierter Name"}],
            "tradeName": [{"lang": "en", "value": "ACME Corp"}],
            "informationUri": [{"lang": "en", "uriValue": "https://example.com/info"}]
        },
        "service": {
            "name": [{"lang": "de", "value": "Eigener Dienstname"}],
            "supplyPoints": [{"uriValue": "https://example.com/api"}]
        }
    }))
    .unwrap();

    let entity = build_trusted_entity(&LoTEType::EuPidProvidersList, &identifier, &params).unwrap();

    assert_eq!(entity.trusted_entity_information.te_name[0].lang, "de");
    assert_eq!(
        entity.trusted_entity_information.te_name[0].value,
        "Benutzerdefinierter Name"
    );
    assert_eq!(
        entity
            .trusted_entity_information
            .te_trade_name
            .as_ref()
            .unwrap()[0]
            .value,
        "ACME Corp"
    );
    assert_eq!(
        entity
            .trusted_entity_information
            .te_information_uri
            .as_ref()
            .unwrap()[0]
            .uri_value,
        "https://example.com/info"
    );
    assert_eq!(
        entity.trusted_entity_services[0]
            .service_information
            .service_name[0]
            .value,
        "Eigener Dienstname"
    );
    assert!(
        entity.trusted_entity_services[0]
            .service_information
            .service_status
            .is_none()
    );
    assert_eq!(
        entity.trusted_entity_services[0]
            .service_information
            .service_supply_points
            .as_ref()
            .unwrap()[0]
            .uri_value,
        "https://example.com/api"
    );
    assert!(
        entity.trusted_entity_services[0]
            .service_information
            .service_type_identifier
            .contains("PID/Issuance")
    );
    assert!(
        entity.trusted_entity_services[0]
            .service_information
            .service_digital_identity
            .is_some()
    );
}

#[tokio::test]
async fn test_create_trust_list_with_params_enriches_scheme_info() {
    let (key_provider, key_algorithm_provider, key, certificate, _) = make_signing_mocks();

    let mut cert_with_key = certificate.clone();
    cert_with_key.key = Some(key.clone());

    let identifier = Identifier {
        r#type: IdentifierType::Certificate,
        certificates: Some(vec![cert_with_key]),
        ..dummy_identifier()
    };

    let identifier_for_create = identifier.clone();

    let mut identifier_repo = MockIdentifierRepository::new();
    identifier_repo
        .expect_get()
        .returning(move |_id, _relations| Ok(Some(identifier.clone())));

    let repos = make_stateful_repos(key.clone(), certificate.clone());

    let publisher = make_publisher(
        key_provider,
        key_algorithm_provider,
        repos.pub_repo,
        repos.entry_repo,
        identifier_repo,
    );

    let params = json!({
        "schemeOperatorName": [{"lang": "de", "value": "Betreiber GmbH"}],
        "schemeName": [{"lang": "de", "value": "EU PID Anbieterliste"}],
        "schemeTerritory": "DE",
        "schemeInformationUri": [{"lang": "en", "uriValue": "https://example.com/info"}],
        "distributionPoints": ["https://example.com/dist"],
        "historicalInformationPeriod": 365
    });

    publisher
        .create_trust_list(CreateTrustListRequest {
            name: "Test List".into(),
            role: TrustListRoleEnum::PidProvider,
            organisation_id: Uuid::new_v4().into(),
            identifier: identifier_for_create,
            key_id: Some(key.id),
            certificate_id: Some(certificate.id),
            params: Some(params),
        })
        .await
        .unwrap();

    let pub_entity = repos.stored_publication.lock().unwrap().clone().unwrap();

    let stored_params: dto::CreateTrustListParams =
        serde_json::from_slice(&pub_entity.metadata).unwrap();
    assert_eq!(
        stored_params.scheme_operator_name.as_ref().unwrap()[0].value,
        "Betreiber GmbH"
    );
    assert_eq!(stored_params.scheme_territory.as_deref().unwrap(), "DE");

    let payload = decode_jws_payload(&pub_entity.content);
    let info = &payload.list_and_scheme_information;
    assert_eq!(info.scheme_operator_name[0].lang, "de");
    assert_eq!(info.scheme_operator_name[0].value, "Betreiber GmbH");
    assert_eq!(info.scheme_territory, "DE");
    assert_eq!(info.lote_type, Some(LoTEType::EuPidProvidersList));
    assert!(info.status_determination_approach.contains("PID"));
    assert!(info.scheme_type_community_rules.is_some());

    let scheme_name = info.scheme_name.as_ref().unwrap();
    assert_eq!(scheme_name[0].lang, "de");
    assert_eq!(scheme_name[0].value, "EU PID Anbieterliste");

    let info_uri = info.scheme_information_uri.as_ref().unwrap();
    assert_eq!(info_uri[0].uri_value, "https://example.com/info");

    let dist = info.distribution_points.as_ref().unwrap();
    assert_eq!(dist[0], "https://example.com/dist");

    assert_eq!(info.historical_information_period.unwrap(), 365);
}

#[tokio::test]
async fn test_generate_trust_list_content_returns_fresh_content() {
    let (key_provider, key_algorithm_provider, key, certificate, _) = make_signing_mocks();

    let mut cert_with_key = certificate.clone();
    cert_with_key.key = Some(key.clone());

    let identifier = Identifier {
        r#type: IdentifierType::Certificate,
        certificates: Some(vec![cert_with_key]),
        ..dummy_identifier()
    };

    let identifier_for_create = identifier.clone();

    let mut identifier_repo = MockIdentifierRepository::new();
    identifier_repo
        .expect_get()
        .returning(move |_id, _relations| Ok(Some(identifier.clone())));

    let repos = make_stateful_repos(key.clone(), certificate.clone());

    let publisher = make_publisher(
        key_provider,
        key_algorithm_provider,
        repos.pub_repo,
        repos.entry_repo,
        identifier_repo,
    );

    publisher
        .create_trust_list(CreateTrustListRequest {
            name: "Test List".into(),
            role: TrustListRoleEnum::PidProvider,
            organisation_id: Uuid::new_v4().into(),
            identifier: identifier_for_create,
            key_id: Some(key.id),
            certificate_id: Some(certificate.id),
            params: None,
        })
        .await
        .unwrap();

    let initial_seq = repos
        .stored_publication
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .sequence_number;

    let publication = repos.stored_publication.lock().unwrap().clone().unwrap();
    let jwt = publisher
        .generate_trust_list_content(publication)
        .await
        .unwrap();
    assert!(!jwt.is_empty());
    assert_eq!(jwt.split('.').count(), 3);

    let final_seq = repos
        .stored_publication
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .sequence_number;
    assert_eq!(initial_seq, final_seq, "should not have re-signed");
}

#[tokio::test]
async fn test_generate_trust_list_content_resigns_stale_content() {
    let (key_provider, key_algorithm_provider, key, certificate, _) = make_signing_mocks();

    let mut cert_with_key = certificate.clone();
    cert_with_key.key = Some(key.clone());

    let identifier = Identifier {
        r#type: IdentifierType::Certificate,
        certificates: Some(vec![cert_with_key]),
        ..dummy_identifier()
    };
    let identifier_for_create = identifier.clone();

    let mut identifier_repo = MockIdentifierRepository::new();
    identifier_repo
        .expect_get()
        .returning(move |_id, _relations| Ok(Some(identifier.clone())));

    let repos = make_stateful_repos(key.clone(), certificate.clone());

    let publisher = make_publisher(
        key_provider,
        key_algorithm_provider,
        repos.pub_repo,
        repos.entry_repo,
        identifier_repo,
    );

    publisher
        .create_trust_list(CreateTrustListRequest {
            name: "Test List".into(),
            role: TrustListRoleEnum::PidProvider,
            organisation_id: Uuid::new_v4().into(),
            identifier: identifier_for_create,
            key_id: Some(key.id),
            certificate_id: Some(certificate.id),
            params: None,
        })
        .await
        .unwrap();

    let seq_after_create = repos
        .stored_publication
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .sequence_number;

    {
        let mut guard = repos.stored_publication.lock().unwrap();
        let pub_entity = guard.as_mut().unwrap();
        pub_entity.last_modified = datetime!(2020-01-01 0:00 UTC);
    }

    let publication = repos.stored_publication.lock().unwrap().clone().unwrap();
    let jwt = publisher
        .generate_trust_list_content(publication)
        .await
        .unwrap();
    assert!(!jwt.is_empty());
    assert_eq!(jwt.split('.').count(), 3);

    let seq_after_get = repos
        .stored_publication
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .sequence_number;
    assert_eq!(
        seq_after_get,
        seq_after_create + 1,
        "should have re-signed (sequence incremented)"
    );
}

#[tokio::test]
async fn test_sign_jades_compact_structure() {
    use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
    use standardized_types::jades::JadesHeader;

    let payload = b"test payload";
    let fake_signature = b"fake-sig-bytes";

    let mut mock_signer = MockSignatureProvider::new();
    mock_signer
        .expect_sign()
        .returning(|_| Ok(fake_signature.to_vec()));
    mock_signer
        .expect_jose_alg()
        .returning(|| Some("ES256".to_string()));

    let cert1 = ct_codecs::Base64::encode_to_string(b"fake-cert-1-der-bytes").unwrap();
    let cert2 = ct_codecs::Base64::encode_to_string(b"fake-cert-2-der-bytes").unwrap();
    let x5c = vec![cert1.clone(), cert2.clone()];

    let now = datetime!(2025-06-15 12:00 UTC);
    let result = super::sign_jades_compact(payload, &mock_signer, x5c, now)
        .await
        .unwrap();

    let jws = String::from_utf8(result).unwrap();
    let mut parts = jws.splitn(3, '.');
    let header_part = parts.next().unwrap();
    let payload_part = parts.next().unwrap();
    let signature_part = parts.next().unwrap();

    let header: JadesHeader =
        serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(header_part, None).unwrap())
            .unwrap();
    assert_eq!(header.alg, "ES256");
    assert_eq!(header.typ, "JOSE");
    assert!(header.crit.is_empty());
    assert_eq!(header.iat, now.unix_timestamp());
    assert_eq!(header.x5c, vec![cert1, cert2]);
    assert!(header.x5t_s256.is_some());

    let decoded_payload = Base64UrlSafeNoPadding::decode_to_vec(payload_part, None).unwrap();
    assert_eq!(decoded_payload, payload);
    let decoded_sig = Base64UrlSafeNoPadding::decode_to_vec(signature_part, None).unwrap();
    assert_eq!(decoded_sig, fake_signature);
}
