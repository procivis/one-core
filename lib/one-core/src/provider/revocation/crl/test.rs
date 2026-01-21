use std::ops::Add;
use std::sync::{Arc, Mutex};

use mockall::predicate::{always, eq};
use shared_types::RevocationListId;
use similar_asserts::assert_eq;
use standardized_types::x509::CertificateSerial;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{CRLRevocation, Params};
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::identifier::Identifier;
use crate::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntityInfo, RevocationListEntry,
    RevocationListEntryStatus, RevocationListPurpose, StatusListCredentialFormat, StatusListType,
    UpdateRevocationListEntryId, UpdateRevocationListEntryRequest,
};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePrivateKeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::repository::revocation_list_repository::MockRevocationListRepository;
use crate::service::test_utilities::{dummy_identifier, dummy_key};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_signature_new_list() {
    let issuer = dummy_identifier();
    let certificate = dummy_ca_certificate(&issuer);

    let mut revocation_list_repository = MockRevocationListRepository::new();
    revocation_list_repository
        .expect_get_revocation_by_issuer_identifier_id()
        .once()
        .with(
            eq(issuer.id),
            eq(Some(certificate.id)),
            eq(RevocationListPurpose::Revocation),
            eq(StatusListType::Crl),
            always(),
        )
        .return_once(|_, _, _, _, _| Ok(None));

    let mut key_provider = MockKeyProvider::new();
    key_provider.expect_get_key_storage().returning(|_| {
        let mut key_storage = MockKeyStorage::new();
        key_storage.expect_key_handle().returning(|_| {
            let mut private = MockSignaturePrivateKeyHandle::new();
            private.expect_sign().return_once(|_| Ok(vec![0xab; 32]));

            Ok(KeyHandle::SignatureOnly(
                SignatureKeyHandle::WithPrivateKey {
                    private: Arc::new(private),
                    public: Arc::new(MockSignaturePublicKeyHandle::new()),
                },
            ))
        });

        Some(Arc::new(key_storage))
    });

    let list_id: Arc<Mutex<Option<RevocationListId>>> = Arc::new(Mutex::new(None));
    let formatted_list: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    revocation_list_repository
        .expect_create_revocation_list()
        .once()
        .return_once({
            let list_id = list_id.clone();
            let formatted_list = formatted_list.clone();
            move |request| {
                *formatted_list.lock().unwrap() = Some(request.formatted_list);
                *list_id.lock().unwrap() = Some(request.id);
                Ok(request.id)
            }
        });

    let serial: Arc<Mutex<Option<CertificateSerial>>> = Arc::new(Mutex::new(None));
    revocation_list_repository
        .expect_create_entry()
        .once()
        .with(always(), always(), eq(None))
        .withf({
            let list_id = list_id.clone();
            let serial = serial.clone();
            move |id, entity, _| {
                let RevocationListEntityId::Signature(_, Some(s)) = entity else {
                    return false;
                };
                *serial.lock().unwrap() = Some(s.to_owned());

                list_id.lock().unwrap().unwrap() == *id
            }
        })
        .return_once(|_, _, _| Ok(Uuid::new_v4().into()));

    let refresh_interval = Duration::seconds(10);
    let revocation_method = CRLRevocation::new(
        Some("http://base.url".to_string()),
        Arc::new(revocation_list_repository),
        Arc::new(NoTransactionManager),
        Arc::new(key_provider),
        Params { refresh_interval },
    );

    let before_adding = OffsetDateTime::now_utc().replace_millisecond(0).unwrap();

    let (_, info) = revocation_method
        .add_signature("signature_type".to_string(), &issuer, &Some(certificate))
        .await
        .unwrap();

    let after_adding = OffsetDateTime::now_utc().replace_millisecond(999).unwrap();

    let list_id = list_id.lock().unwrap().unwrap();
    let serial = serial.lock().unwrap().take().unwrap();
    let formatted_list = formatted_list.lock().unwrap().take().unwrap();

    assert_eq!(info.serial, Some(serial));
    assert_eq!(
        info.credential_status.id.unwrap().to_string(),
        format!("http://base.url/ssi/revocation/v1/crl/{list_id}")
    );

    let (_, crl) = x509_parser::parse_x509_crl(&formatted_list).unwrap();
    let last_update = crl.last_update().to_datetime();
    assert!(last_update >= before_adding);
    assert!(last_update <= after_adding);
    let next_update = crl.next_update().unwrap().to_datetime();
    assert!(next_update >= before_adding + refresh_interval);
    assert!(next_update <= after_adding + refresh_interval);

    assert_eq!(crl.iter_revoked_certificates().next(), None);
    assert_eq!(crl.crl_number(), Some(&0u32.into()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_revoke_signature() {
    let certificate = dummy_ca_certificate(&dummy_identifier());

    let signature_id = Uuid::new_v4().into();
    let list_id = Uuid::new_v4().into();

    let empty_crl = hex_literal::hex!(
        "3082011f3081f2020101300506032b6570308196311c301a06035504030c1363612e6465762e6d646c2d706c75732e636f6d310b3009060355040613024348310f300d06035504070c065a757269636831143012060355040a0c0b50726f6369766973204147311e301c060355040b0c15436572746966696361746520417574686f726974793122302006092a864886f70d0109011613737570706f72744070726f63697669732e6368170d3236303132313130343835355a170d3236303132313130343930355aa02f302d301f0603551d23041830168014e52f49b64bc82990f94b7f13ec40cf6ac2a2f870300a0603551d140403020100300506032b6570032100abababababababababababababababababababababababababababababababab"
    );

    let mut revocation_list_repository = MockRevocationListRepository::new();
    revocation_list_repository
        .expect_update_entry()
        .once()
        .with(
            eq(UpdateRevocationListEntryId::Id(signature_id)),
            eq(UpdateRevocationListEntryRequest {
                status: Some(RevocationListEntryStatus::Revoked),
            }),
        )
        .returning(|_, _| Ok(()));
    revocation_list_repository
        .expect_get_revocation_list_by_entry_id()
        .with(eq(signature_id), always())
        .return_once(move |_, _| {
            Ok(Some(RevocationList {
                id: list_id,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                formatted_list: empty_crl.into(),
                format: StatusListCredentialFormat::X509Crl,
                r#type: StatusListType::Crl,
                purpose: RevocationListPurpose::Revocation,
                issuer_identifier: None,
                issuer_certificate: Some(certificate),
            }))
        });

    let serial = CertificateSerial::new_random();
    let revocation_time = OffsetDateTime::now_utc().replace_millisecond(0).unwrap();
    revocation_list_repository
        .expect_get_entries()
        .with(eq(list_id))
        .return_once({
            let serial = serial.clone();
            move |_| {
                Ok(vec![RevocationListEntry {
                    id: signature_id,
                    created_date: revocation_time,
                    last_modified: revocation_time,
                    entity_info: RevocationListEntityInfo::Signature(
                        "type".to_string(),
                        Some(serial),
                    ),
                    index: None,
                    status: RevocationListEntryStatus::Revoked,
                }])
            }
        });

    let formatted_list: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    revocation_list_repository
        .expect_update_formatted_list()
        .once()
        .with(eq(list_id), always())
        .return_once({
            let formatted_list = formatted_list.clone();
            move |_, data| {
                *formatted_list.lock().unwrap() = Some(data);
                Ok(())
            }
        });

    let mut key_provider = MockKeyProvider::new();
    key_provider.expect_get_key_storage().returning(|_| {
        let mut key_storage = MockKeyStorage::new();
        key_storage.expect_key_handle().returning(|_| {
            let mut private = MockSignaturePrivateKeyHandle::new();
            private.expect_sign().return_once(|_| Ok(vec![0xab; 32]));

            Ok(KeyHandle::SignatureOnly(
                SignatureKeyHandle::WithPrivateKey {
                    private: Arc::new(private),
                    public: Arc::new(MockSignaturePublicKeyHandle::new()),
                },
            ))
        });

        Some(Arc::new(key_storage))
    });

    let refresh_interval = Duration::seconds(10);
    let revocation_method = CRLRevocation::new(
        Some("http://base.url".to_string()),
        Arc::new(revocation_list_repository),
        Arc::new(NoTransactionManager),
        Arc::new(key_provider),
        Params { refresh_interval },
    );

    let before_revocation = OffsetDateTime::now_utc().replace_millisecond(0).unwrap();

    revocation_method
        .revoke_signature(signature_id)
        .await
        .unwrap();

    let after_revocation = OffsetDateTime::now_utc().replace_millisecond(999).unwrap();

    let formatted_list = formatted_list.lock().unwrap().take().unwrap();

    let (_, crl) = x509_parser::parse_x509_crl(&formatted_list).unwrap();
    let last_update = crl.last_update().to_datetime();
    assert!(last_update >= before_revocation);
    assert!(last_update <= after_revocation);
    let next_update = crl.next_update().unwrap().to_datetime();
    assert!(next_update >= before_revocation + refresh_interval);
    assert!(next_update <= after_revocation + refresh_interval);

    let mut revoked_certificates = crl.iter_revoked_certificates();
    let revoked_entry = revoked_certificates.next().unwrap();
    assert_eq!(
        revoked_entry.serial().to_bytes_be(),
        Vec::<u8>::from(serial)
    );
    assert_eq!(revoked_entry.revocation_date.to_datetime(), revocation_time);
    assert_eq!(revoked_certificates.next(), None);
    assert_eq!(crl.crl_number(), Some(&1u32.into()));
}

fn dummy_ca_certificate(issuer: &Identifier) -> Certificate {
    Certificate {
        id: Uuid::new_v4().into(),
        identifier_id: issuer.id,
        organisation_id: None,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        expiry_date: OffsetDateTime::now_utc().add(Duration::minutes(10)),
        name: "test cert".to_string(),
        chain: r#"-----BEGIN CERTIFICATE-----
MIIC6jCCApCgAwIBAgIULOnT9JtSjwzSk5XUCy4lzAXgzsMwCgYIKoZIzj0EAwQw
gZYxHDAaBgNVBAMME2NhLmRldi5tZGwtcGx1cy5jb20xCzAJBgNVBAYTAkNIMQ8w
DQYDVQQHDAZadXJpY2gxFDASBgNVBAoMC1Byb2NpdmlzIEFHMR4wHAYDVQQLDBVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIjAgBgkqhkiG9w0BCQEWE3N1cHBvcnRAcHJv
Y2l2aXMuY2gwHhcNMjUwMzEzMTQzNzAwWhcNMzUwMzExMTQzNzAwWjCBljEcMBoG
A1UEAwwTY2EuZGV2Lm1kbC1wbHVzLmNvbTELMAkGA1UEBhMCQ0gxDzANBgNVBAcM
Blp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHjAcBgNVBAsMFUNlcnRpZmlj
YXRlIEF1dGhvcml0eTEiMCAGCSqGSIb3DQEJARYTc3VwcG9ydEBwcm9jaXZpcy5j
aDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC8hfYMdzhP87J1EnaaIInDNqGeb
PugTdzANq8kd2no4Xav/cyHsOVCe6FL7yYHButVR7xrmCbQip/0ctE0cdrejgbkw
gbYwDgYDVR0PAQH/BAQDAgEGMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jYS5k
ZXYubWRsLXBsdXMuY29tL2NybC8wHgYDVR0SBBcwFYITY2EuZGV2Lm1kbC1wbHVz
LmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTlL0m2S8gpkPlLfxPs
QM9qwqL4cDAfBgNVHSMEGDAWgBTlL0m2S8gpkPlLfxPsQM9qwqL4cDAKBggqhkjO
PQQDBANIADBFAiAwMs/rQEDwt0HbrAt4lvAwT3jrtqqR4BzZDQhqqh8zyAIhAKTY
qzmSNPsC3TZzs4uCBIsS3LKDZHCktmj3La1PCGSS
-----END CERTIFICATE-----
"#
        .to_string(),
        fingerprint: "fingerprint".to_string(),
        state: CertificateState::Active,
        key: Some(dummy_key()),
    }
}
