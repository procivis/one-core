use std::ops::Sub;

use axum::http::Method;
use one_core::model::blob::BlobType;
use one_core::model::certificate::CertificateState;
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::identifier::{IdentifierState, IdentifierType};
use one_core::model::proof::ProofStateEnum;
use one_core::model::revocation_list::{RevocationListPurpose, StatusListType};
use one_core::proto::jwt::mapper::{bin_to_b64url_string, string_to_b64url_string};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::task::certificate_check::dto::CertificateCheckResultDTO;
use one_crypto::Signer;
use one_crypto::signer::eddsa::{EDDSASigner, KeyPair};
use serde_json::json;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::fixtures::{TestingCredentialParams, TestingDidParams, TestingIdentifierParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::certificates::TestingCertificateParams;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::db_clients::keys::eddsa_testing_params;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_run_task_suspend_check_no_update() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.tasks.run("SUSPEND_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalChecks"], 0);
    assert_eq!(resp["updatedCredentialIds"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_run_task_suspend_check_with_update() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "BITSTRINGSTATUSLIST",
            Default::default(),
        )
        .await;

    let a_while_ago = OffsetDateTime::now_utc().sub(Duration::seconds(1));

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                suspend_end_date: Some(a_while_ago),
                ..Default::default()
            },
        )
        .await;

    let revocation_list = context
        .db
        .revocation_lists
        .create(
            identifier,
            RevocationListPurpose::Suspension,
            None,
            Some(StatusListType::BitstringStatusList),
        )
        .await;

    context
        .db
        .revocation_lists
        .create_credential_entry(revocation_list.id, credential.id, 0)
        .await;

    // WHEN
    let resp = context.api.tasks.run("SUSPEND_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalChecks"], 1);
    let credentials = resp["updatedCredentialIds"].as_array().unwrap().to_owned();
    assert_eq!(credentials.len(), 1);
    assert_eq!(
        credentials.first().unwrap().as_str().unwrap(),
        credential.id.to_string()
    );

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(credential.state, CredentialStateEnum::Accepted);
    assert_eq!(credential.suspend_end_date, None);
}

#[tokio::test]
async fn test_run_retain_proof_check_no_update() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.tasks.run("RETAIN_PROOF_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_run_retain_proof_check_with_update() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_1_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![1, 2, 3, 4, 5]),
            r#type: Some(BlobType::Credential),
            ..Default::default()
        })
        .await;

    let credential_2_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![1, 2, 3, 4, 5]),
            r#type: Some(BlobType::Credential),
            ..Default::default()
        })
        .await;

    let other_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![5, 4, 3, 2, 1]),
            r#type: Some(BlobType::Credential),
            ..Default::default()
        })
        .await;

    let credential_1 = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                credential_blob_id: Some(credential_1_blob.id),
                ..Default::default()
            },
        )
        .await;

    let credential_2 = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                credential_blob_id: Some(credential_2_blob.id),
                ..Default::default()
            },
        )
        .await;

    let proof_blob_1 = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![1, 2, 3, 4, 5]),
            r#type: Some(BlobType::Proof),
            ..Default::default()
        })
        .await;

    let proof_blob_2 = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![1, 2, 3, 4, 5]),
            r#type: Some(BlobType::Proof),
            ..Default::default()
        })
        .await;

    let proof_1 = context
        .db
        .proofs
        .create(
            None,
            &identifier,
            None,
            Some(&proof_schema),
            ProofStateEnum::Accepted,
            "OPENID4VP_DRAFT20",
            None,
            verifier_key.clone(),
            Some(proof_blob_1.id),
            None,
        )
        .await;

    let proof_2 = context
        .db
        .proofs
        .create(
            None,
            &identifier,
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VP_DRAFT20",
            None,
            verifier_key,
            Some(proof_blob_2.id),
            None,
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Accepted),
                created_date: Some(get_dummy_date()),
                entity_id: Some(proof_1.id.into()),
                entity_type: Some(HistoryEntityType::Proof),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Created),
                created_date: Some(get_dummy_date()),
                entity_id: Some(proof_2.id.into()),
                entity_type: Some(HistoryEntityType::Proof),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(&proof_1.id, credential_1.claims.unwrap())
        .await;

    context
        .db
        .proofs
        .set_proof_claims(&proof_2.id, credential_2.claims.unwrap())
        .await;

    let credential_1 = context.db.credentials.get(&credential_1.id).await;
    assert!(!credential_1.claims.unwrap().is_empty());

    let credential_2 = context.db.credentials.get(&credential_2.id).await;
    assert!(!credential_2.claims.unwrap().is_empty());

    // WHEN
    let resp = context.api.tasks.run("RETAIN_PROOF_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);

    let proof = context.db.proofs.get(&proof_1.id).await;
    assert!(proof.claims.unwrap().is_empty());

    let credential = context.db.credentials.get(&credential_1.id).await;
    assert!(credential.claims.unwrap().is_empty());

    let get_credential_blob = context.db.blobs.get(&credential_1_blob.id).await;
    assert!(get_credential_blob.is_none());

    let get_proof_blob = context.db.blobs.get(&proof_blob_1.id).await;
    assert!(get_proof_blob.is_none());

    let proof = context.db.proofs.get(&proof_2.id).await;
    assert!(!proof.claims.unwrap().is_empty());

    let credential = context.db.credentials.get(&credential_2.id).await;
    assert!(!credential.claims.unwrap().is_empty());

    let get_credential_blob = context.db.blobs.get(&credential_2_blob.id).await;
    assert!(get_credential_blob.is_some());

    let get_proof_blob = context.db.blobs.get(&proof_blob_2.id).await;
    assert!(get_proof_blob.is_some());

    let get_other_blob = context.db.blobs.get(&other_blob.id).await;
    assert!(get_other_blob.is_some());
}

#[tokio::test]
async fn test_run_task_certificate_check_with_update() {
    // GIVEN
    let (context, organisation, _, _, key) = TestContext::new_with_did(None).await;

    let ok_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                state: Some(IdentifierState::Active),
                ..Default::default()
            },
        )
        .await;

    let ok_certificate = context
        .db
        .certificates
        .create(
            ok_identifier.id,
            TestingCertificateParams {
                state: Some(CertificateState::Active),
                expiry_date: Some(
                    OffsetDateTime::now_utc()
                        .checked_add(Duration::hours(1))
                        .unwrap(),
                ),
                key: Some(key.clone()),
                ..Default::default()
            },
        )
        .await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                state: Some(IdentifierState::Active),
                ..Default::default()
            },
        )
        .await;

    let expired_certificate = context
        .db
        .certificates
        .create(
            identifier.id,
            TestingCertificateParams {
                state: Some(CertificateState::Active),
                expiry_date: Some(OffsetDateTime::now_utc().sub(Duration::hours(1))),
                key: Some(key),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("CERTIFICATE_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let result: CertificateCheckResultDTO = serde_json::from_value(resp).unwrap();

    assert_eq!(result.expired_certificate_ids.len(), 1);
    assert_eq!(result.expired_certificate_ids[0], expired_certificate.id);
    assert_eq!(result.deactivated_identifier_ids.len(), 1);
    assert_eq!(result.deactivated_identifier_ids[0], identifier.id);
    assert_eq!(result.revoked_certificate_ids.len(), 0);
    assert_eq!(result.check_failures.len(), 1);
    assert_eq!(result.check_failures[0].certificate_id, ok_certificate.id);

    let expired_certificate = context.db.certificates.get(expired_certificate.id).await;
    assert_eq!(expired_certificate.state, CertificateState::Expired);

    let identifier = context.db.identifiers.get(identifier.id).await;
    assert_eq!(identifier.state, IdentifierState::Deactivated);

    let certificate_history = context
        .db
        .histories
        .get_by_entity_id(&expired_certificate.id.into())
        .await;
    assert!(
        certificate_history
            .values
            .iter()
            .any(|history| history.action == HistoryAction::Expired)
    );

    let identifier_history = context
        .db
        .histories
        .get_by_entity_id(&identifier.id.into())
        .await;
    assert!(
        identifier_history
            .values
            .iter()
            .any(|history| history.action == HistoryAction::Deactivated)
    );
}

#[tokio::test]
async fn test_run_task_holder_check_credential_status_with_no_params() {
    // GIVEN
    let key_pair = EDDSASigner::generate_key_pair();
    let issuer_did = format!(
        "did:key:{}",
        Eddsa
            .reconstruct_key(&key_pair.public, None, None)
            .unwrap()
            .signature()
            .unwrap()
            .public()
            .as_multibase()
            .unwrap()
    );

    let mock_server = MockServer::builder().start().await;
    let base_url = mock_server.uri();
    let jwt_header = json!({
      "alg": "EDDSA",
      "typ": "JWT"
    });
    let credential_payload = json!({
      "iat": 1707409689,
      "exp": 1770481689,
      "nbf": 1707409629,
      "iss": issuer_did,
      "sub": "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe",
      "jti": "88fb9ad2-efe0-4ade-8251-2b39786490af",
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1"
        ],
        "type": [
          "VerifiableCredential"
        ],
        "id": format!("{base_url}/api/credential/v1/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf"),
        "credentialSubject": {
          "age": "55"
        },
        "credentialStatus": {
          "id":  format!("{base_url}/ssi/revocation/v1/lvvc/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf"),
          "type": "LVVC"
        }
      }
    });

    let lvvc_payload = json!({
      "iat": 1707409689,
      "exp": 1770481689,
      "nbf": 1707409629,
      "iss": issuer_did,
      "sub": "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe",
      "jti": "88fb9ad2-efe0-4ade-8251-2b39786490af",
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1"
        ],
        "type": [
          "VerifiableCredential"
        ],
        "id": format!("{base_url}/ssi/revocation/v1/lvvc/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf"),
        "credentialSubject": {
          "id": format!("{base_url}/api/credential/v1/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf"),
          "status": "ACCEPTED"
        }
      }
    });

    let credential_jwt = sign_jwt_helper(
        &jwt_header.to_string(),
        &credential_payload.to_string(),
        &key_pair,
    );
    let lvvc_credential_jwt = sign_jwt_helper(
        &jwt_header.to_string(),
        &lvvc_payload.to_string(),
        &key_pair,
    );

    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let holder_key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
                did: Some(
                    "did:key:z6MkktrwmJpuMHHkkqY3g5xUP6KKB1eXxLo6KZDZ5LpfBhrc"
                        .parse()
                        .unwrap(),
                ),
                did_type: Some(DidType::Local),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: holder_key,
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let holder_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
                did: Some(
                    "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe"
                        .parse()
                        .unwrap(),
                ),
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let issuer_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "LVVC", Default::default())
        .await;

    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(credential_jwt.as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended,
            &issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                holder_identifier: Some(holder_identifier),
                role: Some(CredentialRole::Holder),
                credential_blob_id: Some(blob.id),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create(
            issuer_identifier,
            RevocationListPurpose::Revocation,
            None,
            None,
        )
        .await;

    Mock::given(method(Method::GET))
        .and(path(
            "/ssi/revocation/v1/lvvc/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential": lvvc_credential_jwt,
            "format": "JWT"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let history_previous = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;

    // WHEN
    let resp = context
        .api
        .tasks
        .run("HOLDER_CHECK_CREDENTIAL_STATUS")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(json!(1), resp["totalChecks"]);

    let history = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;
    // unsuspend added two new history entries
    assert_eq!(history.values.len(), history_previous.values.len() + 2);
    // Within the first two entries there needs to be one Reactivated and one Accepted
    assert!(
        history
            .values
            .iter()
            .take(2)
            .any(|x| x.action == HistoryAction::Accepted)
    );
    assert!(
        history
            .values
            .iter()
            .take(2)
            .any(|x| x.action == HistoryAction::Reactivated)
    );
}

#[tokio::test]
async fn test_run_task_holder_check_credential_status_with_params_none_existing_organisation() {
    // GIVEN
    let key_pair = EDDSASigner::generate_key_pair();
    let issuer_did = format!(
        "did:key:{}",
        Eddsa
            .reconstruct_key(&key_pair.public, None, None)
            .unwrap()
            .signature()
            .unwrap()
            .public()
            .as_multibase()
            .unwrap()
    );

    let mock_server = MockServer::builder().start().await;
    let base_url = mock_server.uri();
    let jwt_header = json!({
      "alg": "EDDSA",
      "typ": "JWT"
    });
    let credential_payload = json!({
      "iat": 1707409689,
      "exp": 1770481689,
      "nbf": 1707409629,
      "iss": issuer_did,
      "sub": "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe",
      "jti": "88fb9ad2-efe0-4ade-8251-2b39786490af",
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1"
        ],
        "type": [
          "VerifiableCredential"
        ],
        "id": format!("{base_url}/api/credential/v1/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf"),
        "credentialSubject": {
          "age": "55"
        },
        "credentialStatus": {
          "id":  format!("{base_url}/ssi/revocation/v1/lvvc/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf"),
          "type": "LVVC"
        }
      }
    });

    let credential_jwt = sign_jwt_helper(
        &jwt_header.to_string(),
        &credential_payload.to_string(),
        &key_pair,
    );

    let non_existing_organisation_id = Uuid::new_v4();
    let additional_config = indoc::formatdoc! {"
        task:
            HOLDER_CHECK_CREDENTIAL_STATUS:
                params:
                    public:
                        organisationId: {non_existing_organisation_id}
    "};

    let (context, organisation) = TestContext::new_with_organisation(Some(additional_config)).await;
    let holder_key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
                did: Some(
                    "did:key:z6MkktrwmJpuMHHkkqY3g5xUP6KKB1eXxLo6KZDZ5LpfBhrc"
                        .parse()
                        .unwrap(),
                ),
                did_type: Some(DidType::Local),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: holder_key,
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let holder_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
                did: Some(
                    "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe"
                        .parse()
                        .unwrap(),
                ),
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let issuer_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "LVVC", Default::default())
        .await;

    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(credential_jwt.as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended,
            &issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                credential_blob_id: Some(blob.id),
                holder_identifier: Some(holder_identifier),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create(
            issuer_identifier,
            RevocationListPurpose::Revocation,
            None,
            None,
        )
        .await;

    let history_previous = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;

    // WHEN
    let resp = context
        .api
        .tasks
        .run("HOLDER_CHECK_CREDENTIAL_STATUS")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(json!(0), resp["totalChecks"]);

    let history = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;
    // no new history entry should be added
    assert_eq!(history.values.len(), history_previous.values.len());
}

fn sign_jwt_helper(jwt_header_json: &str, payload_json: &str, key_pair: &KeyPair) -> String {
    let mut token = format!(
        "{}.{}",
        string_to_b64url_string(jwt_header_json).unwrap(),
        string_to_b64url_string(payload_json).unwrap(),
    );

    let signature = EDDSASigner {}
        .sign(token.as_bytes(), &key_pair.public, &key_pair.private)
        .unwrap();
    let signature_encoded = bin_to_b64url_string(&signature).unwrap();

    token.push('.');
    token.push_str(&signature_encoded);
    token
}
