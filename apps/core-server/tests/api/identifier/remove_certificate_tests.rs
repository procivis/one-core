use one_core::model::history::HistoryAction;
use rcgen::CertificateParams;
use similar_asserts::assert_eq;

use crate::fixtures::certificate::{create_ca_cert, create_cert, ecdsa, eddsa};
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::{ecdsa_testing_params, eddsa_testing_params};

async fn create_two_cert_identifier(
    context: &TestContext,
    organisation: &one_core::model::organisation::Organisation,
    name: &str,
) -> (shared_types::IdentifierId, Vec<shared_types::CertificateId>) {
    let key = context
        .db
        .keys
        .create(organisation, ecdsa_testing_params())
        .await;

    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);
    let cert = create_cert(
        &mut CertificateParams::default(),
        ecdsa::Key,
        &ca_issuer,
        &ca_params,
    );
    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    let create_result = context
        .api
        .identifiers
        .create_certificate_identifier(name, key.id, organisation.id, &chain, &["ASSERTION_METHOD"])
        .await;
    assert_eq!(create_result.status(), 201);
    let resp = create_result.json_value().await;
    let identifier_id: shared_types::IdentifierId = resp["id"].as_str().unwrap().parse().unwrap();

    let get_result = context.api.identifiers.get(&identifier_id).await;
    let resp = get_result.json_value().await;
    let first_certificate_id: shared_types::CertificateId = resp["certificates"][0]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let second_key = context
        .db
        .keys
        .create(organisation, eddsa_testing_params())
        .await;
    let second_cert = create_cert(
        &mut CertificateParams::default(),
        eddsa::Key,
        &ca_issuer,
        &ca_params,
    );
    let second_chain = format!("{}{}", second_cert.pem(), ca_cert.pem());

    let add_result = context
        .api
        .identifiers
        .add_certificates(
            &identifier_id,
            serde_json::json!([{
                "name": "second-cert",
                "chain": second_chain,
                "keyId": second_key.id,
                "roles": ["AUTHENTICATION"]
            }]),
        )
        .await;
    assert_eq!(add_result.status(), 201);
    let resp = add_result.json_value().await;
    let second_certificate_id: shared_types::CertificateId =
        resp["ids"][0].as_str().unwrap().parse().unwrap();

    (
        identifier_id,
        vec![first_certificate_id, second_certificate_id],
    )
}

#[tokio::test]
async fn test_remove_certificate_success() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let (identifier_id, certificate_ids) =
        create_two_cert_identifier(&context, &organisation, "test-identifier").await;
    let certificate_id = certificate_ids[1];

    // when
    let result = context
        .api
        .identifiers
        .delete_certificate(&identifier_id, &certificate_id)
        .await;

    // then
    assert_eq!(result.status(), 204);

    let certificate = context.db.certificates.get(certificate_id).await;
    assert!(certificate.deleted_at.is_some());

    // Identifier details only include certificates that have not been deleted.
    let get_result = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(get_result.status(), 200);
    let resp = get_result.json_value().await;
    let certificates: Vec<_> = resp["certificates"].as_array().unwrap().to_owned();
    assert_eq!(certificates.len(), 1);
    assert_eq!(certificates[0]["id"], certificate_ids[0].to_string());

    let cert_history = context
        .db
        .histories
        .get_by_entity_id(&certificate_id.into())
        .await;
    assert!(
        cert_history
            .values
            .iter()
            .any(|h| h.action == HistoryAction::Deleted)
    );

    let identifier_history = context
        .db
        .histories
        .get_by_entity_id(&identifier_id.into())
        .await;
    assert!(
        identifier_history
            .values
            .iter()
            .any(|h| h.action == HistoryAction::Updated)
    );
}

#[tokio::test]
async fn test_remove_last_certificate_fails() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let (identifier_id, certificate_ids) =
        create_two_cert_identifier(&context, &organisation, "test-identifier").await;

    let result = context
        .api
        .identifiers
        .delete_certificate(&identifier_id, &certificate_ids[1])
        .await;
    assert_eq!(result.status(), 204);

    // when
    let result = context
        .api
        .identifiers
        .delete_certificate(&identifier_id, &certificate_ids[0])
        .await;

    // then
    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0515");
}

#[tokio::test]
async fn test_remove_certificate_not_found() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let (identifier_id, _) =
        create_two_cert_identifier(&context, &organisation, "test-identifier").await;

    // when: deleting a certificate id that does not belong to this (or any) identifier
    let foreign_certificate_id: shared_types::CertificateId = uuid::Uuid::new_v4().into();
    let result = context
        .api
        .identifiers
        .delete_certificate(&identifier_id, &foreign_certificate_id)
        .await;

    // then
    assert_eq!(result.status(), 404);
}
