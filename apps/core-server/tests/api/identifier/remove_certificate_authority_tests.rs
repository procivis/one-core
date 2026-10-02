use one_core::model::history::HistoryAction;
use serde_json::json;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::ecdsa_testing_params;

async fn create_two_ca_cert_identifier(
    context: &TestContext,
    organisation: &one_core::model::organisation::Organisation,
) -> (shared_types::IdentifierId, Vec<shared_types::CertificateId>) {
    let key = context
        .db
        .keys
        .create(organisation, ecdsa_testing_params())
        .await;

    let create_result = context
        .api
        .identifiers
        .create_certificate_authority_identifier_self_signed(
            "ca-identifier",
            key.id,
            organisation.id,
            "root CA",
            "X509_CERTIFICATE",
            None,
        )
        .await;
    assert_eq!(create_result.status(), 201);
    let resp = create_result.json_value().await;
    let identifier_id: shared_types::IdentifierId = resp["id"].as_str().unwrap().parse().unwrap();

    let get_result = context.api.identifiers.get(&identifier_id).await;
    let resp = get_result.json_value().await;
    let first_certificate_id: shared_types::CertificateId = resp["certificateAuthorities"][0]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let second_key = context
        .db
        .keys
        .create(organisation, ecdsa_testing_params())
        .await;

    let add_result = context
        .api
        .identifiers
        .add_certificate_authorities(
            &identifier_id,
            json!([{
                "keyId": second_key.id,
                "selfSigned": {
                    "content": {
                        "subject": {
                            "commonName": "second root CA"
                        }
                    },
                    "signer": "X509_CERTIFICATE"
                }
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

#[tokio::test(flavor = "multi_thread")]
async fn test_remove_certificate_authority_success() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let (identifier_id, certificate_ids) =
        create_two_ca_cert_identifier(&context, &organisation).await;
    let certificate_id = certificate_ids[1];

    // when
    let result = context
        .api
        .identifiers
        .delete_certificate_authority(&identifier_id, &certificate_id)
        .await;

    // then
    assert_eq!(result.status(), 204);

    let certificate = context.db.certificates.get(certificate_id).await;
    assert!(certificate.deleted_at.is_some());

    // deleted certificate authorities are still returned (soft delete keeps them
    // referenceable), only `deletedAt` on the DB record changes
    let get_result = context.api.identifiers.get(&identifier_id).await;
    let resp = get_result.json_value().await;
    let certificate_authorities: Vec<_> = resp["certificateAuthorities"]
        .as_array()
        .unwrap()
        .to_owned();
    assert_eq!(certificate_authorities.len(), 2);
    assert!(
        certificate_authorities
            .iter()
            .any(|c| c["id"].as_str().unwrap() == certificate_id.to_string())
    );

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

#[tokio::test(flavor = "multi_thread")]
async fn test_remove_last_certificate_authority_fails() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let (identifier_id, certificate_ids) =
        create_two_ca_cert_identifier(&context, &organisation).await;

    let result = context
        .api
        .identifiers
        .delete_certificate_authority(&identifier_id, &certificate_ids[1])
        .await;
    assert_eq!(result.status(), 204);

    // when
    let result = context
        .api
        .identifiers
        .delete_certificate_authority(&identifier_id, &certificate_ids[0])
        .await;

    // then
    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0515");
}
