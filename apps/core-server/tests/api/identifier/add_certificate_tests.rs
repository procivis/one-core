use one_core::model::history::HistoryAction;
use one_core::model::identifier::{IdentifierState, IdentifierType};
use rcgen::CertificateParams;
use serde_json::json;
use similar_asserts::assert_eq;

use crate::fixtures::TestingIdentifierParams;
use crate::fixtures::certificate::{create_ca_cert, create_cert, ecdsa, eddsa};
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::{ecdsa_testing_params, eddsa_testing_params};

#[tokio::test]
async fn test_add_certificate_from_pem_success() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
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
        .create_certificate_identifier(
            "test-identifier",
            key.id,
            organisation.id,
            &chain,
            &["ASSERTION_METHOD"],
        )
        .await;
    assert_eq!(create_result.status(), 201);
    let identifier_id = create_result.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let second_key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;
    let second_cert = create_cert(
        &mut CertificateParams::default(),
        eddsa::Key,
        &ca_issuer,
        &ca_params,
    );
    let second_chain = format!("{}{}", second_cert.pem(), ca_cert.pem());

    // when
    let result = context
        .api
        .identifiers
        .add_certificates(
            &identifier_id,
            json!([{
                "name": "second-cert",
                "chain": second_chain,
                "keyId": second_key.id,
                "roles": ["AUTHENTICATION"]
            }]),
        )
        .await;

    // then
    assert_eq!(result.status(), 201);
    let resp = result.json_value().await;
    let ids = resp["ids"].as_array().unwrap();
    assert_eq!(ids.len(), 1);
    let new_certificate_id: shared_types::CertificateId = ids[0].as_str().unwrap().parse().unwrap();

    let result = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;
    assert_eq!(resp["certificates"].as_array().unwrap().len(), 2);

    // identifier history has an UPDATED entry (state stayed ACTIVE)
    let history = context
        .db
        .histories
        .get_by_entity_id(&identifier_id.into())
        .await;
    let actions: Vec<_> = history.values.iter().map(|h| h.action).collect();
    assert!(actions.contains(&HistoryAction::Updated));

    // certificate history has a CREATED entry
    let cert_history = context
        .db
        .histories
        .get_by_entity_id(&new_certificate_id.into())
        .await;
    assert!(
        cert_history
            .values
            .iter()
            .any(|h| h.action == HistoryAction::Created)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_add_certificate_from_content_success() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let ca_key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let ca_result = context
        .api
        .identifiers
        .create_certificate_authority_identifier_self_signed(
            "CA-identifier",
            ca_key.id,
            organisation.id,
            "CA",
            "X509_CERTIFICATE",
            None,
        )
        .await;
    assert_eq!(ca_result.status(), 201);
    let ca_identifier_id: shared_types::IdentifierId = ca_result.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let cert_key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let create_result = context
        .api
        .identifiers
        .create_certificate_identifier_ca_signed(
            "cert-identifier",
            cert_key.id,
            organisation.id,
            ca_identifier_id,
            "Cert",
            "X509_CERTIFICATE",
            "GENERIC",
            &["ASSERTION_METHOD"],
        )
        .await;
    assert_eq!(create_result.status(), 201);
    let identifier_id: shared_types::IdentifierId = create_result.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let second_key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    // when
    let result = context
        .api
        .identifiers
        .add_certificates(
            &identifier_id,
            json!([{
                "keyId": second_key.id,
                "roles": ["AUTHENTICATION"],
                "content": {
                    "certificateAuthority": {
                        "identifierId": ca_identifier_id
                    },
                    "subject": {
                        "commonName": "Second cert"
                    },
                    "profile": "GENERIC",
                    "signer": "X509_CERTIFICATE"
                }
            }]),
        )
        .await;

    // then
    assert_eq!(result.status(), 201);

    let result = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;
    assert_eq!(resp["certificates"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_add_certificate_reactivates_deactivated_identifier() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                state: Some(IdentifierState::Deactivated),
                ..Default::default()
            },
        )
        .await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
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

    // when
    let result = context
        .api
        .identifiers
        .add_certificates(
            &identifier.id,
            json!([{
                "chain": chain,
                "keyId": key.id,
                "roles": ["ASSERTION_METHOD"]
            }]),
        )
        .await;

    // then
    assert_eq!(result.status(), 201);

    let result = context.api.identifiers.get(&identifier.id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;
    assert_eq!(resp["state"].as_str().unwrap(), "ACTIVE");

    let history = context
        .db
        .histories
        .get_by_entity_id(&identifier.id.into())
        .await;
    assert!(
        history
            .values
            .iter()
            .any(|h| h.action == HistoryAction::Reactivated)
    );
}

#[tokio::test]
async fn test_add_certificate_wrong_identifier_type() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let create_result = context
        .api
        .identifiers
        .create_key_identifier("test-identifier", key.id, organisation.id)
        .await;
    assert_eq!(create_result.status(), 201);
    let identifier_id: shared_types::IdentifierId = create_result.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // when
    let result = context
        .api
        .identifiers
        .add_certificates(
            &identifier_id,
            json!([{
                "chain": "dummy",
                "keyId": key.id,
                "roles": ["ASSERTION_METHOD"]
            }]),
        )
        .await;

    // then
    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0514");
}
