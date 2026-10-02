use one_core::model::history::HistoryAction;
use one_core::model::identifier::{IdentifierState, IdentifierType};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyUsagePurpose};
use serde_json::json;
use similar_asserts::assert_eq;

use crate::fixtures::TestingIdentifierParams;
use crate::fixtures::certificate::{create_ca_cert, create_cert, ecdsa, eddsa};
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::{ecdsa_testing_params, eddsa_testing_params};

#[tokio::test]
async fn test_add_certificate_authority_from_pem_success() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let mut ca_params = CertificateParams::default();
    let (ca_cert, _ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);

    let mut cert_params = CertificateParams::default();
    cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cert_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = create_cert(&mut cert_params, ecdsa::Key, &_ca_issuer, &ca_params);
    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    let create_result = context
        .api
        .identifiers
        .create_certificate_authority_identifier("ca-identifier", key.id, organisation.id, &chain)
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
    let mut second_cert_params = CertificateParams::default();
    second_cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    second_cert_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let second_cert = create_cert(&mut second_cert_params, eddsa::Key, &_ca_issuer, &ca_params);
    let second_chain = format!("{}{}", second_cert.pem(), ca_cert.pem());

    // when
    let result = context
        .api
        .identifiers
        .add_certificate_authorities(
            &identifier_id,
            json!([{
                "name": "second-ca",
                "chain": second_chain,
                "keyId": second_key.id
            }]),
        )
        .await;

    // then
    assert_eq!(result.status(), 201);
    let resp = result.json_value().await;
    assert_eq!(resp["ids"].as_array().unwrap().len(), 1);

    let result = context.api.identifiers.get(&identifier_id).await;
    let resp = result.json_value().await;
    assert_eq!(resp["certificateAuthorities"].as_array().unwrap().len(), 2);

    let history = context
        .db
        .histories
        .get_by_entity_id(&identifier_id.into())
        .await;
    assert!(
        history
            .values
            .iter()
            .any(|h| h.action == HistoryAction::Updated)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_add_certificate_authority_self_signed_success() {
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
    let identifier_id: shared_types::IdentifierId = create_result.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let second_key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    // when
    let result = context
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

    // then
    assert_eq!(result.status(), 201);

    let result = context.api.identifiers.get(&identifier_id).await;
    let resp = result.json_value().await;
    assert_eq!(resp["certificateAuthorities"].as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_add_certificate_authority_reactivates_deactivated_identifier() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::CertificateAuthority),
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

    // when
    let result = context
        .api
        .identifiers
        .add_certificate_authorities(
            &identifier.id,
            json!([{
                "keyId": key.id,
                "selfSigned": {
                    "content": {
                        "subject": {
                            "commonName": "root CA"
                        }
                    },
                    "signer": "X509_CERTIFICATE"
                }
            }]),
        )
        .await;

    // then
    assert_eq!(result.status(), 201);

    let result = context.api.identifiers.get(&identifier.id).await;
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
async fn test_add_certificate_authority_wrong_identifier_type() {
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
        .add_certificate_authorities(
            &identifier_id,
            json!([{
                "keyId": key.id,
                "chain": "dummy"
            }]),
        )
        .await;

    // then
    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0514");
}
