use core_server::endpoint::trust_list_publication::dto::TrustListRoleRestEnum;
use rcgen::CertificateParams;
use serde_json::json;
use shared_types::IdentifierId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::certificate::{create_ca_cert, create_cert, ecdsa, eddsa};
use crate::utils::api_clients::trust_list_publication::CreateTrustListPublicationTestParams;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

const SAMPLE_ED25519_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

fn sample_jwk() -> serde_json::Value {
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": SAMPLE_ED25519_X,
    })
}

fn sample_chain() -> String {
    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);
    let cert = create_cert(
        &mut CertificateParams::default(),
        ecdsa::Key,
        &ca_issuer,
        &ca_params,
    );
    format!("{}{}", cert.pem(), ca_cert.pem())
}

fn sample_ca_chain() -> String {
    let mut ca_params = CertificateParams::default();
    let (ca_cert, _) = create_ca_cert(&mut ca_params, &eddsa::Key);
    ca_cert.pem()
}

#[tokio::test]
async fn test_create_remote_did_identifier_success() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let resp = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "remote-did",
            "did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "organisationId": organisation.id,
        }))
        .await;

    assert_eq!(resp.status(), 201);
    let identifier_id: IdentifierId = resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let detail = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(detail.status(), 200);
    let body = detail.json_value().await;
    assert_eq!(body["name"].as_str().unwrap(), "remote-did");
    assert_eq!(body["type"].as_str().unwrap(), "DID");
    assert!(body["isRemote"].as_bool().unwrap());
}

#[tokio::test]
async fn test_create_remote_key_identifier_success() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let resp = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "remote-key",
            "key": sample_jwk(),
            "organisationId": organisation.id,
        }))
        .await;

    assert_eq!(resp.status(), 201);
    let identifier_id: IdentifierId = resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let detail = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(detail.status(), 200);
    let body = detail.json_value().await;
    assert_eq!(body["name"].as_str().unwrap(), "remote-key");
    assert_eq!(body["type"].as_str().unwrap(), "KEY");
    assert!(body["isRemote"].as_bool().unwrap());
}

#[tokio::test]
async fn test_create_remote_certificate_identifier_success() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let resp = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "remote-cert",
            "certificates": [{ "chain": sample_chain() }],
            "organisationId": organisation.id,
        }))
        .await;

    assert_eq!(resp.status(), 201);
    let identifier_id: IdentifierId = resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let detail = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(detail.status(), 200);
    let body = detail.json_value().await;
    assert_eq!(body["name"].as_str().unwrap(), "remote-cert");
    assert_eq!(body["type"].as_str().unwrap(), "CERTIFICATE");
    assert!(body["isRemote"].as_bool().unwrap());
}

#[tokio::test]
async fn test_create_remote_ca_identifier_success() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let resp = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "remote-ca",
            "certificateAuthorities": [{ "chain": sample_ca_chain() }],
            "organisationId": organisation.id,
        }))
        .await;

    assert_eq!(resp.status(), 201);
    let identifier_id: IdentifierId = resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let detail = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(detail.status(), 200);
    let body = detail.json_value().await;
    assert_eq!(body["name"].as_str().unwrap(), "remote-ca");
    assert_eq!(body["type"].as_str().unwrap(), "CA");
    assert!(body["isRemote"].as_bool().unwrap());
}

#[tokio::test]
async fn test_create_remote_ca_identifier_with_end_entity_chain_fails() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let resp = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "remote-ca",
            "certificateAuthorities": [{ "chain": sample_chain() }],
            "organisationId": organisation.id,
        }))
        .await;

    assert_eq!(resp.status(), 400);
    assert_eq!(resp.json_value().await["code"].as_str().unwrap(), "BR_0244");
}

#[tokio::test]
async fn test_create_remote_certificate_identifier_with_ca_chain_fails() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let resp = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "remote-cert",
            "certificates": [{ "chain": sample_ca_chain() }],
            "organisationId": organisation.id,
        }))
        .await;

    assert_eq!(resp.status(), 400);
    assert_eq!(resp.json_value().await["code"].as_str().unwrap(), "BR_0250");
}

#[tokio::test]
async fn test_create_remote_did_identifier_duplicate_returns_collision() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let did = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

    let first = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "first",
            "did": did,
            "organisationId": organisation.id,
        }))
        .await;
    assert_eq!(first.status(), 201);

    let second = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "second",
            "did": did,
            "organisationId": organisation.id,
        }))
        .await;

    assert_eq!(second.status(), 400);
    let body = second.json_value().await;
    assert_eq!(body["code"].as_str().unwrap(), "BR_0240");
}

#[tokio::test]
async fn test_create_remote_certificate_identifier_duplicate_chain_returns_collision() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let chain = sample_chain();

    let first = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "first-cert",
            "certificates": [{ "chain": chain.clone() }],
            "organisationId": organisation.id,
        }))
        .await;
    assert_eq!(first.status(), 201);

    let second = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "second-cert",
            "certificates": [{ "chain": chain }],
            "organisationId": organisation.id,
        }))
        .await;

    assert_eq!(second.status(), 400);
    let body = second.json_value().await;
    assert_eq!(body["code"].as_str().unwrap(), "BR_0240");
}

#[tokio::test]
async fn test_create_remote_identifier_duplicate_name_returns_collision() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let first = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "shared-name",
            "did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "organisationId": organisation.id,
        }))
        .await;
    assert_eq!(first.status(), 201);

    let second = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "shared-name",
            "did": "did:key:z6MkjvBkt8ETnxXGBFPSGgYKb43q7oNHLX8BiYSPcXVG6gY6",
            "organisationId": organisation.id,
        }))
        .await;

    assert_eq!(second.status(), 400);
    let body = second.json_value().await;
    assert_eq!(body["code"].as_str().unwrap(), "BR_0240");
}

#[tokio::test]
async fn test_create_remote_identifier_multiple_inputs_returns_400() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let resp = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "both",
            "did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "key": sample_jwk(),
            "organisationId": organisation.id,
        }))
        .await;

    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"].as_str().unwrap(), "BR_0206");
}

#[tokio::test]
async fn test_remote_certificate_identifier_can_be_added_to_trust_list_entry() {
    let (context, organisation, publisher_identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    let publication = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            identifier_id: publisher_identifier.id,
            organisation_id: organisation.id,
            name: "trust-list",
            role: TrustListRoleRestEnum::PidProvider,
            r#type: "LOTE_PUBLISHER".into(),
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;
    assert_eq!(publication.status(), 201);
    let publication_id: shared_types::TrustListPublicationId =
        publication.json_value().await["id"].parse::<Uuid>().into();

    let remote = context
        .api
        .identifiers
        .create_remote(json!({
            "name": "remote-cert-for-trust-list",
            "certificates": [{ "chain": sample_chain() }],
            "organisationId": organisation.id,
        }))
        .await;
    assert_eq!(remote.status(), 201);
    let remote_id: IdentifierId = remote.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let entry = context
        .api
        .trust_list_publication
        .create_trust_entry(publication_id, remote_id, None)
        .await;

    assert_eq!(entry.status(), 201);
    let entry_id = entry.json_value().await["id"].parse::<Uuid>().into();
    let stored = context.db.trust_entries.get(entry_id).await.unwrap();
    assert_eq!(stored.identifier.id(), remote_id);
    assert_eq!(stored.trust_list_publication.id(), publication_id);
}
