use std::ops::Add;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_core::model::certificate::{Certificate, CertificateRole, CertificateState};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use rcgen::CertificateParams;
use serde_json::{Value, json};
use shared_types::{CertificateId, IdentifierId, KeyId};
use similar_asserts::assert_eq;
use time::Duration;

use crate::fixtures::TestingIdentifierParams;
use crate::fixtures::certificate::{create_ca_cert, ecdsa};
use crate::fixtures::signature::test_access_certificate_payload;
use crate::utils::api_clients::signatures::TestCreateSignatureRequest;
use crate::utils::context::TestContext;
use crate::utils::db_clients::certificates::TestingCertificateParams;
use crate::utils::db_clients::keys::eddsa_testing_params;

const FINAL_RP: &str = "VATBE-0000000001";
const OTHER_FINAL_RP: &str = "VATBE-0000000002";
const INTERMEDIARY: &str = "VATBE-0000000003";
const UNRELATED: &str = "VATBE-0000000004";

struct Setup {
    provider: TestContext,
    registration_certificate_provider: Identifier,
    registration_certificate_key: Key,
    access_certificate_provider: Identifier,
    relying_party: TestContext,
    relying_party_organisation: Organisation,
    access_certificate_key: KeyId,
}

async fn setup() -> Setup {
    let (provider, organisation, registration_certificate_provider, _, key) =
        TestContext::new_with_certificate_identifier(None).await;

    let mut ca_params = CertificateParams::default();
    let (ca_cert, _) = create_ca_cert(&mut ca_params, ecdsa::Key);
    let identifier_id = IdentifierId::new();
    let now = one_core::clock::now_utc();
    let certificate = Certificate {
        id: CertificateId::new(),
        identifier_id,
        organisation: organisation.clone().into(),
        created_date: now,
        last_modified: now,
        expiry_date: now.add(Duration::minutes(10)),
        name: "access certificate provider".to_string(),
        chain: ca_cert.pem(),
        fingerprint: "ccccdddd".to_string(),
        state: CertificateState::Active,
        roles: vec![
            CertificateRole::Authentication,
            CertificateRole::AssertionMethod,
        ],
        key: Some(key.clone().into()),
        deleted_at: None,
    };
    let access_certificate_provider = provider
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::CertificateAuthority),
                certificates: Some(vec![certificate.clone()]),
                ..Default::default()
            },
        )
        .await;
    provider
        .db
        .certificates
        .create(
            access_certificate_provider.id,
            organisation.clone(),
            TestingCertificateParams::from(certificate).await,
        )
        .await;

    let (relying_party, relying_party_organisation) =
        TestContext::new_with_organisation(None).await;
    let access_certificate_key = relying_party
        .db
        .keys
        .create(&relying_party_organisation, eddsa_testing_params())
        .await
        .id;

    Setup {
        provider,
        registration_certificate_provider,
        registration_certificate_key: key,
        access_certificate_provider,
        relying_party,
        relying_party_organisation,
        access_certificate_key,
    }
}

async fn identifier_with_access_certificate(setup: &Setup, relying_party_id: &str) -> IdentifierId {
    let mut data = test_access_certificate_payload(Some("LEGAL_PERSON".to_string()));
    data["organizationIdentifier"] = json!(relying_party_id);

    let response = setup
        .provider
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: setup.access_certificate_provider.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "ACCESS_CERTIFICATE".to_string(),
                data,
                validity_start: None,
                validity_end: None,
            },
            None,
        )
        .await;
    assert_eq!(response.status(), 201);
    let signature = response.json_value().await;

    let response = setup
        .relying_party
        .api
        .identifiers
        .create_certificate_identifier(
            &format!("identifier-{relying_party_id}"),
            setup.access_certificate_key,
            setup.relying_party_organisation.id,
            signature["result"].as_str().unwrap(),
            &["AUTHENTICATION"],
        )
        .await;
    assert_eq!(response.status(), 201);
    let identifier = response.json_value().await;
    identifier["id"].as_str().unwrap().parse().unwrap()
}

fn registration_certificate_request(subject: &str, intermediary: Option<&str>) -> Value {
    let mut data = json!({
        "name": format!("Relying party {subject}"),
        "sub": { "legal_name": "Relying party Ltd.", "id": subject },
        "country": "BE",
        "registry_uri": "https://wallet-relying-party-registry.example",
        "service": [{ "lang": "de", "value": "Dienst" }],
        "entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
        "privacy_policy": [{
            "type": "http://data.europa.eu/eudi/policy/privacy-policy",
            "policyURI": "https://example.com/privacy-policy"
        }],
        "info_uri": "https://example.com/info",
        "dpa": {
            "email": "reports@supervisory-authority.example",
            "phone": "+15555555",
            "uri": "https://supervisory-authority.example"
        },
        "policy_id": ["0.4.0.19475.3.1"],
        "certificate_policy": "https://registrar.example.com/certificate-policy",
        "provided_attestations": [],
        "credentials": [],
        "purpose": [],
        "intended_use_id": "intended-use",
        "public_body": false,
        "support_uri": "https://example.com/support"
    });
    if let Some(intermediary) = intermediary {
        data["act"] = json!({ "sub": intermediary });
    }
    data
}

async fn sign_registration_certificate(
    setup: &Setup,
    subject: &str,
    intermediary: Option<&str>,
) -> String {
    let response = setup
        .provider
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: setup.registration_certificate_provider.id,
                issuer_key: Some(setup.registration_certificate_key.id),
                issuer_certificate: None,
                signer: "REGISTRATION_CERTIFICATE".to_string(),
                data: registration_certificate_request(subject, intermediary),
                validity_start: None,
                validity_end: None,
            },
            None,
        )
        .await;
    assert_eq!(response.status(), 201);
    let signature = response.json_value().await;
    signature["result"].as_str().unwrap().to_string()
}

fn trust_information(certificates: &[&str]) -> Value {
    let entries: Vec<Value> = certificates
        .iter()
        .map(|data| json!({ "data": data, "type": "REGISTRATION_CERTIFICATE" }))
        .collect();
    json!({ "trustInformation": entries })
}

fn decode_claims(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).unwrap();
    let decoded = Base64UrlSafeNoPadding::decode_to_vec(payload, None).unwrap();
    serde_json::from_slice(&decoded).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_signed_registration_certificate_carries_final_rp_and_intermediary() {
    let setup = setup().await;

    let jwt = sign_registration_certificate(&setup, FINAL_RP, Some(INTERMEDIARY)).await;

    let claims = decode_claims(&jwt);
    assert_eq!(claims["sub"], FINAL_RP);
    assert_eq!(claims["intermediary"]["sub"], INTERMEDIARY);
    assert!(claims.get("act").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_intermediary_access_certificate_accepts_signed_registration_certificate() {
    let setup = setup().await;
    let identifier = identifier_with_access_certificate(&setup, INTERMEDIARY).await;
    let jwt = sign_registration_certificate(&setup, FINAL_RP, Some(INTERMEDIARY)).await;

    let response = setup
        .relying_party
        .api
        .identifiers
        .patch(&identifier, trust_information(&[&jwt]))
        .await;

    assert_eq!(response.status(), 204);
    let identifier = setup
        .relying_party
        .api
        .identifiers
        .get(&identifier)
        .await
        .json_value()
        .await;
    assert_eq!(identifier["trustInformation"].as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_intermediary_can_serve_multiple_final_relying_parties() {
    let setup = setup().await;
    let identifier = identifier_with_access_certificate(&setup, INTERMEDIARY).await;
    let first = sign_registration_certificate(&setup, FINAL_RP, Some(INTERMEDIARY)).await;
    let second = sign_registration_certificate(&setup, OTHER_FINAL_RP, Some(INTERMEDIARY)).await;

    let response = setup
        .relying_party
        .api
        .identifiers
        .patch(&identifier, trust_information(&[&first, &second]))
        .await;

    assert_eq!(response.status(), 204);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_final_rp_access_certificate_accepts_certificate_naming_intermediary() {
    let setup = setup().await;
    let identifier = identifier_with_access_certificate(&setup, FINAL_RP).await;
    let jwt = sign_registration_certificate(&setup, FINAL_RP, Some(INTERMEDIARY)).await;

    let response = setup
        .relying_party
        .api
        .identifiers
        .patch(&identifier, trust_information(&[&jwt]))
        .await;

    assert_eq!(response.status(), 204);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unrelated_access_certificate_rejects_signed_registration_certificate() {
    let setup = setup().await;
    let identifier = identifier_with_access_certificate(&setup, UNRELATED).await;
    let jwt = sign_registration_certificate(&setup, FINAL_RP, Some(INTERMEDIARY)).await;

    let response = setup
        .relying_party
        .api
        .identifiers
        .patch(&identifier, trust_information(&[&jwt]))
        .await;

    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code().await, "BR_0416");
}
