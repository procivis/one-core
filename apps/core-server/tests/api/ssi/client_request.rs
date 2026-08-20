use core::str;

use core_server::endpoint::proof::dto::ClientIdSchemeRestEnum;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_core::model::blob::BlobType;
use one_core::model::identifier_trust_information::SchemaFormat;
use one_core::model::interaction::InteractionType;
use one_core::model::proof::{ProofRole, ProofStateEnum};
use serde_json::{Value, json};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures;
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::identifier_trust_information::TestingIdentifierTrustInformationParams;
use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;
use crate::utils::db_clients::proofs::TestingProofParams;

fn decode_jwt(jwt: &str) -> (Value, Value) {
    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    assert!(parts.len() >= 2, "Expected at least 2-part JWT");

    let header: Value = Base64UrlSafeNoPadding::decode_to_vec(parts[0], None)
        .ok()
        .and_then(|s| String::from_utf8(s).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap();

    let payload: Value = Base64UrlSafeNoPadding::decode_to_vec(parts[1], None)
        .ok()
        .and_then(|s| String::from_utf8(s).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap();

    (header, payload)
}

async fn create_credential_and_proof_schemas(
    context: &TestContext,
    organisation: &one_core::model::organisation::Organisation,
    claim_schemas: &[(Uuid, &str, bool, &str, bool)],
) -> (
    one_core::model::credential_schema::CredentialSchema,
    one_core::model::proof_schema::ProofSchema,
) {
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "test",
            organisation,
            claim_schemas,
            "JWT",
            "test-schema-id",
        )
        .await;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            organisation,
            vec![CreateProofInputSchema::from((
                claim_schemas,
                &credential_schema,
            ))],
        )
        .await;

    (credential_schema, proof_schema)
}

async fn setup_final1_certificate_proof(
    reg_cert_data: &[&str],
    client_id_scheme: Option<ClientIdSchemeRestEnum>,
) -> (TestContext, uuid::Uuid, uuid::Uuid) {
    let (context, organisation, identifier, _certificate, key) =
        TestContext::new_with_certificate_identifier(None).await;

    let claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> =
        vec![(Uuid::new_v4(), "firstName", true, "STRING", false)];

    let (credential_schema, proof_schema) =
        create_credential_and_proof_schemas(&context, &organisation, &claim_schemas).await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                proof_schema: Some(proof_schema),
                verifier_identifier: Some(identifier.clone()),
                verifier_key: Some(key),
                ..Default::default()
            },
        )
        .await;

    // Share the proof to create the interaction
    let resp = context.api.proofs.share(proof.id, client_id_scheme).await;
    assert_eq!(resp.status(), 201);

    // Attach registration certificate blobs via trust_information
    for cert_data in reg_cert_data {
        let blob = context
            .db
            .blobs
            .create(TestingBlobParams {
                r#type: Some(BlobType::RegistrationCertificate),
                value: Some(cert_data.as_bytes().to_vec()),
                ..Default::default()
            })
            .await;

        context
            .db
            .identifier_trust_information
            .create(
                identifier.id,
                blob.id,
                TestingIdentifierTrustInformationParams {
                    allowed_verification_types: Some(vec![SchemaFormat {
                        format: "jwt_vc_json".to_string(),
                        schema_id: "test-schema-id".to_string(),
                    }]),
                    ..Default::default()
                },
            )
            .await;
    }

    (context, proof.id.into(), credential_schema.id.into())
}

#[tokio::test]
async fn test_get_client_request_final1_x509_hash_includes_verifier_info() {
    let cert_data = "test-registration-certificate";
    let (context, proof_id, _credential_schema_id) =
        setup_final1_certificate_proof(&[cert_data], Some(ClientIdSchemeRestEnum::X509Hash)).await;

    let resp = context.api.ssi.get_client_request(proof_id).await;

    assert_eq!(resp.status(), 200);
    let (_header, payload) = decode_jwt(&resp.text().await);

    let verifier_info = payload["verifier_info"]
        .as_array()
        .expect("verifier_info must be present for x509_hash scheme");
    assert_eq!(verifier_info.len(), 1);
    assert_eq!(verifier_info[0]["format"], "registration_cert");
    assert_eq!(verifier_info[0]["data"], cert_data);
}

#[tokio::test]
async fn test_get_client_request_final1_no_registration_certs_no_verifier_info() {
    let (context, proof_id, _) = setup_final1_certificate_proof(
        &[], // no registration certs
        Some(ClientIdSchemeRestEnum::X509Hash),
    )
    .await;

    let resp = context.api.ssi.get_client_request(proof_id).await;

    assert_eq!(resp.status(), 200);
    let (_header, payload) = decode_jwt(&resp.text().await);

    // verifier_info should be absent when there are no registration certificates
    assert!(
        payload.get("verifier_info").is_none() || payload["verifier_info"].is_null(),
        "verifier_info should be absent when no registration certificates exist"
    );
}

#[tokio::test]
async fn test_get_client_request_final1_did_scheme_no_verifier_info() {
    // Use a DID-based identifier (not certificate) for DID scheme
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;

    let claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> =
        vec![(Uuid::new_v4(), "firstName", true, "STRING", false)];

    let (_credential_schema, proof_schema) =
        create_credential_and_proof_schemas(&context, &organisation, &claim_schemas).await;

    let proof = fixtures::create_proof(
        &context.db.db_conn,
        &identifier,
        Some(&proof_schema),
        ProofStateEnum::Created,
        ProofRole::Verifier,
        "OPENID4VP_FINAL1",
        None,
        Some(&key),
        None,
        None,
    )
    .await;

    let resp = context
        .api
        .proofs
        .share(
            proof.id,
            Some(ClientIdSchemeRestEnum::DecentralizedIdentifier),
        )
        .await;
    assert_eq!(resp.status(), 201);

    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            r#type: Some(BlobType::RegistrationCertificate),
            value: Some(b"some-reg-cert".to_vec()),
            ..Default::default()
        })
        .await;

    context
        .db
        .identifier_trust_information
        .create(
            identifier.id,
            blob.id,
            TestingIdentifierTrustInformationParams {
                allowed_verification_types: Some(vec![SchemaFormat {
                    format: "jwt_vc_json".to_string(),
                    schema_id: "test-schema-id".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let resp = context.api.ssi.get_client_request(proof.id).await;

    assert_eq!(resp.status(), 200);
    let (_header, payload) = decode_jwt(&resp.text().await);

    assert!(
        payload.get("verifier_info").is_none() || payload["verifier_info"].is_null(),
        "verifier_info must NOT be present for DID client_id_scheme"
    );
}

#[tokio::test]
async fn test_get_client_request_final1_x5c_header_with_access_certificate() {
    let (context, proof_id, _) =
        setup_final1_certificate_proof(&["reg-cert-data"], Some(ClientIdSchemeRestEnum::X509Hash))
            .await;

    let resp = context.api.ssi.get_client_request(proof_id).await;

    assert_eq!(resp.status(), 200);
    let (header, _payload) = decode_jwt(&resp.text().await);

    assert_ne!(
        header["alg"], "none",
        "x509 client-request JWT must be signed, not unsigned"
    );

    let x5c = header["x5c"]
        .as_array()
        .expect("x5c header must be present for x509 scheme");
    assert!(
        !x5c.is_empty(),
        "x5c must contain the access certificate chain"
    );
}

#[tokio::test]
async fn test_get_client_request_final1_verifier_info_has_no_credential_ids() {
    let (context, proof_id, _) =
        setup_final1_certificate_proof(&["reg-cert-data"], Some(ClientIdSchemeRestEnum::X509Hash))
            .await;

    let resp = context.api.ssi.get_client_request(proof_id).await;

    assert_eq!(resp.status(), 200);
    let (_header, payload) = decode_jwt(&resp.text().await);

    let verifier_info = payload["verifier_info"]
        .as_array()
        .expect("verifier_info must be present");

    for entry in verifier_info {
        assert!(
            entry.get("credential_ids").is_none() || entry["credential_ids"].is_null(),
            "registration certificate verifier_info entries must NOT contain credential_ids (ETSI RO_REQ-07)"
        );
    }
}

#[tokio::test]
async fn test_get_client_request_final1_multiple_registration_certs() {
    let (context, proof_id, _) = setup_final1_certificate_proof(
        &["reg-cert-1", "reg-cert-2"],
        Some(ClientIdSchemeRestEnum::X509Hash),
    )
    .await;

    let resp = context.api.ssi.get_client_request(proof_id).await;

    assert_eq!(resp.status(), 200);
    let (_header, payload) = decode_jwt(&resp.text().await);

    let verifier_info = payload["verifier_info"]
        .as_array()
        .expect("verifier_info must be present");
    assert_eq!(
        verifier_info.len(),
        2,
        "all registration certificates must appear in verifier_info"
    );
}

#[tokio::test]
async fn test_get_client_request_final1_includes_transaction_data() {
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;

    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        json!({
          "nonce": "QnoICmZxqAUZdOlPJRVtbJrrHJRTDwCM",
          "client_id": "redirect_uri:https://verifier.example/response",
          "client_id_scheme": "redirect_uri",
          "response_uri": "https://verifier.example/response",
          "dcql_query": {
            "credentials": [
              {
                "id": "input_0",
                "format": "mso_mdoc",
                "meta": {
                  "doctype_value": "org.iso.18013.5.1.mDL"
                },
                "claims": [
                  {
                    "path": [
                      "namespace",
                      "given_name"
                    ]
                  }
                ]
              }
            ]
          },
          "transaction_data": [
            {
              "type": "QES_APPROVAL",
              "credential_ids": [
                "input_0"
              ],
              "data": {
                "documentInfos": [
                  {
                    "access": {
                      "oneTimePassword": "51623",
                      "type": "OTP"
                    },
                    "checksum": "sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                    "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                    "hashType": "sodr",
                    "href": "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374",
                    "label": "Example Contract"
                  },
                  {
                    "access": {
                      "type": "public"
                    },
                    "checksum": "sha256-HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
                    "hash": "HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
                    "hashType": "sodr",
                    "href": "https://public.rp-cdn.example/terms-and-conditions.pdf",
                    "label": "Example Terms of Service"
                  },
                  {
                    "access": {
                      "oneTimePassword": "83920",
                      "type": "OTP"
                    },
                    "checksum": "sha256-nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ=",
                    "hash": "nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ=",
                    "hashType": "sodr",
                    "href": "https://protected.rp.example/invoice-2025-07.pdf?token=jk47ns88sna9a",
                    "label": "Example Invoice"
                  }
                ],
                "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
                "numSignatures": 2,
                "signatureQualifier": "eu_eidas_qes"
              },
              "encoded": "eyJjcmVkZW50aWFsX2lkcyI6WyJpbnB1dF8wIl0sImRvY3VtZW50SW5mb3MiOlt7ImFjY2VzcyI6eyJvbmVUaW1lUGFzc3dvcmQiOiI1MTYyMyIsInR5cGUiOiJPVFAifSwiY2hlY2tzdW0iOiJzaGEyNTYtc1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0iLCJoYXNoIjoic1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0iLCJoYXNoVHlwZSI6InNvZHIiLCJocmVmIjoiaHR0cHM6Ly9wcm90ZWN0ZWQucnAuZXhhbXBsZS9jb250cmFjdC0wMS5wZGY_dG9rZW49SFM5bmFKS1d3cDkwMWhCY0szNDhJVUhpdUg4Mzc0IiwibGFiZWwiOiJFeGFtcGxlIENvbnRyYWN0In0seyJhY2Nlc3MiOnsidHlwZSI6InB1YmxpYyJ9LCJjaGVja3N1bSI6InNoYTI1Ni1IWlF6Wm1NQUlXZWtmR0gwL1pLVzFuc2R0MHhnM0g2YlpZenRnc01UTHcwPSIsImhhc2giOiJIWlF6Wm1NQUlXZWtmR0gwL1pLVzFuc2R0MHhnM0g2YlpZenRnc01UTHcwPSIsImhhc2hUeXBlIjoic29kciIsImhyZWYiOiJodHRwczovL3B1YmxpYy5ycC1jZG4uZXhhbXBsZS90ZXJtcy1hbmQtY29uZGl0aW9ucy5wZGYiLCJsYWJlbCI6IkV4YW1wbGUgVGVybXMgb2YgU2VydmljZSJ9LHsiYWNjZXNzIjp7Im9uZVRpbWVQYXNzd29yZCI6IjgzOTIwIiwidHlwZSI6Ik9UUCJ9LCJjaGVja3N1bSI6InNoYTI1Ni1uTDd6UW1BS2ZRMmpBRHJPeGtFWmgyVXFWNEx4NFdzbWVsU2l2UDZMam9RPSIsImhhc2giOiJuTDd6UW1BS2ZRMmpBRHJPeGtFWmgyVXFWNEx4NFdzbWVsU2l2UDZMam9RPSIsImhhc2hUeXBlIjoic29kciIsImhyZWYiOiJodHRwczovL3Byb3RlY3RlZC5ycC5leGFtcGxlL2ludm9pY2UtMjAyNS0wNy5wZGY_dG9rZW49ams0N25zODhzbmE5YSIsImxhYmVsIjoiRXhhbXBsZSBJbnZvaWNlIn1dLCJoYXNoQWxnb3JpdGhtT0lEIjoiMi4xNi44NDAuMS4xMDEuMy40LjIuMSIsIm51bVNpZ25hdHVyZXMiOjIsInNpZ25hdHVyZVF1YWxpZmllciI6ImV1X2VpZGFzX3FlcyIsInR5cGUiOiJodHRwczovL2Nsb3Vkc2lnbmF0dXJlY29uc29ydGl1bS5vcmcvMjAyNS9xZXMtYXBwcm92YWwifQ"
            }
          ]
        })
        .to_string()
        .as_bytes(),
        &organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Pending,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                interaction: Some(interaction),
                verifier_identifier: Some(identifier),
                verifier_key: Some(key),
                ..Default::default()
            },
        )
        .await;

    let resp = context.api.ssi.get_client_request(proof.id).await;

    assert_eq!(resp.status(), 200);
    let (_header, payload) = decode_jwt(&resp.text().await);

    let transaction_data = payload["transaction_data"]
        .as_array()
        .expect("transaction_data must be present");
    assert_eq!(transaction_data.len(), 1);

    // the provider composes the entry from the stored name/credential_ids/data
    let entry: Value = serde_json::from_slice(
        &Base64UrlSafeNoPadding::decode_to_vec(transaction_data[0].as_str().unwrap(), None)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        entry["type"],
        "https://cloudsignatureconsortium.org/2025/qes-approval"
    );
    assert_eq!(entry["credential_ids"], json!(["input_0"]));
    assert_eq!(entry["signatureQualifier"], "eu_eidas_qes");
}
