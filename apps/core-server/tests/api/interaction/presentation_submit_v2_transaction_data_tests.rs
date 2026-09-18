use std::collections::HashMap;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_core::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::interaction::{Interaction, InteractionType};
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::proof::{Proof, ProofStateEnum};
use one_core::provider::credential_formatter::model::{
    CredentialData, Issuer, PublishedClaim, PublishedClaimValue,
};
use one_core::provider::credential_formatter::vcdm::VcdmCredential;
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::MockBuilder;
use wiremock::matchers::body_string_contains;

use crate::fixtures;
use crate::fixtures::mdoc::format_mdoc_credential;
use crate::fixtures::{
    ClaimData, TestingCredentialParams, TestingDidParams, TestingIdentifierParams, TestingKeyParams,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::proofs::TestingProofParams;
use crate::utils::field_match::FieldHelpers;

const QES_APPROVAL_TYPE: &str = "https://cloudsignatureconsortium.org/2025/qes-approval";
const MDOC_DOCTYPE: &str = "doctype";
const MDOC_NAMESPACE: &str = "namespace";

/// Base64URL-encoded QES approval transaction data applicable to credential
/// query `input_0`.
fn qes_approval_transaction_data(label: &str) -> String {
    let payload = json!({
        "type": QES_APPROVAL_TYPE,
        "credential_ids": ["input_0"],
        "numSignatures": 1,
        "signatureQualifier": "eu_eidas_qes",
        "documentInfos": [
            {
                "label": label,
                "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                "hashType": "sodr",
                "access": { "type": "public" },
                "href": "https://public.rp-cdn.example/contract.pdf",
                "checksum": "sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="
            }
        ],
        "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
    });
    Base64UrlSafeNoPadding::encode_to_string(serde_json::to_vec(&payload).unwrap()).unwrap()
}

async fn create_mdoc_holder_credential(
    context: &TestContext,
    organisation: &Organisation,
    issuer_identifier: &Identifier,
) -> Credential {
    let namespace_claim_id = Uuid::new_v4();
    let given_name_claim_id = Uuid::new_v4();
    let claim_schemas: &[(Uuid, &str, bool, &str, bool)] = &[
        (namespace_claim_id, MDOC_NAMESPACE, true, "OBJECT", false),
        (
            given_name_claim_id,
            &format!("{MDOC_NAMESPACE}/given_name"),
            true,
            "STRING",
            false,
        ),
    ];
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "mDL",
            organisation,
            claim_schemas,
            "MDOC",
            MDOC_DOCTYPE,
        )
        .await;

    let (holder_key, holder_identifier) = create_holder_identifier(context, organisation).await;

    let token = format_mdoc_credential(
        CredentialData {
            vcdm: VcdmCredential {
                context: Default::default(),
                id: None,
                r#type: vec![],
                issuer: Issuer::Url("https://example.issuer.com".parse().unwrap()),
                valid_from: None,
                issuance_date: None,
                valid_until: None,
                expiration_date: None,
                credential_subject: vec![],
                credential_status: vec![],
                proof: None,
                credential_schema: Some(vec![
                    one_core::provider::credential_formatter::model::CredentialSchema {
                        id: MDOC_DOCTYPE.to_string(),
                        r#type: "schema".to_string(),
                        metadata: None,
                    },
                ]),
                refresh_service: None,
                name: None,
                description: None,
                terms_of_use: None,
                evidence: None,
                related_resource: None,
            },
            claims: vec![PublishedClaim {
                key: format!("{MDOC_NAMESPACE}/given_name"),
                value: PublishedClaimValue::String("John".to_string()),
                datatype: Some("STRING".to_string()),
            }],
            holder_identifier: Some(holder_identifier.clone()),
            holder_key_id: None,
            issuer_certificate: None,
        },
        json!({
            "expirationSeconds": 86_400,
            "msoExpectedUpdateInSeconds": 300,
            "msoMinimumRefreshSeconds": 300,
            "leewaySeconds": 60
        }),
    )
    .await;

    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(token.as_ref().as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            issuer_identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                holder_identifier: Some(holder_identifier),
                key: Some(holder_key),
                role: Some(CredentialRole::Holder),
                credential_blob_id: Some(blob.id),
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: namespace_claim_id.into(),
                        path: MDOC_NAMESPACE.to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: given_name_claim_id.into(),
                        path: format!("{MDOC_NAMESPACE}/given_name"),
                        value: Some("John".to_string()),
                        selectively_disclosable: true,
                    },
                ]),
                ..Default::default()
            },
        )
        .await
}

/// Sets up a submittable mdoc presentation whose interaction carries the given
/// number of already-validated QES approval transaction-data entries (keyed by
/// the returned ids), all applicable to credential query `input_0`.
async fn setup_submittable_mdoc_with_transaction_data(
    context: &TestContext,
    organisation: &Organisation,
    issuer_identifier: &Identifier,
    transaction_data_count: usize,
) -> (Credential, Interaction, Proof, Vec<Uuid>) {
    let client_metadata = json!({
        "vp_formats_supported": {
            "mso_mdoc": { "alg": ["ES256"] }
        }
    });

    let verifier_key = context
        .db
        .keys
        .create(organisation, Default::default())
        .await;
    let verifier_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![
                    RelatedKey {
                        role: KeyRole::Authentication,
                        key: verifier_key.clone(),
                        reference: "1".to_string(),
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: verifier_key.clone(),
                        reference: "1".to_string(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;
    let verifier_identifier = context
        .db
        .identifiers
        .create(
            organisation,
            TestingIdentifierParams {
                did: Some(verifier_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(verifier_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential = create_mdoc_holder_credential(context, organisation, issuer_identifier).await;

    let transaction_data_ids: Vec<Uuid> = (0..transaction_data_count)
        .map(|_| Uuid::new_v4())
        .collect();
    let validated_transaction_data: Vec<serde_json::Value> = transaction_data_ids
        .iter()
        .enumerate()
        .map(|(idx, id)| {
            json!([
                id,
                {
                    "raw": qes_approval_transaction_data(&format!("Example Contract {idx}")),
                    "credential_query_ids": ["input_0"],
                    "transaction_data_type": "QES_APPROVAL"
                }
            ])
        })
        .collect();
    let verifier_url = context.server_mock.uri();
    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        json!({
            "response_type": "vp_token",
            "state": "53c44733-4f9d-4db2-aa83-afb8e17b500f",
            "nonce": "QnoICmZxqAUZdOlPJRVtbJrrHJRTDwCM",
            "client_id_scheme": "redirect_uri",
            "client_id": format!("{verifier_url}/mock/response"),
            "client_metadata": client_metadata,
            "response_mode": "direct_post",
            "response_uri": format!("{verifier_url}/mock/response"),
            "dcql_query": {
                "credentials": [
                    {
                        "id": "input_0",
                        "format": "mso_mdoc",
                        "meta": { "doctype_value": MDOC_DOCTYPE },
                        "claims": [ { "path": [MDOC_NAMESPACE, "given_name"] } ]
                    }
                ]
            },
            "transaction_data": {
                "Validated": validated_transaction_data
            }
        })
        .to_string()
        .as_bytes(),
        organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Requested,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(verifier_identifier),
                verifier_key: Some(verifier_key),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    (credential, interaction, proof, transaction_data_ids)
}

/// Asserts that the mdoc `vp_token` the holder posted to the verifier carries
/// the QES approval transaction data as a device-signed element. The element
/// name appears as a literal UTF-8 string inside the CBOR `DeviceResponse`.
async fn assert_vp_token_carries_transaction_data(context: &TestContext) {
    let requests = context
        .server_mock
        .received_requests()
        .await
        .expect("mock recorded requests");
    let submission = requests
        .iter()
        .find(|r| r.url.path() == "/mock/response")
        .expect("verifier received the submission");

    let params: HashMap<String, String> = url::form_urlencoded::parse(&submission.body)
        .into_owned()
        .collect();
    let vp_token = params.get("vp_token").expect("vp_token form field");
    // DCQL vp_token is a JSON map { "input_0": ["<base64url DeviceResponse>"] }.
    let map: HashMap<String, Vec<String>> =
        serde_json::from_str(vp_token).expect("vp_token is a DCQL map");
    let device_response = &map.get("input_0").expect("input_0 presentation")[0];
    let cbor = Base64UrlSafeNoPadding::decode_to_vec(device_response, None)
        .expect("base64url DeviceResponse");

    let needle = b"qesApproval";
    assert!(
        cbor.windows(needle.len()).any(|w| w == needle),
        "expected QES approval transaction data in the mdoc device response"
    );
}

async fn create_holder_identifier(
    context: &TestContext,
    organisation: &Organisation,
) -> (Key, Identifier) {
    let holder_key = fixtures::create_key(
        &context.db.db_conn,
        organisation,
        Some(TestingKeyParams {
            key_type: Some("ECDSA".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                2, 41, 83, 61, 165, 86, 37, 125, 46, 237, 61, 7, 255, 169, 76, 11, 51, 20, 151,
                189, 221, 246, 169, 103, 136, 2, 114, 144, 254, 4, 26, 202, 33,
            ]),
            key_reference: Some(vec![
                214, 40, 173, 242, 210, 229, 35, 49, 245, 164, 136, 170, 0, 0, 0, 0, 0, 0, 0, 32,
                168, 61, 62, 181, 162, 142, 116, 226, 190, 20, 146, 183, 17, 166, 110, 17, 207, 54,
                243, 166, 143, 172, 23, 72, 196, 139, 42, 147, 222, 122, 234, 133, 236, 18, 64,
                113, 85, 218, 233, 136, 236, 48, 86, 184, 249, 54, 210, 76,
            ]),
            ..Default::default()
        }),
    )
    .await;
    let holder_did = fixtures::create_did(
        &context.db.db_conn,
        organisation,
        Some(TestingDidParams {
            did_method: Some("KEY".into()),
            did: Some(
                "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6"
                    .parse()
                    .unwrap(),
            ),
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: holder_key.clone(),
                reference: "1".to_string(),
            }]),
            ..Default::default()
        }),
    )
    .await;
    let holder_identifier = context
        .db
        .identifiers
        .create(
            organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    (holder_key, holder_identifier)
}

#[tokio::test]
async fn test_presentation_submit_v2_transaction_data_auto_assignment() {
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let (credential, interaction, proof, _) =
        setup_submittable_mdoc_with_transaction_data(&context, &organisation, &identifier, 1).await;

    context
        .server_mock
        .ssi_request_uri_endpoint(Some(|mock_builder: MockBuilder| {
            mock_builder
                .and(body_string_contains("state"))
                .and(body_string_contains("vp_token"))
        }))
        .await;

    let resp = context
        .api
        .interactions
        .presentation_submit_v2(interaction.id, credential.id, &[], &[])
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let proof = fixtures::get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);
    assert_vp_token_carries_transaction_data(&context).await;
}

#[tokio::test]
async fn test_presentation_submit_v2_transaction_data_manual_assignment() {
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let (credential, interaction, proof, transaction_data_ids) =
        setup_submittable_mdoc_with_transaction_data(&context, &organisation, &identifier, 1).await;

    context
        .server_mock
        .ssi_request_uri_endpoint(Some(|mock_builder: MockBuilder| {
            mock_builder
                .and(body_string_contains("state"))
                .and(body_string_contains("vp_token"))
        }))
        .await;

    let resp = context
        .api
        .interactions
        .presentation_submit_v2(interaction.id, credential.id, &[], &transaction_data_ids)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let proof = fixtures::get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);
    assert_vp_token_carries_transaction_data(&context).await;
}

#[tokio::test]
async fn test_presentation_submit_v2_two_transaction_data_pinned_to_one_credential_fails() {
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let (credential, interaction, proof, transaction_data_ids) =
        setup_submittable_mdoc_with_transaction_data(&context, &organisation, &identifier, 2).await;

    // Both QES approval entries are pinned to the same credential; a
    // presentation can only carry a single qesApproval value.
    let resp = context
        .api
        .interactions
        .presentation_submit_v2(interaction.id, credential.id, &[], &transaction_data_ids)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0459", resp.error_code().await);
    // nothing was sent to the verifier, the proof remains actionable
    let proof = fixtures::get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Requested);
}

#[tokio::test]
async fn test_presentation_submit_v2_two_transaction_data_auto_assignment_fails_for_one_credential()
{
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let (credential, interaction, proof, _) =
        setup_submittable_mdoc_with_transaction_data(&context, &organisation, &identifier, 2).await;

    // No explicit selection: two entries cannot be distributed over the single
    // presented credential.
    let resp = context
        .api
        .interactions
        .presentation_submit_v2(interaction.id, credential.id, &[], &[])
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0459", resp.error_code().await);
    let proof = fixtures::get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Requested);
}

#[tokio::test]
async fn test_presentation_definition_v2_surfaces_transaction_data() {
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let (_credential, _interaction, proof, transaction_data_ids) =
        setup_submittable_mdoc_with_transaction_data(&context, &organisation, &identifier, 1).await;

    // WHEN
    let resp = context
        .api
        .proofs
        .presentation_definition_v2(proof.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    let transaction_data = body["transactionData"].as_array().unwrap();
    assert_eq!(transaction_data.len(), 1);
    let entry = &transaction_data[0];
    entry["id"].assert_eq(&transaction_data_ids[0]);
    assert_eq!(entry["type"], "QES_APPROVAL");
    assert_eq!(entry["credentialQueryIds"], json!(["input_0"]));
}

#[tokio::test]
async fn test_get_proof_transaction_data() {
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let (_credential, _interaction, proof, transaction_data_ids) =
        setup_submittable_mdoc_with_transaction_data(&context, &organisation, &identifier, 1).await;

    // WHEN
    let resp = context
        .api
        .proofs
        .transaction_data(proof.id, transaction_data_ids[0])
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    body["id"].assert_eq(&transaction_data_ids[0]);
    assert_eq!(body["type"], "QES_APPROVAL");
    assert_eq!(body["credentialQueryIds"], json!(["input_0"]));

    // display data assembled from the QES approval `documentInfos` group
    let display = body["transactionDataDisplay"].as_array().unwrap();
    assert_eq!(display.len(), 1);
    assert_eq!(display[0]["title"], "Example Contract 0");
    let attributes = display[0]["attributes"].as_array().unwrap();
    assert_eq!(attributes.len(), 2);

    // raw transaction data is the fully decoded verifier payload
    assert_eq!(body["rawTransactionData"]["type"], QES_APPROVAL_TYPE);
    assert_eq!(body["rawTransactionData"]["numSignatures"], 1);
    assert_eq!(
        body["rawTransactionData"]["credential_ids"],
        json!(["input_0"])
    );
}

#[tokio::test]
async fn test_get_proof_transaction_data_unknown_id_returns_404() {
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let (_credential, _interaction, proof, _) =
        setup_submittable_mdoc_with_transaction_data(&context, &organisation, &identifier, 1).await;

    // WHEN
    let resp = context
        .api
        .proofs
        .transaction_data(proof.id, Uuid::new_v4())
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}
