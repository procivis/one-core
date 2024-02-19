use std::str::FromStr;

use one_core::model::{
    credential::CredentialStateEnum,
    did::{Did, DidType, KeyRole, RelatedKey},
    key::Key,
    organisation::Organisation,
    proof::ProofStateEnum,
};
use serde_json::json;
use shared_types::DidValue;
use uuid::Uuid;

use crate::{
    fixtures::{TestingCredentialParams, TestingDidParams, TestingKeyParams},
    utils::context::TestContext,
};

// Full flow test still under development
#[ignore]
#[tokio::test]
async fn test_opeind4vc_jsondl_flow_bbs() {
    test_opeind4vc_jsondl_flow(bbs_key_1(), eddsa_key_1(), eddsa_key_2()).await
}

async fn test_opeind4vc_jsondl_flow(
    issuer_bbs_key: TestKey,
    holder_key: TestKey,
    _verifier_key: TestKey,
) {
    // GIVEN
    let server_context = TestContext::new().await;
    let base_url = server_context.config.app.core_base_url.clone();
    let server_organisation = server_context.db.organisations.create().await;
    let nonce = "nonce123";

    let (server_did, holder_did, local_key) = prepare_dids(
        &server_context,
        &server_organisation,
        issuer_bbs_key.to_owned(),
        holder_key.to_owned(),
    )
    .await;

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str)> = vec![
        (Uuid::new_v4(), "Key", true, "STRING"),
        (Uuid::new_v4(), "Name", true, "STRING"),
        (Uuid::new_v4(), "Address", true, "STRING"),
    ];

    let credential_schema = server_context
        .db
        .credential_schemas
        .create_with_claims(
            "Test",
            &server_organisation,
            "BITSTRINGSTATUSLIST",
            &new_claim_schemas,
            "JSON_LD_BBSPLUS",
        )
        .await;

    let credential = server_context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &server_did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                holder_did: Some(holder_did.clone()),
                ..Default::default()
            },
        )
        .await;

    server_context
        .server_mock
        .json_ld_context(&credential_schema.id, "Test")
        .await;

    let proof_schema = server_context
        .db
        .proof_schemas
        .create("Test", &server_organisation, &new_claim_schemas)
        .await;

    let interaction_id = Uuid::new_v4();

    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": interaction_id.to_string(),
            "input_descriptors": [{
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "id": new_claim_schemas[0].0,
                            "path": ["$.credentialSubject.Key"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.credentialSubject.Name"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[2].0,
                            "path": ["$.credentialSubject.Address"],
                            "optional": false
                        }
                    ]
                }
            }]
        }
    });

    let interaction = server_context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &base_url,
            interaction_data.to_string().as_bytes(),
        )
        .await;

    let _proof = server_context
        .db
        .proofs
        .create(
            None,
            &server_did,
            Some(&holder_did),
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VC",
            Some(&interaction),
            local_key,
        )
        .await;

    let resp = server_context.api.ssi.temporary_submit(credential.id).await;
    let resp = resp.json_value().await;

    // Valid credentials
    let credentials = resp["credential"].as_str();

    assert!(credentials.is_some());
}

async fn prepare_dids(
    context: &TestContext,
    organisation: &Organisation,
    local_key_params: TestKey,
    remote_key_params: TestKey,
) -> (Did, Did, Key) {
    let local_key = context
        .db
        .keys
        .create(organisation, local_key_params.params)
        .await;
    let local_did = context
        .db
        .dids
        .create(
            organisation,
            TestingDidParams {
                did_type: Some(DidType::Local),
                ..key_to_did_params(Some(&local_key), &local_key_params.multibase)
            },
        )
        .await;

    let remote_did = context
        .db
        .dids
        .create(
            organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..key_to_did_params(None, &remote_key_params.multibase)
            },
        )
        .await;
    (local_did, remote_did, local_key)
}

fn key_to_did_params(key: Option<&Key>, multibase: &str) -> TestingDidParams {
    TestingDidParams {
        did_method: Some("KEY".to_string()),
        did: Some(DidValue::from_str(&format!("did:key:{multibase}",)).unwrap()),
        keys: key.map(|key| {
            vec![
                RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                },
            ]
        }),
        ..Default::default()
    }
}

#[derive(Clone)]
struct TestKey {
    multibase: String,
    params: TestingKeyParams,
}

fn eddsa_key_1() -> TestKey {
    TestKey {
        multibase: "z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB".to_string(),
        params: TestingKeyParams {
            key_type: Some("EDDSA".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                247, 48, 105, 26, 32, 134, 117, 181, 204, 194, 200, 75, 150, 16, 179, 22, 25, 85,
                252, 36, 83, 75, 3, 227, 191, 61, 55, 14, 149, 78, 206, 62,
            ]),
            key_reference: Some(vec![
                212, 80, 75, 28, 149, 144, 224, 28, 223, 35, 146, 169, 0, 0, 0, 0, 0, 0, 0, 64, 68,
                141, 148, 184, 183, 93, 124, 94, 83, 37, 210, 158, 29, 198, 205, 80, 195, 231, 51,
                105, 223, 240, 42, 129, 38, 242, 34, 135, 183, 137, 16, 97, 99, 78, 128, 164, 7,
                224, 218, 192, 165, 238, 164, 235, 194, 174, 23, 8, 65, 236, 151, 160, 239, 122,
                128, 137, 179, 207, 221, 144, 39, 35, 41, 197, 187, 16, 201, 230, 68, 12, 227, 117,
                56, 166, 196, 208, 5, 218, 2, 154,
            ]),
            ..Default::default()
        },
    }
}

fn eddsa_key_2() -> TestKey {
    TestKey {
        multibase: "z6Mki2njTKAL6rctJpMzHEeL35qhnG1wQaTG2knLVSk93Bj5".to_string(),
        params: TestingKeyParams {
            key_type: Some("EDDSA".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                53, 41, 236, 251, 185, 9, 201, 18, 100, 252, 20, 153, 131, 142, 218, 73, 109, 237,
                68, 35, 207, 20, 15, 39, 108, 188, 153, 46, 114, 75, 86, 224,
            ]),
            key_reference: Some(vec![
                103, 220, 116, 52, 196, 76, 31, 218, 7, 98, 15, 113, 0, 0, 0, 0, 0, 0, 0, 64, 24,
                146, 78, 36, 166, 76, 92, 244, 62, 141, 72, 168, 119, 97, 65, 237, 225, 64, 143,
                194, 12, 54, 139, 194, 174, 4, 166, 254, 120, 85, 50, 195, 244, 114, 34, 66, 225,
                119, 93, 162, 209, 171, 21, 33, 239, 46, 38, 225, 251, 115, 125, 119, 103, 172, 90,
                0, 57, 203, 39, 186, 177, 154, 133, 61, 38, 126, 230, 178, 135, 149, 20, 28, 80,
                208, 0, 205, 166, 10, 225, 50,
            ]),
            ..Default::default()
        },
    }
}

fn bbs_key_1() -> TestKey {
    TestKey {
        multibase: "zUC77bqRWgmZNzUQHeSSuQTiMc2Pqv3uTp1oWgbwrXushHz4Y5CbCG3WRZVo93qMwqKqizMbA6ntv\
            gGBXq5ZoHZ6HseTN842bp43GkR3N1Sw7TkJ52uQPUEyWYVD5ggtnn1E85W"
            .to_string(),
        params: TestingKeyParams {
            key_type: Some("BBS_PLUS".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                147, 93, 112, 129, 203, 111, 44, 119, 169, 7, 95, 132, 153, 185, 198, 198, 129, 84,
                156, 55, 184, 61, 204, 119, 111, 122, 160, 163, 48, 239, 33, 137, 125, 140, 163,
                102, 57, 192, 136, 126, 86, 183, 128, 140, 219, 199, 154, 22, 15, 128, 57, 87, 78,
                30, 140, 204, 70, 118, 7, 231, 236, 124, 182, 174, 78, 221, 147, 133, 22, 141, 5,
                68, 223, 121, 15, 120, 12, 199, 148, 247, 139, 220, 251, 131, 254, 247, 142, 138,
                222, 72, 105, 81, 218, 112, 27, 233,
            ]),
            key_reference: Some(vec![
                106, 24, 25, 239, 49, 159, 115, 152, 71, 187, 10, 249, 0, 0, 0, 0, 0, 0, 0, 32, 78,
                70, 91, 108, 197, 78, 54, 13, 243, 59, 43, 81, 46, 122, 63, 210, 19, 49, 124, 233,
                140, 70, 195, 60, 62, 175, 172, 120, 48, 121, 166, 240, 209, 195, 125, 120, 45,
                199, 92, 119, 53, 237, 185, 129, 6, 109, 32, 97,
            ]),
            ..Default::default()
        },
    }
}
