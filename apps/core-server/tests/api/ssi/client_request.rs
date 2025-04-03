use core::str;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_core::model::proof::ProofStateEnum;
use serde_json::json;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;

#[tokio::test]
async fn test_get_client_request() {
    // GIVEN
    let (context, organisation, did, key) = TestContext::new_with_did(None).await;

    let nonce = "nonce123";
    let new_claim_schemas: Vec<(Uuid, &'static str, bool, &'static str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false),
        (Uuid::new_v4(), "cat2", true, "STRING", false),
    ];
    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "id": new_claim_schemas[0].0,
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": false
                        }
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "https://response.uri/",
    });

    let schema_id = Uuid::new_v4();
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_id,
            "NewCredentialSchema",
            &organisation,
            "NONE",
            &new_claim_schemas,
            "JWT",
            &schema_id.to_string(),
        )
        .await;
    let proof_input_schema =
        CreateProofInputSchema::from((&new_claim_schemas[..], &credential_schema));

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "schema-client-request",
            &organisation,
            vec![proof_input_schema],
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &context.server_mock.uri(),
            interaction_data.to_string().as_bytes(),
            &organisation,
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            key.to_owned(),
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_client_request(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.text().await;

    let (header, payload) = resp.split_once('.').unwrap();

    let header: serde_json::Value = Base64UrlSafeNoPadding::decode_to_vec(header, None)
        .ok()
        .and_then(|s| String::from_utf8(s).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap();

    let payload: serde_json::Value = Base64UrlSafeNoPadding::decode_to_vec(payload, None)
        .ok()
        .and_then(|s| String::from_utf8(s).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap();

    assert_eq!(
        json!({ "alg": "none", "typ": "oauth-authz-req+jwt"}),
        header
    );

    assert_eq!(
        json!({
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "id": new_claim_schemas[0].0,
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": false
                        }
                    ]
                }
            }]
        }),
        payload["presentation_definition"],
    );
    assert_eq!(nonce, payload["nonce"]);
    assert_eq!("direct_post", payload["response_mode"]);
    assert_eq!("vp_token", payload["response_type"]);
    assert_eq!("client_id", payload["client_id"]);
    assert_eq!("https://self-issued.me/v2", payload["aud"]);
    assert_eq!("https://response.uri/", payload["response_uri"]);
    assert_eq!(interaction.id.to_string(), payload["state"]);
    assert!(payload["client_metadata"].is_object());
}
