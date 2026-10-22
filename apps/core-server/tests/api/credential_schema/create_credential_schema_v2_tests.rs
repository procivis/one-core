use core_server::endpoint::credential_schema::dto::{
    CredentialSchemaTransactionCodeRequestRestDTO, TransactionCodeTypeRestEnum,
};
use one_core::model::credential_schema::{KeyStorageSecurity, WalletAttestation};
use one_core::model::localized_text::{LocalizedTextEntityType, LocalizedTextField};
use shared_types::EntityId;
use similar_asserts::assert_eq;

use crate::utils::api_clients::credential_schemas::{
    CreateSchemaV2Params, TestClaim, TestClaimMappings,
};
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

fn default_claims() -> Vec<TestClaim> {
    vec![TestClaim {
        datatype: "OBJECT".to_string(),
        key: "root".to_string(),
        required: true,
        claims: vec![TestClaim {
            datatype: "STRING".to_string(),
            key: "firstName".to_string(),
            required: true,
            claims: vec![],
            array: None,
            translations: None,
            mappings: None,
        }],
        array: None,
        translations: None,
        mappings: None,
    }]
}

fn jwt_format() -> serde_json::Value {
    serde_json::json!({ "format": "JWT" })
}

#[tokio::test]
async fn test_create_credential_schema_v2_success_single_format() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let id = resp["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;
    assert_eq!(credential_schema.name, "v2 schema");
    assert_eq!(credential_schema.organisation.id(), organisation.id);

    let formats = credential_schema.formats.as_ref().await.unwrap();
    assert_eq!(formats.len(), 1);
    let claim_mappings = formats[0].claim_mappings.as_ref().await.unwrap();
    assert!(claim_mappings.iter().any(|m| m.technical_key == "root"));
    assert!(
        claim_mappings
            .iter()
            .any(|m| m.technical_key == "root/firstName")
    );
}

#[tokio::test]
async fn test_create_credential_schema_v2_success_single_format_multiple_claims() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: vec![
                TestClaim {
                    datatype: "STRING".to_string(),
                    key: "First name".to_string(),
                    required: true,
                    claims: vec![],
                    array: None,
                    translations: None,
                    mappings: None,
                },
                TestClaim {
                    datatype: "STRING".to_string(),
                    key: "Last name".to_string(),
                    required: true,
                    claims: vec![],
                    array: None,
                    translations: None,
                    mappings: None,
                },
                TestClaim {
                    datatype: "BIRTH_DATE".to_string(),
                    key: "Birthday".to_string(),
                    required: true,
                    claims: vec![],
                    array: None,
                    translations: None,
                    mappings: None,
                },
            ],
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let id = resp["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;
    assert_eq!(credential_schema.name, "v2 schema");
    assert_eq!(credential_schema.organisation.id(), organisation.id);

    let formats = credential_schema.formats.as_ref().await.unwrap();
    assert_eq!(formats.len(), 1);
    let claims = credential_schema.claim_schemas.as_ref().await.unwrap();
    let non_metadata_claims = claims.iter().filter(|c| !c.metadata).collect::<Vec<_>>();
    assert_eq!(non_metadata_claims.len(), 3);
    // ordered correctly
    assert_eq!(
        non_metadata_claims
            .iter()
            .map(|c| c.key.as_str())
            .collect::<Vec<_>>(),
        vec!["First name", "Last name", "Birthday"]
    );
}

#[tokio::test]
async fn test_create_credential_schema_v2_incompatible_formats() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // MDOC has no common issuer identifier type with JWT, while BBS+ has no
    // common signing key algorithm with JWT.
    for format in [
        serde_json::json!({ "format": "MDOC", "ecosystemSchemaId": "org.example.test" }),
        serde_json::json!({ "format": "JSON_LD_BBSPLUS" }),
    ] {
        let resp = context
            .api
            .credential_schemas
            .create_v2(CreateSchemaV2Params {
                name: "incompatible formats".into(),
                organisation_id: organisation.id.into(),
                formats: vec![jwt_format(), format],
                claims: default_claims(),
                ..Default::default()
            })
            .await;

        assert_eq!(resp.status(), 400);
        assert_eq!(resp.json_value().await["code"], "BR_0511");
    }
}

#[tokio::test]
async fn test_create_credential_schema_v2_datatype_not_supported_by_all_formats() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    for nested in [false, true] {
        // MDL_PICTURE is supported by MDOC but not SD-JWT VC.
        let portrait = TestClaim {
            key: "portrait".into(),
            datatype: "MDL_PICTURE".into(),
            required: true,
            ..Default::default()
        };
        let claims = if nested {
            vec![TestClaim {
                key: "person".into(),
                datatype: "OBJECT".into(),
                required: true,
                claims: vec![portrait],
                ..Default::default()
            }]
        } else {
            vec![portrait]
        };

        let resp = context
            .api
            .credential_schemas
            .create_v2(CreateSchemaV2Params {
                name: "unsupported datatype".into(),
                organisation_id: organisation.id.into(),
                formats: vec![
                    serde_json::json!({ "format": "MDOC", "ecosystemSchemaId": "org.example.test" }),
                    serde_json::json!({ "format": "SD_JWT_VC" }),
                ],
                claims,
                ..Default::default()
            })
            .await;

        assert_eq!(resp.status(), 400);
        assert_eq!(resp.error_code().await, "BR_0245");
    }
}

#[tokio::test]
async fn test_create_credential_schema_v2_success_multiple_formats() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN - SD-JWT VC and MDOC produce different schema_ids (MDOC uses explicit schemaId)
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 multi-format schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![
                serde_json::json!({ "format": "SD_JWT_VC" }),
                serde_json::json!({ "format": "MDOC", "ecosystemSchemaId": "org.example.test" }),
            ],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let id = resp["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;

    let formats = credential_schema.formats.as_ref().await.unwrap();
    assert_eq!(formats.len(), 2);
    for format in &formats {
        let claim_mappings = format.claim_mappings.as_ref().await.unwrap();
        assert!(claim_mappings.iter().any(|m| m.technical_key == "root"));
        assert!(
            claim_mappings
                .iter()
                .any(|m| m.technical_key == "root/firstName")
        );
    }
}

#[tokio::test]
async fn test_create_credential_schema_v2_mdoc_with_sd_jwt_vc_without_root_object_succeeds() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let flat_claims = vec![TestClaim {
        datatype: "STRING".to_string(),
        key: "firstName".to_string(),
        required: true,
        claims: vec![],
        array: None,
        translations: None,
        mappings: None,
    }];

    // when
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "mdoc and sd-jwt vc schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![
                serde_json::json!({ "format": "SD_JWT_VC" }),
                serde_json::json!({ "format": "MDOC", "ecosystemSchemaId": "org.example.test" }),
            ],
            claims: flat_claims,
            ..Default::default()
        })
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let id = resp.json_value().await["id"].parse::<uuid::Uuid>();

    let resp = context.api.credential_schemas.get_v2(&id).await;
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let formats = resp["formats"]
        .as_array()
        .expect("formats should be an array");
    assert_eq!(formats.len(), 2);
    assert!(formats.iter().any(|f| f["format"] == "SD_JWT_VC"));
    assert!(formats.iter().any(|f| f["format"] == "MDOC"));
}

#[tokio::test]
async fn test_create_credential_schema_v2_success_with_batch_size() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 batch schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            batch_size: Some(5),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_empty_formats() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_empty_claims() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: vec![],
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_duplicate_formats() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format(), jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_credential_schema_v2_success_with_expiration() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema with expiration".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            expiration: Some(63072000),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let id = resp["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;
    assert_eq!(
        credential_schema.expiration,
        Some(time::Duration::seconds(63072000))
    );

    let get_resp = context
        .api
        .credential_schemas
        .get_v2(&credential_schema.id)
        .await
        .json_value()
        .await;
    assert_eq!(get_resp["expiration"], 63072000);
}

#[tokio::test]
async fn test_create_credential_schema_v2_default_expiration_is_null() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema without expiration".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let id = resp["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;
    assert_eq!(credential_schema.expiration, None);

    let get_resp = context
        .api
        .credential_schemas
        .get_v2(&credential_schema.id)
        .await
        .json_value()
        .await;
    assert!(get_resp["expiration"].is_null());
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_expiration_not_positive() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            expiration: Some(0),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0474");
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_negative_expiration() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            expiration: Some(-1),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0474");
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_expiration_too_long() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            expiration: Some(400000000),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0474");
}

#[tokio::test]
async fn test_create_credential_schema_v2_success_with_wallet_attestation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema with wallet attestation".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            wallet_attestation: Some(serde_json::json!({
                "requireInstanceAttestation": true,
                "keyStorageSecurityLevel": "HIGH",
                "preferredKeyStorageAttestationLifetime": 2678400,
                "preferredInstanceAttestationLifetime": 5356800,
            })),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let id = resp["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;
    assert_eq!(
        credential_schema.wallet_attestation,
        WalletAttestation {
            require_instance_attestation: true,
            key_storage_security_level: Some(KeyStorageSecurity::High),
            preferred_key_storage_attestation_lifetime: Some(time::Duration::seconds(2678400)),
            preferred_instance_attestation_lifetime: Some(time::Duration::seconds(5356800)),
        }
    );

    let get_resp = context
        .api
        .credential_schemas
        .get_v2(&credential_schema.id)
        .await
        .json_value()
        .await;
    assert_eq!(
        get_resp["walletAttestation"]["requireInstanceAttestation"],
        true
    );
    assert_eq!(
        get_resp["walletAttestation"]["keyStorageSecurityLevel"],
        "HIGH"
    );
    assert_eq!(
        get_resp["walletAttestation"]["preferredKeyStorageAttestationLifetime"],
        2678400
    );
    assert_eq!(
        get_resp["walletAttestation"]["preferredInstanceAttestationLifetime"],
        5356800
    );
}

#[tokio::test]
async fn test_create_credential_schema_v2_default_wallet_attestation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema without wallet attestation".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let id = resp["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;
    assert_eq!(
        credential_schema.wallet_attestation,
        WalletAttestation::default()
    );

    let get_resp = context
        .api
        .credential_schemas
        .get_v2(&credential_schema.id)
        .await
        .json_value()
        .await;
    assert_eq!(
        get_resp["walletAttestation"]["requireInstanceAttestation"],
        false
    );
    assert!(get_resp["walletAttestation"]["keyStorageSecurityLevel"].is_null());
    assert!(get_resp["walletAttestation"]["preferredKeyStorageAttestationLifetime"].is_null());
    assert!(get_resp["walletAttestation"]["preferredInstanceAttestationLifetime"].is_null());
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_wallet_attestation_lifetime_not_positive() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema with invalid wallet attestation lifetime".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            wallet_attestation: Some(serde_json::json!({
                "preferredKeyStorageAttestationLifetime": 0,
            })),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0504");
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_batch_size_too_small() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            batch_size: Some(1),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_schema_id_not_allowed_for_jwt() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![serde_json::json!({ "format": "JWT", "ecosystemSchemaId": "some-id" })],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_same_name_in_same_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;
    assert_eq!(resp.status(), 201);

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_credential_schema_v2_same_name_in_different_organisations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let organisation2 = context.db.organisations.create().await;

    // WHEN
    let resp1 = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    let resp2 = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation2.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp1.status(), 201);
    assert_eq!(resp2.status(), 201);
}

#[tokio::test]
async fn test_create_credential_schema_v2_mdoc_with_schema_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 mdoc schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![
                serde_json::json!({ "format": "MDOC", "ecosystemSchemaId": "org.iso.18013.5.1.mDL" }),
            ],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_create_credential_schema_v2_mdoc_with_nesting_and_namespace() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 mdoc schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![
                serde_json::json!({ "format": "MDOC", "ecosystemSchemaId": "org.iso.18013.5.1.mDL" }),
            ],
            claims: vec![TestClaim {
                datatype: "OBJECT".to_string(),
                key: "root".to_string(),
                required: true,
                claims: vec![TestClaim {
                    datatype: "STRING".to_string(),
                    key: "nestedClaim".to_string(),
                    required: true,
                    claims: vec![],
                    array: None,
                    translations: None,
                    mappings: Some(vec![TestClaimMappings {
                        format: "MDOC".to_string(),
                        technical_key: "nestedClaim_tech_key".to_string(),
                        namespace: None,
                    }]),
                }],
                array: None,
                translations: None,
                mappings: Some(vec![TestClaimMappings {
                    format: "MDOC".to_string(),
                    technical_key: "root_tech_key".to_string(),
                    namespace: Some("mapped_namespace".to_string()),
                }]),
            }],
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let schema = context
        .db
        .credential_schemas
        .get(&resp.json_value().await["id"].parse())
        .await;
    let claims = schema.claim_schemas.as_ref().await.unwrap();
    let formats = schema.formats.as_ref().await.unwrap();
    let mappings = formats[0].claim_mappings.as_ref().await.unwrap();
    assert_eq!(formats.len(), 1);
    assert_eq!(formats[0].format, "MDOC".into());
    assert_eq!(mappings.len(), 3);
    let root = mappings
        .iter()
        .find(|m| m.technical_key == "root_tech_key")
        .unwrap();
    assert_eq!(root.namespace, Some("mapped_namespace".to_string()));
    let root_claim = claims
        .iter()
        .find(|c| c.id == root.claim_schema_id)
        .unwrap();
    assert_eq!(root_claim.key, "root");
    let child = mappings
        .iter()
        .find(|m| m.technical_key == "root_tech_key/nestedClaim_tech_key")
        .unwrap();
    assert_eq!(child.namespace, Some("mapped_namespace".to_string()));
    let child_claim = claims
        .iter()
        .find(|c| c.id == child.claim_schema_id)
        .unwrap();
    assert_eq!(child_claim.key, "root/nestedClaim");
    let metadata = mappings
        .iter()
        .find(|m| m.technical_key == "doctype")
        .unwrap();
    assert_eq!(metadata.namespace, None);
    let metadata_claim = claims
        .iter()
        .find(|c| c.id == metadata.claim_schema_id)
        .unwrap();
    assert_eq!(metadata_claim.key, "doctype");
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_duplicate_schema_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 mdoc schema 1".into(),
            organisation_id: organisation.id.into(),
            formats: vec![
                serde_json::json!({ "format": "MDOC", "ecosystemSchemaId": "org.example.foo" }),
            ],
            claims: default_claims(),
            ..Default::default()
        })
        .await;
    assert_eq!(resp.status(), 201);

    // WHEN - second schema with same schemaId
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 mdoc schema 2".into(),
            organisation_id: organisation.id.into(),
            formats: vec![
                serde_json::json!({ "format": "MDOC", "ecosystemSchemaId": "org.example.foo" }),
            ],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_forbidden_claim_name() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![serde_json::json!({ "format": "JSON_LD_CLASSIC" })],
            claims: vec![TestClaim {
                datatype: "OBJECT".to_string(),
                key: "root".to_string(),
                required: true,
                claims: vec![TestClaim {
                    datatype: "STRING".to_string(),
                    key: "id".to_string(),
                    required: true,
                    claims: vec![],
                    array: None,
                    translations: None,
                    mappings: None,
                }],
                array: None,
                translations: None,
                mappings: None,
            }],
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0145");
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_claim_name_with_slash() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![serde_json::json!({ "format": "JWT" })],
            claims: vec![TestClaim {
                datatype: "STRING".to_string(),
                key: "test/key".to_string(),
                required: true,
                claims: vec![],
                array: None,
                translations: None,
                mappings: None,
            }],
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0108");
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_technical_key_with_slash() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![serde_json::json!({ "format": "JWT" })],
            claims: vec![TestClaim {
                datatype: "STRING".to_string(),
                key: "key".to_string(),
                required: true,
                claims: vec![],
                array: None,
                translations: None,
                mappings: Some(vec![TestClaimMappings {
                    format: "JWT".to_string(),
                    technical_key: "technical/key".to_string(),
                    namespace: None,
                }]),
            }],
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0108");
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_transaction_code_length_too_big() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            transaction_code: Some(CredentialSchemaTransactionCodeRequestRestDTO {
                r#type: TransactionCodeTypeRestEnum::Numeric,
                length: 11,
                description: None,
            }),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0338");
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_deactivated_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    context.db.organisations.deactivate(&organisation.id).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0241");
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_unsupported_data_type() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![
                serde_json::json!({ "format": "SD_JWT_VC_SWIYU", "ecosystemSchemaId": "ID" }),
            ],
            claims: vec![TestClaim {
                datatype: "PICTURE".to_string(),
                key: "firstName".to_string(),
                required: true,
                claims: vec![],
                array: Some(true),
                translations: None,
                mappings: None,
            }],
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0245");
}

#[tokio::test]
async fn test_create_credential_schema_v2_with_claim_translations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema with claim translations".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: vec![TestClaim {
                datatype: "OBJECT".to_string(),
                key: "root".to_string(),
                required: true,
                claims: vec![TestClaim {
                    datatype: "STRING".to_string(),
                    key: "firstName".to_string(),
                    required: true,
                    claims: vec![],
                    array: None,
                    translations: Some(serde_json::json!({
                        "name": {
                            "en": "First Name",
                            "de": "Vorname"
                        }
                    })),
                    mappings: None,
                }],
                array: None,
                translations: Some(serde_json::json!({
                    "name": {
                        "en": "Root Object",
                        "de": "Hauptobjekt"
                    }
                })),
                mappings: None,
            }],
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;
    let id = resp_json["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;

    let get_resp = context
        .api
        .credential_schemas
        .get_v2(&credential_schema.id)
        .await
        .json_value()
        .await;

    let root_claim = &get_resp["claims"][0];
    assert_eq!(root_claim["key"], "root");
    assert_eq!(root_claim["translations"]["name"]["en"], "Root Object");
    assert_eq!(root_claim["translations"]["name"]["de"], "Hauptobjekt");

    let first_name_claim = &root_claim["claims"][0];
    assert_eq!(first_name_claim["key"], "firstName");
    assert_eq!(first_name_claim["translations"]["name"]["en"], "First Name");
    assert_eq!(first_name_claim["translations"]["name"]["de"], "Vorname");

    let claim_schemas = credential_schema.claim_schemas.as_ref().await.unwrap();
    let root_cs = claim_schemas.iter().find(|cs| cs.key == "root").unwrap();
    let root_translations = context.db.localized_text.get(root_cs.id).await;
    assert_eq!(root_translations.len(), 2);
    assert!(
        root_translations
            .iter()
            .any(|t| t.lang == "en" && t.value == "Root Object")
    );
    assert!(
        root_translations
            .iter()
            .any(|t| t.lang == "de" && t.value == "Hauptobjekt")
    );
    assert!(
        root_translations
            .iter()
            .all(|t| t.entity_type == LocalizedTextEntityType::ClaimSchema)
    );

    let first_name_cs = claim_schemas
        .iter()
        .find(|cs| cs.key == "root/firstName")
        .unwrap();
    let first_name_translations = context.db.localized_text.get(first_name_cs.id).await;
    assert_eq!(first_name_translations.len(), 2);
    assert!(
        first_name_translations
            .iter()
            .any(|t| t.lang == "en" && t.value == "First Name")
    );
    assert!(
        first_name_translations
            .iter()
            .any(|t| t.lang == "de" && t.value == "Vorname")
    );
}

#[tokio::test]
async fn test_create_credential_schema_v2_with_translations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            translations: Some(serde_json::json!({
                "name": {
                    "en": "Schema name in English",
                    "de": "Schema Name auf Deutsch"
                },
                "description": {
                    "en": "Schema description in English",
                    "de": "Schema Beschreibung auf Deutsch"
                }
            })),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;
    let id = resp_json["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;

    let get_resp = context
        .api
        .credential_schemas
        .get_v2(&credential_schema.id)
        .await
        .json_value()
        .await;

    assert_eq!(
        get_resp["translations"]["name"]["en"],
        "Schema name in English"
    );
    assert_eq!(
        get_resp["translations"]["name"]["de"],
        "Schema Name auf Deutsch"
    );
    assert_eq!(
        get_resp["translations"]["description"]["en"],
        "Schema description in English"
    );
    assert_eq!(
        get_resp["translations"]["description"]["de"],
        "Schema Beschreibung auf Deutsch"
    );
    let schema_translations = context.db.localized_text.get(credential_schema.id).await;

    let name_translations: Vec<_> = schema_translations
        .iter()
        .filter(|t| t.field == LocalizedTextField::Name)
        .collect();
    assert_eq!(name_translations.len(), 2);
    assert!(
        name_translations
            .iter()
            .any(|t| t.lang == "en" && t.value == "Schema name in English")
    );
    assert!(
        name_translations
            .iter()
            .any(|t| t.lang == "de" && t.value == "Schema Name auf Deutsch")
    );

    let description_translations: Vec<_> = schema_translations
        .iter()
        .filter(|t| t.field == LocalizedTextField::Description)
        .collect();
    assert_eq!(description_translations.len(), 2);
    assert!(
        description_translations
            .iter()
            .any(|t| t.lang == "en" && t.value == "Schema description in English")
    );
    assert!(
        description_translations
            .iter()
            .any(|t| t.lang == "de" && t.value == "Schema Beschreibung auf Deutsch")
    );

    assert!(
        schema_translations
            .iter()
            .all(|t| t.entity_type == LocalizedTextEntityType::CredentialSchema)
    );
}

#[tokio::test]
async fn test_create_credential_schema_v2_with_translations_non_default() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            translations: Some(serde_json::json!({
                "name": {
                    "de": "Schema Name auf Deutsch"
                }
            })),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;
    let schema_translations = context
        .db
        .localized_text
        .get(resp_json["id"].parse::<EntityId>())
        .await;
    assert_eq!(schema_translations.len(), 2);
    assert!(
        schema_translations
            .iter()
            .any(|t| t.lang == "en" && t.value == "v2 schema")
    );
    assert!(
        schema_translations
            .iter()
            .any(|t| t.lang == "de" && t.value == "Schema Name auf Deutsch")
    );
    assert!(
        schema_translations
            .iter()
            .all(|t| t.field == LocalizedTextField::Name)
    );
}

#[tokio::test]
async fn test_create_credential_schema_v2_default_translation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN - no translations provided
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "my schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;
    let id = resp_json["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;

    let get_resp = context
        .api
        .credential_schemas
        .get_v2(&credential_schema.id)
        .await
        .json_value()
        .await;

    assert_eq!(get_resp["translations"]["name"]["en"], "my schema");
    let schema_translations = context.db.localized_text.get(credential_schema.id).await;
    assert_eq!(schema_translations.len(), 1);
    assert_eq!(schema_translations[0].lang, "en");
    assert_eq!(schema_translations[0].value, "my schema");
    assert_eq!(schema_translations[0].field, LocalizedTextField::Name);
}

#[tokio::test]
async fn test_create_credential_schema_v2_with_dislosure_policy() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            embedded_disclosure_policy: Some(serde_json::json!({
                "policy": "allowList",
                "options": {
                   "values": [{
                       "dn": "C=CH",
                       "entitlement": "entitlement"
                   }]
                },
                "description": "description",
                "url": "https://url",
            })),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;
    let id = resp_json["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;

    let get_resp = context
        .api
        .credential_schemas
        .get_v2(&credential_schema.id)
        .await
        .json_value()
        .await;

    let policy = &get_resp["embeddedDisclosurePolicy"];
    assert!(
        policy["id"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/ssi/disclosure-policy/v1/{id}"))
    );
    assert_eq!(policy["policy"], "allowList");
    assert_eq!(policy["description"], "description");
    assert_eq!(policy["url"], "https://url");
    assert_eq!(
        policy["options"],
        serde_json::json!({
            "values": [{
                "dn": "C=CH",
                "entitlement": "entitlement"
            }]
        })
    );
}
