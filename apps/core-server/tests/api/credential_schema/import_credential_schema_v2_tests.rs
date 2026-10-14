use one_core::model::credential_schema::{KeyStorageSecurity, WalletAttestation};
use one_core::model::localized_text::{LocalizedTextEntityType, LocalizedTextField};
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_import_credential_schema_v2_with_translations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let import_schema = serde_json::json!(
    {
      "allowSuspension": false,
      "claims": [
        {
          "array": false,
          "claims": [
            {
              "array": false,
              "claims": [],
              "createdDate": "2026-05-18T13:53:49.979Z",
              "datatype": "STRING",
              "id": "ac18f142-50c4-4878-802a-7e3245ac0d05",
              "key": "firstName",
              "lastModified": "2026-05-18T13:53:49.979Z",
              "mappings": [
                {
                  "format": "JWT",
                  "technicalKey": "root/firstName"
                }
              ],
              "required": true,
              "translations": {
                "name": {
                  "en": "firstName"
                }
              }
            }
          ],
          "createdDate": "2026-05-18T13:53:49.979Z",
          "datatype": "OBJECT",
          "id": "ef625d50-b816-43ce-b69b-2f5fc6cc59c8",
          "key": "root",
          "lastModified": "2026-05-18T13:53:49.979Z",
          "mappings": [
            {
              "format": "JWT",
              "technicalKey": "root"
            }
          ],
          "required": true,
          "translations": {
            "name": {
              "en": "root"
            }
          }
        }
      ],
      "createdDate": "2026-05-18T13:53:49.979Z",
      "formats": [
        {
          "format": "JWT",
          "ecosystemSchemaId": "7812e9af-523d-4892-8fb2-fe67101a5ffe"
        }
      ],
      "id": "7812e9af-523d-4892-8fb2-fe67101a5ffe",
      "importedSourceUrl": "http://127.0.0.1:51147/ssi/schema/v2/6b457c8b-5af4-4fd9-9767-c87349675dd2",
      "lastModified": "2026-05-18T13:53:49.979Z",
      "layoutProperties": {
        "background": {
          "color": "bg-color"
        },
        "primaryAttribute": "root/firstName"
      },
      "layoutType": "CARD",
      "name": "exportable schema",
      "organisationId": "b6bb4b89-8e70-48b3-9ff7-e8e9c44904e7",
      "translations": {
        "description": {
          "de": "Ein Schema zum Importieren",
          "en": "A schema for import"
        },
        "name": {
          "de": "Importierbares Schema",
          "en": "Importable schema"
        }
      }
    });

    // WHEN
    let import_resp = context
        .api
        .credential_schemas
        .import_v2(organisation.id, import_schema)
        .await;

    // THEN
    assert_eq!(import_resp.status(), 201);
    let imported_id = import_resp.json_value().await["id"].parse();
    let imported_schema = context.db.credential_schemas.get(&imported_id).await;
    let imported_schema_translations = context.db.localized_text.get(imported_schema.id).await;
    let name_translations: Vec<_> = imported_schema_translations
        .iter()
        .filter(|t| t.field == LocalizedTextField::Name)
        .collect();
    assert_eq!(name_translations.len(), 2);
    assert!(
        name_translations
            .iter()
            .any(|t| t.lang == "en" && t.value == "Importable schema")
    );
    assert!(
        name_translations
            .iter()
            .any(|t| t.lang == "de" && t.value == "Importierbares Schema")
    );
    let description_translations: Vec<_> = imported_schema_translations
        .iter()
        .filter(|t| t.field == LocalizedTextField::Description)
        .collect();
    assert_eq!(description_translations.len(), 2);
    assert!(
        description_translations
            .iter()
            .any(|t| t.lang == "en" && t.value == "A schema for import")
    );
    assert!(
        description_translations
            .iter()
            .any(|t| t.lang == "de" && t.value == "Ein Schema zum Importieren")
    );
    assert!(
        imported_schema_translations
            .iter()
            .all(|t| t.entity_type == LocalizedTextEntityType::CredentialSchema)
    );
}

#[tokio::test]
async fn test_import_credential_schema_v2_imports_claim_translations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let import_schema = serde_json::json!(
    {
      "allowSuspension": false,
      "claims": [
        {
          "array": false,
          "claims": [
            {
              "array": false,
              "claims": [],
              "createdDate": "2026-05-18T13:53:49.979Z",
              "datatype": "STRING",
              "id": "ac18f142-50c4-4878-802a-7e3245ac0d05",
              "key": "firstName",
              "lastModified": "2026-05-18T13:53:49.979Z",
              "mappings": [
                {
                  "format": "JWT",
                  "technicalKey": "root/firstName"
                }
              ],
              "required": true,
              "translations": {
                "name": {
                  "en": "First name",
                  "de": "Vorname"
                }
              }
            }
          ],
          "createdDate": "2026-05-18T13:53:49.979Z",
          "datatype": "OBJECT",
          "id": "ef625d50-b816-43ce-b69b-2f5fc6cc59c8",
          "key": "root",
          "lastModified": "2026-05-18T13:53:49.979Z",
          "mappings": [
            {
              "format": "JWT",
              "technicalKey": "root"
            }
          ],
          "required": true,
          "translations": {
            "name": {
              "en": "Root",
              "de": "Hauptobjekt"
            }
          }
        }
      ],
      "createdDate": "2026-05-18T13:53:49.979Z",
      "formats": [
        {
          "format": "JWT",
          "ecosystemSchemaId": "7812e9af-523d-4892-8fb2-fe67101a5ffe"
        }
      ],
      "id": "7812e9af-523d-4892-8fb2-fe67101a5ffe",
      "importedSourceUrl": "http://127.0.0.1:51147/ssi/schema/v2/6b457c8b-5af4-4fd9-9767-c87349675dd2",
      "lastModified": "2026-05-18T13:53:49.979Z",
      "layoutProperties": {
        "background": {
          "color": "bg-color"
        },
        "primaryAttribute": "root/firstName"
      },
      "layoutType": "CARD",
      "name": "exportable schema",
      "organisationId": "b6bb4b89-8e70-48b3-9ff7-e8e9c44904e7",
      "translations": {
        "name": {
          "en": "Importable schema"
        }
      }
    });

    // WHEN
    let import_resp = context
        .api
        .credential_schemas
        .import_v2(organisation.id, import_schema)
        .await;

    // THEN
    assert_eq!(import_resp.status(), 201);
    let imported_id = import_resp.json_value().await["id"].parse::<uuid::Uuid>();

    let get_resp = context.api.credential_schemas.get_v2(&imported_id).await;
    assert_eq!(get_resp.status(), 200);
    let get_resp = get_resp.json_value().await;

    let claims = get_resp["claims"].as_array().unwrap();
    let root_claim = claims
        .iter()
        .find(|c| c["key"] == "root")
        .expect("root claim should be present");
    assert_eq!(root_claim["translations"]["name"]["en"], "Root");
    assert_eq!(root_claim["translations"]["name"]["de"], "Hauptobjekt");

    let first_name_claim = root_claim["claims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["key"] == "firstName")
        .expect("firstName claim should be present");
    assert_eq!(first_name_claim["translations"]["name"]["en"], "First name");
    assert_eq!(first_name_claim["translations"]["name"]["de"], "Vorname");
}

#[tokio::test]
async fn test_import_credential_schema_v2_with_expiration() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let import_schema = serde_json::json!(
    {
      "allowSuspension": false,
      "claims": [
        {
          "array": false,
          "claims": [],
          "createdDate": "2026-05-18T13:53:49.979Z",
          "datatype": "STRING",
          "id": "ac18f142-50c4-4878-802a-7e3245ac0d05",
          "key": "firstName",
          "lastModified": "2026-05-18T13:53:49.979Z",
          "required": true,
          "translations": {
            "name": {
              "en": "firstName"
            }
          }
        }
      ],
      "createdDate": "2026-05-18T13:53:49.979Z",
      "expiration": 63072000,
      "formats": [
        {
          "format": "JWT",
          "ecosystemSchemaId": "7812e9af-523d-4892-8fb2-fe67101a5ffe"
        }
      ],
      "id": "7812e9af-523d-4892-8fb2-fe67101a5ffe",
      "importedSourceUrl": "http://127.0.0.1:51147/ssi/schema/v2/6b457c8b-5af4-4fd9-9767-c87349675dd2",
      "lastModified": "2026-05-18T13:53:49.979Z",
      "layoutType": "CARD",
      "name": "schema with expiration",
      "organisationId": "b6bb4b89-8e70-48b3-9ff7-e8e9c44904e7"
    });

    // WHEN
    let import_resp = context
        .api
        .credential_schemas
        .import_v2(organisation.id, import_schema)
        .await;

    // THEN
    assert_eq!(import_resp.status(), 201);
    let imported_id = import_resp.json_value().await["id"].parse();
    let imported_schema = context.db.credential_schemas.get(&imported_id).await;
    assert_eq!(
        imported_schema.expiration,
        Some(time::Duration::seconds(63072000))
    );

    let get_resp = context
        .api
        .credential_schemas
        .get_v2(&imported_id)
        .await
        .json_value()
        .await;
    assert_eq!(get_resp["expiration"], 63072000);
}

#[tokio::test]
async fn test_import_credential_schema_v2_with_wallet_attestation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let import_schema = serde_json::json!(
    {
      "allowSuspension": false,
      "claims": [
        {
          "array": false,
          "claims": [],
          "createdDate": "2026-05-18T13:53:49.979Z",
          "datatype": "STRING",
          "id": "ac18f142-50c4-4878-802a-7e3245ac0d05",
          "key": "firstName",
          "lastModified": "2026-05-18T13:53:49.979Z",
          "required": true,
          "translations": {
            "name": {
              "en": "firstName"
            }
          }
        }
      ],
      "createdDate": "2026-05-18T13:53:49.979Z",
      "formats": [
        {
          "format": "JWT",
          "ecosystemSchemaId": "7812e9af-523d-4892-8fb2-fe67101a5ffe"
        }
      ],
      "id": "7812e9af-523d-4892-8fb2-fe67101a5ffe",
      "importedSourceUrl": "http://127.0.0.1:51147/ssi/schema/v2/6b457c8b-5af4-4fd9-9767-c87349675dd2",
      "lastModified": "2026-05-18T13:53:49.979Z",
      "layoutType": "CARD",
      "name": "schema with wallet attestation",
      "organisationId": "b6bb4b89-8e70-48b3-9ff7-e8e9c44904e7",
      "walletAttestation": {
        "requireInstanceAttestation": true,
        "keyStorageSecurityLevel": "HIGH",
        "preferredKeyStorageAttestationLifetime": 2678400,
        "preferredInstanceAttestationLifetime": 5356800
      }
    });

    // WHEN
    let import_resp = context
        .api
        .credential_schemas
        .import_v2(organisation.id, import_schema)
        .await;

    // THEN
    assert_eq!(import_resp.status(), 201);
    let imported_id = import_resp.json_value().await["id"].parse();
    let imported_schema = context.db.credential_schemas.get(&imported_id).await;
    assert_eq!(
        imported_schema.wallet_attestation,
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
        .get_v2(&imported_id)
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
async fn test_import_credential_schema_v2_multiple_formats_with_shared_metadata_claims() {
    // GIVEN
    // JWT and SD_JWT formatters both emit the same metadata claims (iss, sub, aud, ...),
    // which must be deduplicated on import to not violate the unique
    // (key, credential_schema_id) index on claim_schema
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let import_schema = serde_json::json!(
    {
      "allowSuspension": false,
      "claims": [
        {
          "array": false,
          "claims": [],
          "createdDate": "2026-07-03T11:44:45.285Z",
          "datatype": "STRING",
          "id": "98d0312c-9c69-48dc-a759-946964520cfe",
          "key": "firstName",
          "lastModified": "2026-07-03T11:44:45.285Z",
          "required": true,
          "translations": {
            "name": {
              "en": "firstName"
            }
          }
        }
      ],
      "createdDate": "2026-07-03T11:44:45.285Z",
      "formats": [
        {
          "format": "JWT",
          "ecosystemSchemaId": "http://example.com/schema/jwt"
        },
        {
          "format": "SD_JWT",
          "ecosystemSchemaId": "http://example.com/schema/sd-jwt"
        }
      ],
      "id": "efced6c9-7257-424c-be4e-c68554509540",
      "importedSourceUrl": "http://127.0.0.1:51147/ssi/schema/v2/efced6c9-7257-424c-be4e-c68554509540",
      "lastModified": "2026-07-03T11:44:45.285Z",
      "layoutType": "CARD",
      "name": "multi-format schema",
      "organisationId": "18364c17-06a1-4b93-9a4b-c440f2bc2420"
    });

    // WHEN
    let import_resp = context
        .api
        .credential_schemas
        .import_v2(organisation.id, import_schema)
        .await;

    // THEN
    assert_eq!(import_resp.status(), 201);
    let imported_id = import_resp.json_value().await["id"].parse();
    let imported_schema = context.db.credential_schemas.get(&imported_id).await;

    let claim_schemas = imported_schema.claim_schemas.as_ref().await.unwrap();
    let mut keys: Vec<_> = claim_schemas.iter().map(|cs| cs.key.as_str()).collect();
    keys.sort_unstable();
    let total_keys = keys.len();
    keys.dedup();
    assert_eq!(keys.len(), total_keys, "duplicate claim schema keys");

    // shared metadata claims are mapped in both formats
    let iss_claim_schema = claim_schemas
        .iter()
        .find(|cs| cs.key == "iss" && cs.metadata)
        .expect("iss metadata claim should be present");
    let formats = imported_schema.formats.as_ref().await.unwrap();
    assert_eq!(formats.len(), 2);
    for format in &formats {
        let claim_mappings = format.claim_mappings.as_ref().await.unwrap();
        assert!(
            claim_mappings
                .iter()
                .any(|m| m.claim_schema_id == iss_claim_schema.id),
            "format `{}` should have a mapping for the shared iss metadata claim",
            format.format
        );
    }
}

#[tokio::test]
async fn test_import_credential_schema_v2_without_translation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let import_schema = serde_json::json!(
    {
      "allowSuspension": false,
      "claims": [
        {
          "array": false,
          "claims": [
            {
              "array": false,
              "claims": [],
              "createdDate": "2026-05-18T13:58:17.758Z",
              "datatype": "STRING",
              "id": "13a73121-eb6f-4ffd-97f5-a9d9a0ec3597",
              "key": "firstName",
              "lastModified": "2026-05-18T13:58:17.758Z",
              "mappings": [
                {
                  "format": "JWT",
                  "technicalKey": "root/firstName"
                }
              ],
              "required": true,
              "translations": {
                "name": {
                  "en": "firstName"
                }
              }
            }
          ],
          "createdDate": "2026-05-18T13:58:17.758Z",
          "datatype": "OBJECT",
          "id": "355107ca-9872-4f09-b30a-647b8006b308",
          "key": "root",
          "lastModified": "2026-05-18T13:58:17.758Z",
          "mappings": [
            {
              "format": "JWT",
              "technicalKey": "root"
            }
          ],
          "required": true,
          "translations": {
            "name": {
              "en": "root"
            }
          }
        }
      ],
      "createdDate": "2026-05-18T13:58:17.758Z",
      "formats": [
        {
          "format": "JWT",
          "ecosystemSchemaId": "ab3f4837-0a50-4218-bd90-6d0e60671946"
        }
      ],
      "id": "ab3f4837-0a50-4218-bd90-6d0e60671946",
      "importedSourceUrl": "http://127.0.0.1:51170/ssi/schema/v2/4842afb9-26e6-4e83-a651-a57b4521b832",
      "lastModified": "2026-05-18T13:58:17.758Z",
      "layoutProperties": {
        "background": {
          "color": "bg-color"
        },
        "primaryAttribute": "root/firstName"
      },
      "layoutType": "CARD",
      "name": "plain schema",
      "organisationId": "ca7493bb-2ae4-49b9-b26c-c0485e98f2d9"
    }
        );
    // WHEN
    let import_resp = context
        .api
        .credential_schemas
        .import_v2(organisation.id, import_schema)
        .await;

    // THEN
    assert_eq!(import_resp.status(), 201);
    let imported_id = import_resp.json_value().await["id"].parse();
    let imported_schema = context.db.credential_schemas.get(&imported_id).await;
    let imported_schema_translations = context.db.localized_text.get(imported_schema.id).await;
    let name_translations: Vec<_> = imported_schema_translations
        .iter()
        .filter(|t| t.field == LocalizedTextField::Name)
        .collect();
    assert_eq!(name_translations.len(), 1);
    assert_eq!(name_translations.first().unwrap().lang, "en");
    assert_eq!(name_translations.first().unwrap().value, "plain schema");
}

#[tokio::test]
async fn test_import_credential_schema_v2_sdjwtvc_forbidden_claim() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let import_schema = serde_json::json!(
    {
      "allowSuspension": false,
      "claims": [
        {
          "array": false,
          "claims": [],
          "createdDate": "2026-05-18T13:58:17.758Z",
          "datatype": "STRING",
          "id": "355107ca-9872-4f09-b30a-647b8006b308",
          "key": "root",
          "lastModified": "2026-05-18T13:58:17.758Z",
          "mappings": [
            {
              "format": "SD_JWT_VC",
              "technicalKey": "status"
            }
          ],
          "required": true
        }
      ],
      "createdDate": "2026-05-18T13:58:17.758Z",
      "formats": [
        {
          "format": "SD_JWT_VC",
          "ecosystemSchemaId": "vct"
        }
      ],
      "id": "ab3f4837-0a50-4218-bd90-6d0e60671946",
      "importedSourceUrl": "http://random.url",
      "lastModified": "2026-05-18T13:58:17.758Z",
      "name": "schema",
      "organisationId": "ca7493bb-2ae4-49b9-b26c-c0485e98f2d9"
    }
        );
    // WHEN
    let import_resp = context
        .api
        .credential_schemas
        .import_v2(organisation.id, import_schema)
        .await;

    // THEN
    assert_eq!(import_resp.status(), 400);
    assert_eq!(import_resp.error_code().await, "BR_0145");
}
