use std::{collections::HashSet, sync::Arc};

use maplit::{hashmap, hashset};
use mockall::predicate::eq;
use one_providers::{
    common_models::{
        claim::OpenClaim,
        claim_schema::OpenClaimSchema,
        credential::{
            OpenCredential, OpenCredentialRole, OpenCredentialState, OpenCredentialStateEnum,
        },
        credential_schema::{OpenCredentialSchema, OpenCredentialSchemaClaim, OpenLayoutType},
        organisation::OpenOrganisation,
        proof::OpenProof,
    },
    exchange_protocol::openid4vc::{
        model::PresentationDefinitionRuleTypeEnum, ExchangeProtocolImpl, MockStorageProxy,
    },
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    provider::{
        credential_formatter::mdoc_formatter::mdoc::EmbeddedCbor,
        exchange_protocol::iso_mdl::common::{
            DeviceRequest, DocRequest, ItemsRequest, SkDevice, SkReader,
        },
    },
    service::{proof::dto::MdocBleInteractionData, test_utilities::generic_config},
};

use super::IsoMdl;

#[tokio::test]
async fn test_get_presentation_definition_ok() {
    let core_config = generic_config().core;
    let service = IsoMdl::new(Arc::new(core_config));

    let organisation_id = Uuid::new_v4().into();
    let schema_id = "org.iso.18013.5.1".to_string();
    let interaction_data = serde_json::to_value(MdocBleInteractionData {
        service_id: Uuid::new_v4(),
        task_id: Uuid::new_v4(),
        sk_device: SkDevice::new([0; 32]),
        sk_reader: SkReader::new([0; 32]),
        device_request: DeviceRequest {
            version: "1.0".to_string(),
            doc_request: vec![DocRequest {
                items_request: EmbeddedCbor(ItemsRequest {
                    doc_type: schema_id.clone(),
                    name_spaces: hashmap! {
                        "org.iso.18013.5.1.mDL".to_string() => hashmap! {
                            "name".to_string() => true,
                            "age".to_string() => true,
                            "country".to_string() => true,
                            "info".to_string() => true,
                        }
                    },
                }),
            }],
        }
        .into(),
        organisation_id,
    })
    .unwrap();

    let proof_id = Uuid::new_v4().into();
    let proof = OpenProof {
        id: proof_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "ISO_MDL".to_string(),
        transport: "BLE".to_string(),
        redirect_uri: None,
        state: None,
        schema: None,
        claims: None,
        verifier_did: None,
        holder_did: None,
        verifier_key: None,
        interaction: None,
    };

    let credential_id = Uuid::new_v4().into();
    let credential_schema_id = Uuid::new_v4().into();

    let claim_schemas = hashmap![
       "org.iso.18013.5.1.mDL" => OpenCredentialSchemaClaim {
            schema: OpenClaimSchema {
                id: Uuid::new_v4().into(),
                key: "org.iso.18013.5.1.mDL".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
            },
            required: true,
        },
        "org.iso.18013.5.1.mDL/name" => OpenCredentialSchemaClaim {
            schema: OpenClaimSchema {
                id: Uuid::new_v4().into(),
                key: "org.iso.18013.5.1.mDL/name".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
            },
            required: true,
        },
       "org.iso.18013.5.1.mDL/age" => OpenCredentialSchemaClaim {
            schema: OpenClaimSchema {
                id: Uuid::new_v4().into(),
                key: "org.iso.18013.5.1.mDL/age".to_string(),
                data_type: "NUMBER".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
            },
            required: true,
        },
       "org.iso.18013.5.1.mDL/country" => OpenCredentialSchemaClaim {
            schema: OpenClaimSchema {
                id: Uuid::new_v4().into(),
                key: "org.iso.18013.5.1.mDL/country".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
            },
            required: true,
        },
       "org.iso.18013.5.1.mDL/country_code" => OpenCredentialSchemaClaim {
            schema: OpenClaimSchema {
                id: Uuid::new_v4().into(),
                key: "org.iso.18013.5.1.mDL/country_code".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
            },
            required: true,
        },
        "org.iso.18013.5.1.mDL/info" => OpenCredentialSchemaClaim {
            schema: OpenClaimSchema {
                id: Uuid::new_v4().into(),
                key: "org.iso.18013.5.1.mDL/info".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
            },
            required: true,
        },
        "org.iso.18013.5.1.mDL/info/code" => OpenCredentialSchemaClaim {
            schema: OpenClaimSchema {
                id: Uuid::new_v4().into(),
                key: "org.iso.18013.5.1.mDL/info/code".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
            },
            required: true,
        },
    ];
    let credential_schema = OpenCredentialSchema {
        id: credential_schema_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "schema-name".to_string(),
        format: "ISO_MDL".to_string(),
        revocation_method: "NONE".to_string(),
        layout_type: OpenLayoutType::Card,
        schema_id: schema_id.clone(),
        schema_type: "schema-type".to_string(),
        organisation: Some(OpenOrganisation {
            id: organisation_id.into(),
        }),
        layout_properties: None,
        claim_schemas: Some(claim_schemas.values().cloned().collect()),
        wallet_storage_type: None,
        deleted_at: None,
    };
    let credential_state = OpenCredentialState {
        created_date: OffsetDateTime::now_utc(),
        state: OpenCredentialStateEnum::Accepted,
        suspend_end_date: None,
    };
    let claims = vec![
        OpenClaim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL/name"].schema.clone()),
            path: "org.iso.18013.5.1.mDL/name".to_string(),
            value: "John".to_string(),
        },
        OpenClaim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            schema: Some(claim_schemas["org.iso.18013.5.1.mDL/age"].schema.clone()),
            path: "org.iso.18013.5.1.mDL/age".to_string(),
            value: "55".to_string(),
        },
        OpenClaim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            schema: Some(
                claim_schemas["org.iso.18013.5.1.mDL/country"]
                    .schema
                    .clone(),
            ),
            path: "org.iso.18013.5.1.mDL/country".to_string(),
            value: "Germany".to_string(),
        },
        OpenClaim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            schema: Some(
                claim_schemas["org.iso.18013.5.1.mDL/country_code"]
                    .schema
                    .clone(),
            ),
            path: "org.iso.18013.5.1.mDL/country_code".to_string(),
            value: "DE".to_string(),
        },
        OpenClaim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            schema: Some(
                claim_schemas["org.iso.18013.5.1.mDL/info/code"]
                    .schema
                    .clone(),
            ),
            path: "org.iso.18013.5.1.mDL/info/code".to_string(),
            value: "ABCDEFG".to_string(),
        },
    ];

    let mut storage_access = MockStorageProxy::new();
    storage_access
        .expect_get_credentials_by_credential_schema_id()
        .with(eq(schema_id))
        .return_once(move |_| {
            Ok(vec![OpenCredential {
                id: credential_id,
                created_date: OffsetDateTime::now_utc(),
                issuance_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                exchange: "ISO_MDL".to_string(),
                schema: Some(credential_schema),
                role: OpenCredentialRole::Holder,
                credential: vec![],
                deleted_at: None,
                redirect_uri: None,
                state: Some(vec![credential_state]),
                claims: Some(claims),
                issuer_did: None,
                holder_did: None,
                key: None,
                interaction: None,
            }])
        });

    let mut presentation_definition = service
        .get_presentation_definition(
            &proof,
            interaction_data,
            &storage_access,
            hashmap! {},
            hashmap! {},
        )
        .await
        .unwrap();

    assert_eq!(1, presentation_definition.request_groups.len());
    let mut request_group = presentation_definition.request_groups.pop().unwrap();

    assert_eq!(proof_id.to_string(), request_group.id);
    assert!(matches!(
        request_group.rule.r#type,
        PresentationDefinitionRuleTypeEnum::All
    ));

    assert_eq!(1, request_group.requested_credentials.len());
    let requested_credential = request_group.requested_credentials.pop().unwrap();

    assert_eq!(1, requested_credential.applicable_credentials.len());
    assert_eq!(
        credential_id.to_string(),
        requested_credential.applicable_credentials[0]
    );

    let (credentials, mapped_field_ids): (HashSet<String>, HashSet<String>) = requested_credential
        .fields
        .into_iter()
        .flat_map(|field| field.key_map)
        .unzip();

    assert_eq!(hashset![credential_id.to_string()], credentials);

    assert_eq!(
        mapped_field_ids,
        hashset![
            "org.iso.18013.5.1.mDL/name".into(),
            "org.iso.18013.5.1.mDL/age".into(),
            "org.iso.18013.5.1.mDL/country".into(),
            "org.iso.18013.5.1.mDL/info".into(),
        ]
    )
}
