use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

use shared_types::DidValue;

use crate::model::did::DidType;
use crate::provider::credential_formatter::CredentialData;
use crate::service::credential::dto::{
    CredentialDetailResponseDTO, CredentialRole, CredentialSchemaType, CredentialStateEnum,
    DetailCredentialClaimResponseDTO, DetailCredentialClaimValueResponseDTO,
    DetailCredentialSchemaResponseDTO,
};
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::did::dto::DidListItemResponseDTO;

fn generate_credential_detail_response(
    claims: Vec<DetailCredentialClaimResponseDTO>,
) -> CredentialDetailResponseDTO {
    let now = OffsetDateTime::now_utc();

    CredentialDetailResponseDTO {
        id: Uuid::new_v4().into(),
        created_date: now,
        issuance_date: now,
        revocation_date: None,
        state: CredentialStateEnum::Created,
        last_modified: now,
        schema: DetailCredentialSchemaResponseDTO {
            id: Default::default(),
            created_date: now,
            last_modified: now,
            deleted_at: None,
            name: "".to_string(),
            format: "".to_string(),
            revocation_method: "".to_string(),
            organisation_id: Uuid::new_v4().into(),
            wallet_storage_type: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            layout_type: None,
            schema_id: "".to_string(),
            layout_properties: None,
        },
        issuer_did: Some(DidListItemResponseDTO {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: "".to_string(),
            did: DidValue::from_str("did:key:1234").unwrap(),
            did_type: DidType::Remote,
            did_method: "".to_string(),
            deactivated: false,
        }),
        claims,
        redirect_uri: None,
        role: CredentialRole::Holder,
        lvvc_issuance_date: None,
        suspend_end_date: None,
    }
}

#[test]
fn test_from_credential_detail_response_nested_claim_mapping() {
    let now = OffsetDateTime::now_utc();
    let actual = CredentialData::from_credential_detail_response(
        generate_credential_detail_response(vec![
            DetailCredentialClaimResponseDTO {
                schema: CredentialClaimSchemaDTO {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    last_modified: now,
                    key: "location".to_string(),
                    datatype: "OBJECT".to_string(),
                    required: false,
                    claims: vec![],
                },
                value: DetailCredentialClaimValueResponseDTO::Nested(vec![
                    DetailCredentialClaimResponseDTO {
                        schema: CredentialClaimSchemaDTO {
                            id: Uuid::new_v4().into(),
                            created_date: now,
                            last_modified: now,
                            key: "x".to_string(),
                            datatype: "STRING".to_string(),
                            required: false,
                            claims: vec![],
                        },
                        value: DetailCredentialClaimValueResponseDTO::String("123".to_string()),
                    },
                    DetailCredentialClaimResponseDTO {
                        schema: CredentialClaimSchemaDTO {
                            id: Uuid::new_v4().into(),
                            created_date: now,
                            last_modified: now,
                            key: "y".to_string(),
                            datatype: "STRING".to_string(),
                            required: false,
                            claims: vec![],
                        },
                        value: DetailCredentialClaimValueResponseDTO::String("456".to_string()),
                    },
                ]),
            },
            DetailCredentialClaimResponseDTO {
                schema: CredentialClaimSchemaDTO {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    last_modified: now,
                    key: "street".to_string(),
                    datatype: "STRING".to_string(),
                    required: false,
                    claims: vec![],
                },
                value: DetailCredentialClaimValueResponseDTO::String("some street".to_string()),
            },
        ]),
        "http://127.0.0.1",
        vec![],
    )
    .unwrap()
    .claims;

    let expected: Vec<(String, String)> = vec![
        ("location/x".to_string(), "123".to_string()),
        ("location/y".to_string(), "456".to_string()),
        ("street".to_string(), "some street".to_string()),
    ];

    assert_eq!(expected, actual);
}
