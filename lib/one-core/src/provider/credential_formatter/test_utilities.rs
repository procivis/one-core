use shared_types::DidValue;
use std::str::FromStr as _;
use time::{macros::datetime, OffsetDateTime};
use uuid::Uuid;

use crate::service::credential::dto::DetailCredentialClaimValueResponseDTO;
use crate::{
    model::{credential_schema::LayoutType, did::DidType},
    service::{
        credential::dto::{
            CredentialDetailResponseDTO, CredentialRole, CredentialSchemaType, CredentialStateEnum,
            DetailCredentialClaimResponseDTO, DetailCredentialSchemaResponseDTO,
        },
        credential_schema::dto::CredentialClaimSchemaDTO,
        did::dto::DidListItemResponseDTO,
    },
};

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 +1)
}

pub fn test_credential_detail_response_dto() -> CredentialDetailResponseDTO {
    let id = Uuid::from_str("9a414a60-9e6b-4757-8011-9aa870ef4788").unwrap();

    CredentialDetailResponseDTO {
        id: id.into(),
        created_date: get_dummy_date(),
        issuance_date: get_dummy_date(),
        revocation_date: None,
        state: CredentialStateEnum::Created,
        last_modified: get_dummy_date(),
        schema: DetailCredentialSchemaResponseDTO {
            id: id.into(),
            created_date: get_dummy_date(),
            deleted_at: None,
            last_modified: get_dummy_date(),
            wallet_storage_type: None,
            name: "Credential schema name".to_string(),
            format: "Credential schema format".to_string(),
            revocation_method: "Credential schema revocation method".to_string(),
            organisation_id: id.into(),
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            layout_type: Some(LayoutType::Card),
            layout_properties: None,
        },
        issuer_did: Some(DidListItemResponseDTO {
            id: id.into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "foo".into(),
            did: DidValue::from_str("Issuer DID").unwrap(),
            did_type: DidType::Remote,
            did_method: "KEY".into(),
            deactivated: false,
        }),
        claims: vec![
            DetailCredentialClaimResponseDTO {
                path: "name".to_string(),
                schema: CredentialClaimSchemaDTO {
                    id: id.into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: "name".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    array: false,
                    claims: vec![],
                },
                value: DetailCredentialClaimValueResponseDTO::String("John".to_string()),
            },
            DetailCredentialClaimResponseDTO {
                path: "age".to_string(),
                schema: CredentialClaimSchemaDTO {
                    id: id.into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: "age".to_string(),
                    datatype: "NUMBER".to_string(),
                    required: true,
                    array: false,
                    claims: vec![],
                },
                value: DetailCredentialClaimValueResponseDTO::String("42".to_string()),
            },
        ],
        redirect_uri: None,
        role: CredentialRole::Holder,
        lvvc_issuance_date: None,
        suspend_end_date: None,
    }
}

pub fn test_credential_detail_response_dto_with_array() -> CredentialDetailResponseDTO {
    let id = Uuid::from_str("9a414a60-9e6b-4757-8011-9aa870ef4788").unwrap();

    CredentialDetailResponseDTO {
        id: id.into(),
        created_date: get_dummy_date(),
        issuance_date: get_dummy_date(),
        revocation_date: None,
        state: CredentialStateEnum::Created,
        last_modified: get_dummy_date(),
        schema: DetailCredentialSchemaResponseDTO {
            id: id.into(),
            created_date: get_dummy_date(),
            deleted_at: None,
            last_modified: get_dummy_date(),
            wallet_storage_type: None,
            name: "Credential schema name".to_string(),
            format: "Credential schema format".to_string(),
            revocation_method: "Credential schema revocation method".to_string(),
            organisation_id: id.into(),
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            layout_type: Some(LayoutType::Card),
            layout_properties: None,
        },
        issuer_did: Some(DidListItemResponseDTO {
            id: id.into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "foo".into(),
            did: DidValue::from_str("Issuer DID").unwrap(),
            did_type: DidType::Remote,
            did_method: "KEY".into(),
            deactivated: false,
        }),
        claims: vec![
            DetailCredentialClaimResponseDTO {
                schema: CredentialClaimSchemaDTO {
                    id: id.into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: "root".to_string(),
                    datatype: "OBJECT".to_string(),
                    required: true,
                    array: false,
                    claims: vec![],
                },
                path: "root".to_string(),
                value: DetailCredentialClaimValueResponseDTO::Nested(vec![
                    DetailCredentialClaimResponseDTO {
                        schema: CredentialClaimSchemaDTO {
                            id: id.into(),
                            created_date: get_dummy_date(),
                            last_modified: get_dummy_date(),
                            key: "array".to_string(),
                            datatype: "STRING".to_string(),
                            required: true,
                            array: true,
                            claims: vec![],
                        },
                        path: "root/array".to_string(),
                        value: DetailCredentialClaimValueResponseDTO::Nested(vec![
                            DetailCredentialClaimResponseDTO {
                                schema: CredentialClaimSchemaDTO {
                                    id: id.into(),
                                    created_date: get_dummy_date(),
                                    last_modified: get_dummy_date(),
                                    key: "0".to_string(),
                                    datatype: "STRING".to_string(),
                                    required: true,
                                    array: false,
                                    claims: vec![],
                                },
                                path: "root/array/0".to_string(),
                                value: DetailCredentialClaimValueResponseDTO::String(
                                    "array_item".to_string(),
                                ),
                            },
                        ]),
                    },
                    DetailCredentialClaimResponseDTO {
                        schema: CredentialClaimSchemaDTO {
                            id: id.into(),
                            created_date: get_dummy_date(),
                            last_modified: get_dummy_date(),
                            key: "nested".to_string(),
                            datatype: "STRING".to_string(),
                            required: true,
                            array: false,
                            claims: vec![],
                        },
                        path: "root/nested".to_string(),
                        value: DetailCredentialClaimValueResponseDTO::String(
                            "nested_item".to_string(),
                        ),
                    },
                ]),
            },
            DetailCredentialClaimResponseDTO {
                schema: CredentialClaimSchemaDTO {
                    id: id.into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: "root_item".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    array: false,
                    claims: vec![],
                },
                path: "root_item".to_string(),
                value: DetailCredentialClaimValueResponseDTO::String("root_item".to_string()),
            },
        ],
        redirect_uri: None,
        role: CredentialRole::Holder,
        lvvc_issuance_date: None,
        suspend_end_date: None,
    }
}
