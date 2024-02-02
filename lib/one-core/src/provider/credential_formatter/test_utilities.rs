use std::str::FromStr as _;

use shared_types::DidValue;
use time::{macros::datetime, OffsetDateTime};
use uuid::Uuid;

use crate::{
    model::did::DidType,
    service::{
        credential::dto::{
            CredentialDetailResponseDTO, CredentialRole, CredentialStateEnum,
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
        id,
        created_date: get_dummy_date(),
        issuance_date: get_dummy_date(),
        revocation_date: None,
        state: CredentialStateEnum::Created,
        last_modified: get_dummy_date(),
        schema: DetailCredentialSchemaResponseDTO {
            id,
            created_date: get_dummy_date(),
            deleted_at: None,
            last_modified: get_dummy_date(),
            name: "Credential schema name".to_string(),
            format: "Credential schema format".to_string(),
            revocation_method: "Credential schema revocation method".to_string(),
            organisation_id: id,
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
                    id,
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: "name".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                },
                value: "John".to_string(),
            },
            DetailCredentialClaimResponseDTO {
                schema: CredentialClaimSchemaDTO {
                    id,
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: "age".to_string(),
                    datatype: "NUMBER".to_string(),
                    required: true,
                },
                value: "42".to_string(),
            },
        ],
        redirect_uri: None,
        role: CredentialRole::Holder,
    }
}
