use mockall::predicate::*;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::core_config::CoreConfig,
    model::{
        claim_schema::{ClaimSchema, ClaimSchemaRelations},
        credential_schema::{
            CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations,
            GetCredentialSchemaList,
        },
        organisation::{Organisation, OrganisationRelations},
    },
    repository::{
        credential_schema_repository::MockCredentialSchemaRepository, error::DataLayerError,
        mock::organisation_repository::MockOrganisationRepository,
    },
    service::{
        credential_schema::{
            dto::{
                CreateCredentialSchemaRequestDTO, CredentialClaimSchemaRequestDTO,
                GetCredentialSchemaQueryDTO,
            },
            CredentialSchemaService,
        },
        error::ServiceError,
        test_utilities::generic_config,
    },
};

fn setup_service(
    credential_schema_repository: MockCredentialSchemaRepository,
    organisation_repository: MockOrganisationRepository,
    config: CoreConfig,
) -> CredentialSchemaService {
    CredentialSchemaService::new(
        Arc::new(credential_schema_repository),
        Arc::new(organisation_repository),
        Arc::new(config),
    )
}

fn generic_credential_schema() -> CredentialSchema {
    let now = OffsetDateTime::now_utc();
    CredentialSchema {
        id: Uuid::new_v4(),
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: "".to_string(),
        format: "".to_string(),
        revocation_method: "".to_string(),
        claim_schemas: Some(vec![CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4(),
                key: "".to_string(),
                data_type: "".to_string(),
                created_date: now,
                last_modified: now,
            },
            required: true,
        }]),
        organisation: Some(Organisation {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
        }),
    }
}

#[tokio::test]
async fn test_get_credential_schema_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let relations = CredentialSchemaRelations {
        claim_schemas: Some(ClaimSchemaRelations::default()),
        organisation: Some(OrganisationRelations::default()),
    };

    let schema = generic_credential_schema();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), eq(relations))
            .returning(move |_, _| Ok(clone.clone()));
    }

    let service = setup_service(repository, organisation_repository, generic_config());

    let result = service.get_credential_schema(&schema.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, schema.id);
}

#[tokio::test]
async fn test_get_credential_schema_fail() {
    let mut repository = MockCredentialSchemaRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let relations = CredentialSchemaRelations {
        claim_schemas: Some(ClaimSchemaRelations::default()),
        organisation: Some(OrganisationRelations::default()),
    };

    let mut schema = generic_credential_schema();
    schema.organisation = None;
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), eq(relations))
            .returning(move |_, _| Ok(clone.clone()));
    }

    let service = setup_service(repository, organisation_repository, generic_config());

    let organisation_is_none = service.get_credential_schema(&schema.id).await;
    assert!(organisation_is_none.is_err_and(|e| matches!(e, ServiceError::MappingError(_))));
}

#[tokio::test]
async fn test_get_credential_schema_list_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: 1,
        total_items: 3,
    };

    {
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(repository, organisation_repository, generic_config());

    let result = service
        .get_credential_schema_list(GetCredentialSchemaQueryDTO {
            page: 0,
            page_size: 5,
            sort: None,
            sort_direction: None,
            exact: None,
            name: None,
            organisation_id: "".to_string(),
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(3, result.total_items);
    assert_eq!(1, result.total_pages);
    assert_eq!(
        response.values.get(0).unwrap().id,
        result.values.get(0).unwrap().id
    );
    assert_eq!(
        response.values.get(1).unwrap().id,
        result.values.get(1).unwrap().id
    );
    assert_eq!(
        response.values.get(2).unwrap().id,
        result.values.get(2).unwrap().id
    );
}

#[tokio::test]
async fn test_delete_credential_schema() {
    let mut repository = MockCredentialSchemaRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let schema_id = Uuid::new_v4();

    {
        repository
            .expect_delete_credential_schema()
            .times(1)
            .with(eq(schema_id.to_owned()))
            .returning(move |_| Ok(()));
    }

    let service = setup_service(repository, organisation_repository, generic_config());

    let result = service.delete_credential_schema(&schema_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_schema_success() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();

    let now = OffsetDateTime::now_utc();
    let organisation = Organisation {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
    };
    let schema_id = Uuid::new_v4();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: 0,
        total_items: 0,
    };

    {
        let organisation = organisation.clone();
        organisation_repository
            .expect_get_organisation()
            .times(1)
            .with(
                eq(organisation.id.to_owned()),
                eq(OrganisationRelations::default()),
            )
            .returning(move |_, _| Ok(organisation.clone()));
        repository
            .expect_create_credential_schema()
            .times(1)
            .returning(move |_| Ok(schema_id.to_owned()));
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(repository, organisation_repository, generic_config());

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
            }],
        })
        .await;
    assert!(result.is_ok());
    assert_eq!(schema_id, result.unwrap());
}

#[tokio::test]
async fn test_create_credential_schema_unique_name_error() {
    let mut repository = MockCredentialSchemaRepository::default();

    let now = OffsetDateTime::now_utc();
    let organisation = Organisation {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
    };

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: 1,
        total_items: 1,
    };

    {
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_| Ok(response.clone()));
    }

    let service = setup_service(
        repository,
        MockOrganisationRepository::default(),
        generic_config(),
    );

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            organisation_id: organisation.id.to_owned(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
            }],
        })
        .await;
    assert!(result.is_err_and(|e| matches!(e, ServiceError::AlreadyExists)));
}

#[tokio::test]
async fn test_create_credential_schema_fail_validation() {
    let repository = MockCredentialSchemaRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let service = setup_service(repository, organisation_repository, generic_config());

    let non_existing_format = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "NON_EXISTING_FORMAT".to_string(),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
            }],
        })
        .await;
    assert!(non_existing_format.is_err_and(|e| matches!(e, ServiceError::ConfigValidationError(_))));

    let non_existing_revocation_method = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            revocation_method: "TEST".to_string(),
            organisation_id: Uuid::new_v4(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
            }],
        })
        .await;
    assert!(non_existing_revocation_method
        .is_err_and(|e| matches!(e, ServiceError::ConfigValidationError(_))));

    let wrong_datatype = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "BLABLA".to_string(),
                required: true,
            }],
        })
        .await;
    assert!(wrong_datatype.is_err_and(|e| matches!(e, ServiceError::ConfigValidationError(_))));

    let no_claims = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4(),
            claims: vec![],
        })
        .await;
    assert!(no_claims.is_err_and(|e| matches!(e, ServiceError::IncorrectParameters)));
}

#[tokio::test]
async fn test_create_credential_schema_fail_missing_organisation() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();

    let response = GetCredentialSchemaList {
        values: vec![
            generic_credential_schema(),
            generic_credential_schema(),
            generic_credential_schema(),
        ],
        total_pages: 0,
        total_items: 0,
    };

    {
        organisation_repository
            .expect_get_organisation()
            .times(1)
            .returning(move |_, _| Err(DataLayerError::RecordNotFound));
        let clone = response.clone();
        repository
            .expect_get_credential_schema_list()
            .times(1)
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(repository, organisation_repository, generic_config());

    let result = service
        .create_credential_schema(CreateCredentialSchemaRequestDTO {
            name: "cred".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            organisation_id: Uuid::new_v4(),
            claims: vec![CredentialClaimSchemaRequestDTO {
                key: "test".to_string(),
                datatype: "STRING".to_string(),
                required: true,
            }],
        })
        .await;

    assert!(result.is_err_and(|e| matches!(e, ServiceError::NotFound)));
}
