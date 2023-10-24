use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::repository::mock::credential_schema_repository::MockCredentialSchemaRepository;
use crate::service::oidc::OIDCService;
use mockall::predicate::eq;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

fn setup_service(repository: MockCredentialSchemaRepository) -> OIDCService {
    OIDCService::new(
        Some("http://127.0.0.1:3000".to_string()),
        Arc::new(repository),
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
        format: "JWT".to_string(),
        revocation_method: "".to_string(),
        claim_schemas: None,
        organisation: None,
    }
}

#[tokio::test]
async fn test_get_issuer_metadata_jwt() {
    let mut repository = MockCredentialSchemaRepository::default();
    let schema = generic_credential_schema();
    let relations = CredentialSchemaRelations::default();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), eq(relations))
            .returning(move |_, _| Ok(clone.clone()));
    }
    let service = setup_service(repository);
    let result = service.oidc_get_issuer_metadata(&schema.id).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(
        "jwt_vc_json".to_string(),
        result.credentials_supported.get(0).unwrap().format
    );
}

#[tokio::test]
async fn test_get_issuer_metadata_sd_jwt() {
    let mut repository = MockCredentialSchemaRepository::default();
    let mut schema = generic_credential_schema();
    schema.format = "SDJWT".to_string();
    let relations = CredentialSchemaRelations::default();
    {
        let clone = schema.clone();
        repository
            .expect_get_credential_schema()
            .times(1)
            .with(eq(schema.id.to_owned()), eq(relations))
            .returning(move |_, _| Ok(clone.clone()));
    }
    let service = setup_service(repository);
    let result = service.oidc_get_issuer_metadata(&schema.id).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(
        "vc+sd-jwt".to_string(),
        result.credentials_supported.get(0).unwrap().format
    );
}
