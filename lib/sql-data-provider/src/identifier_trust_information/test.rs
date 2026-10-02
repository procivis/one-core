use one_core::model::identifier_trust_information::{IdentifierTrustInformation, SchemaFormat};
use one_core::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use shared_types::{BlobId, IdentifierId, IdentifierTrustInformationId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::entity::blob::BlobType;
use crate::identifier_trust_information::IdentifierTrustInformationProvider;
use crate::test_utilities::{
    get_dummy_date, insert_blob_to_database, insert_identifier, insert_organisation_to_database,
    setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub provider: IdentifierTrustInformationProvider,
    pub identifier_id: IdentifierId,
    blob_id: BlobId,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

    let identifier_id = insert_identifier(
        &db,
        "identifier",
        Uuid::new_v4(),
        None,
        organisation_id,
        false,
    )
    .await
    .unwrap();

    let blob_id = insert_blob_to_database(&db, None, BlobType::RegistrationCertificate, None)
        .await
        .unwrap();

    TestSetup {
        provider: IdentifierTrustInformationProvider {
            db: TransactionManagerImpl::new(db),
        },
        identifier_id,
        blob_id,
    }
}

#[tokio::test]
async fn test_create_identifier_trust_information() {
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let trust_info = IdentifierTrustInformation {
        id,
        identifier_id: setup.identifier_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        valid_from: None,
        valid_to: Some(get_dummy_date()),
        intended_use: Some("intended_use".to_string()),
        allowed_issuance_types: vec![SchemaFormat {
            format: "jwt_vc_json".to_string(),
            schema_id: "simple-format".to_string(),
        }],
        allowed_verification_types: vec![
            SchemaFormat {
                format: "mso_mdoc".to_string(),
                schema_id: "difficult,|-format".to_string(),
            },
            SchemaFormat {
                format: "vc+sd-jwt".to_string(),
                schema_id: "difficult,%25,|-format2".to_string(),
            },
        ],
        blob_id: setup.blob_id,
    };
    assert_eq!(id, setup.provider.create(trust_info).await.unwrap());
}

#[tokio::test]
async fn test_get_identifier_trust_information() {
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let trust_info = IdentifierTrustInformation {
        id,
        identifier_id: setup.identifier_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        valid_from: None,
        valid_to: Some(get_dummy_date()),
        intended_use: Some("intended_use".to_string()),
        allowed_issuance_types: vec![SchemaFormat {
            format: "jwt_vc_json".to_string(),
            schema_id: "simple-format".to_string(),
        }],
        allowed_verification_types: vec![
            SchemaFormat {
                format: "mso_mdoc".to_string(),
                schema_id: "difficult,|-format".to_string(),
            },
            SchemaFormat {
                format: "vc+sd-jwt".to_string(),
                schema_id: "difficult,%25,|-format2".to_string(),
            },
        ],
        blob_id: setup.blob_id,
    };
    setup.provider.create(trust_info.clone()).await.unwrap();

    let result = setup
        .provider
        .get_by_identifier_id(&setup.identifier_id)
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], trust_info);
}

#[tokio::test]
async fn test_delete_identifier_trust_information() {
    let setup = setup().await;
    let id: IdentifierTrustInformationId = Uuid::new_v4().into();
    setup
        .provider
        .create(IdentifierTrustInformation {
            id,
            identifier_id: setup.identifier_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            valid_from: None,
            valid_to: None,
            intended_use: None,
            allowed_issuance_types: vec![],
            allowed_verification_types: vec![],
            blob_id: setup.blob_id,
        })
        .await
        .unwrap();

    setup.provider.delete(&id).await.unwrap();

    let result = setup
        .provider
        .get_by_identifier_id(&setup.identifier_id)
        .await
        .unwrap();
    assert!(result.is_empty());
}
