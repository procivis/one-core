use one_core::model::credential::{IssuerIdentity, VerifierCredentialData};
use one_core::repository::DataRepository;
use sea_orm::{ActiveModelTrait, IntoActiveModel};
use similar_asserts::assert_eq;

use super::*;

#[tokio::test]
async fn verifier_single_round_trip_preserves_relations_and_legacy_missing_holder() {
    let setup = setup_with_credential().await;
    let repositories = crate::DataLayer::build(setup.db.clone(), vec![]);
    let repository = repositories.get_credential_repository();
    let template = repository
        .get_credential(&setup.credential_id)
        .await
        .unwrap();
    let format = template
        .common()
        .schema
        .as_ref()
        .await
        .unwrap()
        .formats
        .as_ref()
        .await
        .unwrap()[0]
        .clone();
    let claim = Claim {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("verified value".into()),
        path: "key-0".into(),
        selectively_disclosable: false,
        schema: setup
            .credential_schema
            .claim_schemas
            .as_ref()
            .await
            .unwrap()[0]
            .clone()
            .into(),
    };
    let request = Credential::Verifier {
        common: CredentialCommon {
            id: Uuid::new_v4().into(),
            state: CredentialStateEnum::Accepted,
            ..template.common().clone()
        },
        verifier_data: VerifierCredentialData {
            issuer: IssuerIdentity {
                identifier: setup.identifier.clone().into(),
                certificate: None,
            },
            format: format.clone().into(),
            claims: vec![claim.clone()].into(),
            holder_identifier: None,
        },
    };
    let id = repository.create_credential(request).await.unwrap();
    let row = credential::Entity::find_by_id(id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.role, credential::CredentialRole::Verifier);
    assert_eq!(row.r#type, credential::CredentialType::Single);
    assert_eq!(row.issuer_identifier_id, Some(setup.identifier.id));
    assert_eq!(row.format, Some(format.id));
    assert!(row.credential_blob_id.is_none());

    let loaded = repository.get_credential(&id).await.unwrap();
    let Credential::Verifier { verifier_data, .. } = &loaded else {
        panic!("expected a verifier single");
    };
    assert_eq!(
        verifier_data.issuer.identifier.as_ref().await.unwrap().id,
        setup.identifier.id
    );
    assert_eq!(verifier_data.format.as_ref().await.unwrap().id, format.id);
    assert_eq!(verifier_data.claims.as_ref().await.unwrap()[0].id, claim.id);
    assert!(verifier_data.holder_identifier.is_none());

    let listed = repository
        .get_credential_list(CredentialListQuery {
            filtering: Some(CredentialFilterValue::CredentialIds(vec![id]).condition()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(matches!(
        listed.values.as_slice(),
        [Credential::Verifier { .. }]
    ));
}

#[rstest]
#[case::batch_parent(credential::CredentialType::BatchParent, true, true)]
#[case::batch_item(credential::CredentialType::BatchItem, true, true)]
#[case::missing_issuer(credential::CredentialType::Single, false, true)]
#[case::missing_format(credential::CredentialType::Single, true, false)]
#[tokio::test]
async fn invalid_verifier_rows_return_mapping_errors(
    #[case] credential_type: credential::CredentialType,
    #[case] has_issuer: bool,
    #[case] has_format: bool,
) {
    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    let format_id = crate::entity::credential_schema_format::Entity::find()
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap()
        .id;
    let mut row = credential::Entity::find_by_id(setup.credential_id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    row.role = Set(credential::CredentialRole::Verifier);
    row.r#type = Set(credential_type);
    row.issuer_identifier_id = Set(has_issuer.then_some(setup.identifier.id));
    row.format = Set(has_format.then_some(format_id));
    row.update(&setup.db).await.unwrap();

    assert!(matches!(
        repository.get_credential(&setup.credential_id).await,
        Err(DataLayerError::MappingError)
    ));
    assert!(matches!(
        repository
            .get_credential_list(CredentialListQuery::default())
            .await,
        Err(DataLayerError::MappingError)
    ));
}

#[rstest]
#[case::single(CredentialType::Single)]
#[case::batch_parent(CredentialType::BatchParent)]
#[case::batch_item(CredentialType::BatchItem)]
#[tokio::test]
async fn generic_verifier_credentials_cannot_be_persisted(#[case] credential_type: CredentialType) {
    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    let mut request = repository
        .get_credential(&setup.credential_id)
        .await
        .unwrap();
    request.common_mut().id = Uuid::new_v4().into();
    *request.role_mut().unwrap() = CredentialRole::Verifier;
    *request.type_mut().unwrap() = credential_type;
    assert!(matches!(
        repository.create_credential(request.clone()).await,
        Err(DataLayerError::MappingError)
    ));
    assert!(
        credential::Entity::find_by_id(request.common().id)
            .one(&setup.db)
            .await
            .unwrap()
            .is_none()
    );
}
