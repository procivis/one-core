use sea_orm::sea_query::{expr::Expr, IntoCondition, SimpleExpr};
use sea_orm::{
    ColumnTrait, Condition, DatabaseConnection, EntityTrait, IntoSimpleExpr, PaginatorTrait,
    QueryOrder, QuerySelect, RelationTrait, Select,
};

use crate::data_layer::{
    common::calculate_pages_count,
    common_queries::*,
    data_model::{
        CredentialDidCredentialSchemaCombined, DetailCredentialResponse, GetCredentialsResponse,
        GetListQueryParams, SortableCredentialColumn,
    },
    entities::{credential, credential_schema, credential_state, did, Credential},
    list_query::{GetEntityColumn, SelectWithListQuery},
    DataLayer, DataLayerError,
};

impl GetEntityColumn for SortableCredentialColumn {
    fn get_simple_expr(&self) -> SimpleExpr {
        match self {
            SortableCredentialColumn::CreatedDate => {
                credential::Column::CreatedDate.into_simple_expr()
            }
            SortableCredentialColumn::SchemaName => {
                credential_schema::Column::Name.into_simple_expr()
            }
            SortableCredentialColumn::IssuerDid => did::Column::Did.into_simple_expr(),
            SortableCredentialColumn::State => credential_state::Column::State.into_simple_expr(),
        }
    }
}

pub type GetCredentialsQuery = GetListQueryParams<SortableCredentialColumn>;

fn get_select_credentials_query(
    base_query: Select<Credential>,
    organisation_id: Option<String>,
) -> Select<Credential> {
    base_query
        .select_only()
        .columns([
            credential::Column::Id,
            credential::Column::CreatedDate,
            credential::Column::LastModified,
            credential::Column::IssuanceDate,
        ])
        .columns([did::Column::Did])
        .columns([credential_state::Column::State])
        .column_as(credential_schema::Column::Id, "schema_id")
        .column_as(credential_schema::Column::Name, "schema_name")
        .column_as(credential_schema::Column::Format, "schema_format")
        .column_as(
            credential_schema::Column::RevocationMethod,
            "schema_revocation_method",
        )
        .column_as(
            credential_schema::Column::CreatedDate,
            "schema_created_date",
        )
        .column_as(
            credential_schema::Column::LastModified,
            "schema_last_modified",
        )
        .column_as(
            credential_schema::Column::OrganisationId,
            "schema_organisation_id",
        )
        // add related issuerDid
        .join_rev(
            sea_orm::JoinType::LeftJoin,
            credential::Relation::IssuerDid.def().rev(),
        )
        // add related schema
        .join_rev(
            sea_orm::JoinType::InnerJoin,
            credential::Relation::CredentialSchema
                .def()
                .rev()
                .on_condition(move |_left, _right| match &organisation_id {
                    None => Condition::all(),
                    Some(id) => credential_schema::Column::OrganisationId
                        .eq(id)
                        .into_condition(),
                }),
        )
        // add latest state
        .column_as(
            Expr::col((
                credential_state::Entity,
                credential_state::Column::CreatedDate,
            ))
            .max(),
            "state_created_date",
        )
        .group_by(credential::Column::Id)
        .join(
            sea_orm::JoinType::InnerJoin,
            credential::Relation::CredentialState.def(),
        )
        // fallback ordering
        .order_by_desc(credential::Column::CreatedDate)
        .order_by_desc(credential::Column::Id)
}

async fn combine_with_claims(
    db: &DatabaseConnection,
    query: Select<Credential>,
) -> Result<Vec<DetailCredentialResponse>, DataLayerError> {
    let combined_credentials = query
        .into_model::<CredentialDidCredentialSchemaCombined>()
        .all(db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

    let credential_ids = combined_credentials
        .iter()
        .map(|model| model.id.clone())
        .collect::<Vec<_>>();

    let claims = fetch_claim_claim_schemas(db, credential_ids.as_slice()).await?;

    let result = combined_credentials
        .into_iter()
        .map(|value| {
            DetailCredentialResponse::from_combined_credential_did_and_credential_schema(
                value, &claims,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(result)
}

impl DataLayer {
    pub async fn get_credentials(
        &self,
        query_params: GetCredentialsQuery,
    ) -> Result<GetCredentialsResponse, DataLayerError> {
        let limit: u64 = query_params.page_size as u64;

        let query = get_select_credentials_query(
            Credential::find()
                .with_list_query(&query_params, &Some(vec![credential_schema::Column::Name])),
            Some(query_params.organisation_id),
        );

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(GetCredentialsResponse {
            values: combine_with_claims(&self.db, query).await?,
            total_pages: calculate_pages_count(items_count, limit),
            total_items: items_count,
        })
    }

    pub async fn get_all_credentials(
        &self,
    ) -> Result<Vec<DetailCredentialResponse>, DataLayerError> {
        let query = get_select_credentials_query(Credential::find(), None);
        combine_with_claims(&self.db, query).await
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::data_layer::{
        common_queries::insert_credential_state,
        data_model::{CredentialState, SortDirection, SortableCredentialColumn},
        entities::{claim_schema::Datatype, credential_state},
        get_credentials::GetCredentialsQuery,
        test_utilities::*,
        DataLayer,
    };

    struct TestData {
        pub data_layer: DataLayer,
        pub organisation_id: String,
        pub did_value: String,
        pub first_credential_id: String,
    }

    impl TestData {
        async fn new() -> TestData {
            let data_layer = setup_test_data_layer_and_connection().await.unwrap();

            let organisation_id = insert_organisation_to_database(&data_layer.db, None)
                .await
                .unwrap();
            let did_value = "test123";
            let did_id = insert_did(&data_layer.db, "did name", did_value, &organisation_id)
                .await
                .unwrap();
            let credential_schema_id = insert_credential_schema_to_database(
                &data_layer.db,
                None,
                &organisation_id,
                "test123",
            )
            .await
            .unwrap();
            let new_claims: Vec<(Uuid, bool, u32, Datatype)> = (0..4)
                .map(|i| (Uuid::new_v4(), i % 2 == 0, i, Datatype::String))
                .collect();
            insert_many_claims_schema_to_database(
                &data_layer.db,
                &credential_schema_id,
                &new_claims,
            )
            .await
            .unwrap();
            let first_credential_id =
                insert_credential(&data_layer.db, &credential_schema_id, &did_id)
                    .await
                    .unwrap();
            let _second_credential_id =
                insert_credential(&data_layer.db, &credential_schema_id, &did_id)
                    .await
                    .unwrap();

            Self {
                data_layer,
                organisation_id,
                did_value: did_value.to_string(),
                first_credential_id,
            }
        }
    }

    #[tokio::test]
    async fn get_credentials_test_simple() {
        let test_data = TestData::new().await;

        let credentials = test_data
            .data_layer
            .get_credentials(GetCredentialsQuery::from_pagination(
                0,
                2,
                test_data.organisation_id.to_owned(),
            ))
            .await;
        assert!(credentials.is_ok());
        let credentials = credentials.unwrap();
        assert_eq!(2, credentials.total_items);
        assert_eq!(1, credentials.total_pages);
        assert_eq!(CredentialState::Created, credentials.values[0].state);
        assert_eq!(CredentialState::Created, credentials.values[1].state);
        assert_eq!(
            test_data.did_value,
            credentials.values[0].issuer_did.to_owned().unwrap()
        );
        assert_eq!(
            test_data.did_value,
            credentials.values[1].issuer_did.to_owned().unwrap()
        );

        let later = OffsetDateTime::now_utc() + time::Duration::seconds(1);
        insert_credential_state(
            &test_data.data_layer.db,
            &test_data.first_credential_id,
            later,
            credential_state::CredentialState::Offered,
        )
        .await
        .unwrap();

        let credentials = test_data
            .data_layer
            .get_credentials(GetCredentialsQuery::from_pagination(
                0,
                2,
                test_data.organisation_id.to_owned(),
            ))
            .await;
        assert!(credentials.is_ok());
        let credentials = credentials.unwrap();
        assert_eq!(2, credentials.total_items);
        let item_index = credentials
            .values
            .iter()
            .position(|r| r.id == test_data.first_credential_id)
            .unwrap();
        assert_eq!(
            CredentialState::Offered,
            credentials.values[item_index].state
        );
    }

    #[tokio::test]
    async fn get_credentials_test_order_by_state() {
        let test_data = TestData::new().await;

        let later = OffsetDateTime::now_utc() + time::Duration::seconds(1);
        insert_credential_state(
            &test_data.data_layer.db,
            &test_data.first_credential_id,
            later,
            credential_state::CredentialState::Offered,
        )
        .await
        .unwrap();

        fn get_query_sort_by_state(
            organisation_id: &str,
            sort_direction: SortDirection,
        ) -> GetCredentialsQuery {
            GetCredentialsQuery {
                page: 0,
                page_size: 2,
                organisation_id: organisation_id.to_owned(),
                name: None,
                sort: Some(SortableCredentialColumn::State),
                sort_direction: Some(sort_direction),
            }
        }

        let credentials = test_data
            .data_layer
            .get_credentials(get_query_sort_by_state(
                &test_data.organisation_id,
                SortDirection::Descending,
            ))
            .await;
        assert!(credentials.is_ok());
        let credentials_descending = credentials.unwrap();
        assert_eq!(2, credentials_descending.total_items);
        assert_eq!(
            test_data.first_credential_id,
            credentials_descending.values[0].id
        );

        let credentials = test_data
            .data_layer
            .get_credentials(get_query_sort_by_state(
                &test_data.organisation_id,
                SortDirection::Ascending,
            ))
            .await;
        assert!(credentials.is_ok());
        let credentials_ascending = credentials.unwrap();
        assert_eq!(2, credentials_ascending.total_items);
        assert_eq!(
            test_data.first_credential_id,
            credentials_ascending.values[1].id
        );
    }

    #[tokio::test]
    async fn get_all_credentials_test_simple() {
        let test_data = TestData::new().await;

        let credentials = test_data.data_layer.get_all_credentials().await;
        assert!(credentials.is_ok());
        let credentials = credentials.unwrap();
        assert_eq!(2, credentials.len());
        assert_eq!(CredentialState::Created, credentials[0].state);
        assert_eq!(CredentialState::Created, credentials[1].state);
        assert_eq!(
            test_data.did_value,
            credentials[0].issuer_did.to_owned().unwrap()
        );
        assert_eq!(
            test_data.did_value,
            credentials[1].issuer_did.to_owned().unwrap()
        );
    }
}
