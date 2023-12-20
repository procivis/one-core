use one_core::{
    model::organisation::{Organisation, OrganisationRelations},
    repository::DataRepository,
};
use sql_data_provider::{test_utilities::get_dummy_date, DataLayer, DbConn};
use uuid::Uuid;

pub struct DbClient {
    data_layer: DataLayer,
}

impl DbClient {
    pub fn new(db: DbConn) -> Self {
        Self {
            data_layer: DataLayer::build(db),
        }
    }

    pub async fn get_organisation(&self, id: Uuid) -> Organisation {
        self.data_layer
            .get_organisation_repository()
            .get_organisation(&id, &OrganisationRelations {})
            .await
            .unwrap()
    }

    pub async fn create_organisation(&self) -> Organisation {
        let id = Uuid::new_v4();

        let organisation = Organisation {
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };

        self.data_layer
            .get_organisation_repository()
            .create_organisation(organisation)
            .await
            .unwrap();

        self.get_organisation(id).await
    }
}
