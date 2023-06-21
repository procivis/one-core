use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, Set};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::entities::organisation;

use super::data_model::{CreateOrganisationRequestDTO, CreateOrganisationResponseDTO};

pub(crate) async fn create_organisation(
    db: &DatabaseConnection,
    request: CreateOrganisationRequestDTO,
) -> Result<CreateOrganisationResponseDTO, DbErr> {
    let now = OffsetDateTime::now_utc();
    let id = request.id.unwrap_or_else(Uuid::new_v4);

    let organisation = organisation::ActiveModel {
        id: Set(id.to_string()),
        created_date: Set(now),
        last_modified: Set(now),
    }
    .insert(db)
    .await?;

    Ok(CreateOrganisationResponseDTO {
        id: organisation.id,
    })
}

#[cfg(test)]
mod tests {
    use sea_orm::{DbErr, EntityTrait};
    use uuid::Uuid;

    use super::*;
    use crate::{entities::Organisation, test_utilities::setup_test_database_and_connection};

    #[tokio::test]
    async fn create_organisation_id_provided() {
        let database = setup_test_database_and_connection().await.unwrap();

        let org_id = Uuid::new_v4();

        let request = CreateOrganisationRequestDTO { id: Some(org_id) };

        let response: Result<CreateOrganisationResponseDTO, DbErr> =
            create_organisation(&database, request).await;
        assert!(response.is_ok());
        assert_eq!(Uuid::parse_str(&response.unwrap().id).unwrap(), org_id);

        assert_eq!(Organisation::find().all(&database).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn create_organisation_id_not_provided() {
        let database = setup_test_database_and_connection().await.unwrap();

        let request = CreateOrganisationRequestDTO { id: None };

        let response: Result<CreateOrganisationResponseDTO, DbErr> =
            create_organisation(&database, request).await;
        assert!(response.is_ok());
        assert!(Uuid::parse_str(&response.unwrap().id).is_ok());

        assert_eq!(Organisation::find().all(&database).await.unwrap().len(), 1);
    }
}
