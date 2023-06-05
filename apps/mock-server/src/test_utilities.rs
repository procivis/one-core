use chrono::{DateTime, Duration, NaiveDate, NaiveTime, Utc};
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, Set};

use migration::{Migrator, MigratorTrait};
use one_core::entities::credential_schema;

pub fn get_dummy_date() -> DateTime<Utc> {
    DateTime::from_utc(
        NaiveDate::from_ymd_opt(2005, 4, 2)
            .unwrap()
            .and_time(NaiveTime::from_hms_opt(21, 37, 00).unwrap()),
        Utc,
    )
}

pub async fn insert_credential_schema_to_database(
    database: &DatabaseConnection,
    deleted_at: Option<DateTime<Utc>>,
) -> Result<u32, DbErr> {
    let schema = credential_schema::ActiveModel {
        id: Default::default(),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        format: Set(Default::default()),
        name: Set(Default::default()),
        revocation_method: Set(Default::default()),

        deleted_at: Set(deleted_at),
    }
    .insert(database)
    .await?;
    Ok(schema.id)
}

pub async fn get_credential_schema_with_id(
    database: &DatabaseConnection,
    id: u32,
) -> Result<Option<credential_schema::Model>, DbErr> {
    credential_schema::Entity::find_by_id(id)
        .one(database)
        .await
}

pub async fn setup_test_database_and_connection() -> Result<DatabaseConnection, DbErr> {
    let db = sea_orm::Database::connect("sqlite::memory:").await?;
    Migrator::up(&db, None).await?;
    Ok(db)
}

pub fn are_datetimes_within_minute(d1: DateTime<Utc>, d2: DateTime<Utc>) -> bool {
    (d2 - d1) < Duration::minutes(1)
}

#[test]
fn test_are_datetimes_within_minute() {
    let d1 = get_dummy_date();

    assert!(are_datetimes_within_minute(d1, d1 + Duration::seconds(10)));
    assert!(are_datetimes_within_minute(d1, d1 + Duration::seconds(30)));
    assert!(!are_datetimes_within_minute(
        d1,
        d1 + Duration::seconds(120)
    ));
}
