use sea_orm::DatabaseConnection;

mod helpers;
mod mappers;
mod models;
pub mod repository;

pub(crate) struct BackupProvider {
    db: DatabaseConnection,
    exportable_storages: Vec<String>,
}

#[cfg(test)]
mod test;
