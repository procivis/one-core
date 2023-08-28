use sea_orm::DatabaseConnection;

pub mod mapper;
pub mod repository;

mod create_did;
mod get_did;
mod get_did_by_value;
mod get_did_list;

#[cfg(test)]
mod test_utilities;

pub(crate) struct DidProvider {
    pub db: DatabaseConnection,
}
