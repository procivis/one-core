use sea_orm::DatabaseConnection;

pub mod history;
mod mapper;
pub mod repository;

#[cfg(test)]
mod test;

pub(crate) struct OrganisationProvider {
    pub db: DatabaseConnection,
}
