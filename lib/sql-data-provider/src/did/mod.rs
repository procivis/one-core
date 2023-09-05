use sea_orm::DatabaseConnection;

pub mod mapper;
pub mod repository;

pub(crate) struct DidProvider {
    pub db: DatabaseConnection,
}

#[cfg(test)]
mod test;
