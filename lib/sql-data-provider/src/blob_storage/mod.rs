use sea_orm::DatabaseConnection;
pub mod mapper;
pub mod repository;
pub(crate) struct BlobProvider {
    db: DatabaseConnection,
}

impl BlobProvider {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[cfg(test)]
mod test;
