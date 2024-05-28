use sea_orm::DatabaseConnection;

mod mapper;
mod repository;

#[cfg(test)]
mod test;

pub struct ValidityCredentialProvider {
    db_conn: DatabaseConnection,
}

impl ValidityCredentialProvider {
    pub fn new(db_conn: DatabaseConnection) -> Self {
        Self { db_conn }
    }
}
