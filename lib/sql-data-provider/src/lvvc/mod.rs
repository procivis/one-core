use sea_orm::DatabaseConnection;

mod mapper;
mod repository;

#[cfg(test)]
mod test;

pub struct LvvcProvider {
    db_conn: DatabaseConnection,
}

impl LvvcProvider {
    pub fn new(db_conn: DatabaseConnection) -> Self {
        Self { db_conn }
    }
}
