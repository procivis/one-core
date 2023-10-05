use sea_orm::DatabaseConnection;

pub mod repository;

pub(crate) struct KeyProvider {
    pub db: DatabaseConnection,
}

#[cfg(test)]
mod test;
