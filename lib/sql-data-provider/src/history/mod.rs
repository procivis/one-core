use sea_orm::DatabaseConnection;

pub mod mapper;
pub mod repository;

pub(crate) struct HistoryProvider {
    pub db: DatabaseConnection,
}

#[cfg(test)]
mod test;