use std::fmt::Debug;

use sea_orm::DbBackend;

mod mysql;
mod sqlite;

pub(super) async fn fetch_schema() -> Box<dyn Schema> {
    let url = std::env::var("ONE_app__databaseUrl").unwrap_or("sqlite::memory:".to_string());
    let schema = if url.starts_with("mysql:") {
        mysql::get_mysql_schema(&url).await
    } else {
        sqlite::get_sqlite_schema(&url).await
    };
    println!("DB: {:?}", schema.backend());
    schema
}

pub(super) trait Schema: Debug {
    fn backend(&self) -> DbBackend;
    fn table(&self, name: &str) -> Box<dyn Table>;
}

pub(super) trait Table: Debug {
    fn column(&self, name: &str) -> Box<dyn Column>;

    fn columns(&self, columns: &[&str]) -> Box<dyn Table>;
    fn index(&self, name: &str, unique: bool, columns: &[&str]) -> Box<dyn Table>;
}

pub(super) trait Column: Debug {
    fn r#type(&self, r#type: ColumnType) -> Box<dyn Column>;
    fn nullable(&self, nullable: bool) -> Box<dyn Column>;
    fn default(&self, default: Option<DefaultValue>) -> Box<dyn Column>;
    fn primary_key(&self) -> Box<dyn Column>;
    fn foreign_key(&self, name: &str, into_table: &str, column: &str) -> Box<dyn Column>;
}

#[derive(Debug)]
pub(super) enum ColumnType {
    String(Option<u32>),
    Uuid,
    TimestampMilliseconds,
    TimestampSeconds,
    Unsigned,
    BigInt,
    Boolean,
    Blob,
    Json,
    Text,
}

#[derive(Debug)]
#[expect(dead_code)]
pub(super) enum DefaultValue {
    String(String),
    Integer(i64),
}
