use migration::runner::run_migrations;
use sea_orm::sqlx::Sqlite;
use sea_orm::{ConnectOptions, DatabaseConnection, DbBackend};
use sea_schema::sea_query::{ColumnType, StringLen};
use sea_schema::sqlite::def::{ColumnInfo, DefaultType, Schema, TableDef};
use sea_schema::sqlite::discovery::SchemaDiscovery;
use similar_asserts::assert_eq;

use super::{Column, DefaultValue, Table};

pub(super) async fn get_sqlite_schema(url: &str) -> Box<dyn super::Schema> {
    let pool = ConnectOptions::new(url)
        .sqlx_pool_options::<Sqlite>()
        .connect(url)
        .await
        .unwrap();

    run_migrations(&DatabaseConnection::from(pool.to_owned()))
        .await
        .unwrap();

    let schema_discovery = SchemaDiscovery::new(pool);
    Box::new(SchemaWrapper(
        schema_discovery
            .discover()
            .await
            .unwrap()
            .merge_indexes_into_table(),
    ))
}

#[derive(Debug)]
struct SchemaWrapper(Schema);

impl super::Schema for SchemaWrapper {
    fn backend(&self) -> DbBackend {
        DbBackend::Sqlite
    }

    fn table(&self, name: &str) -> Box<dyn Table> {
        let table = self.0.tables.iter().find(|t| t.name == name);
        assert!(table.is_some(), "Table {name} does not exist");
        Box::new(TableWrapper(table.unwrap().to_owned()))
    }
}

#[derive(Clone, Debug)]
struct TableWrapper(TableDef);

impl Table for TableWrapper {
    fn column(&self, name: &str) -> Box<dyn Column> {
        let column = self.0.columns.iter().find(|column| column.name == name);
        assert!(
            column.is_some(),
            "Column {name} does not exist in table {}",
            self.0.name
        );
        Box::new(ColumnWrapper {
            info: column.unwrap().to_owned(),
            table: self.0.to_owned(),
        })
    }

    fn columns(&self, columns: &[&str]) -> Box<dyn Table> {
        for column in columns {
            self.column(column);
        }
        for column in &self.0.columns {
            assert!(
                columns.contains(&column.name.as_str()),
                "Unknown column {} exists in table {}",
                column.name,
                self.0.name
            );
        }
        Box::new(self.clone())
    }

    fn index(&self, name: &str, unique: bool, columns: &[&str]) -> Box<dyn Table> {
        let constraint = self
            .0
            .constraints
            .iter()
            .find(|constraint| constraint.index_name == name);
        assert!(
            constraint.is_some(),
            "No index with name {name} exists in table {}",
            self.0.name
        );
        let constraint = constraint.unwrap();

        assert_eq!(
            constraint.unique, unique,
            "Index name {name} in table {}: wrong uniqueness",
            self.0.name
        );

        assert_eq!(
            constraint.columns.len(),
            columns.len(),
            "Index name {name} in table {}: wrong number of columns",
            self.0.name
        );

        for (index, column) in constraint.columns.iter().enumerate() {
            // bug in sea-schema - empty string for COALESCEd columns
            if column.is_empty() {
                continue;
            }

            assert_eq!(
                column, columns[index],
                "Index name {name} in table {}: wrong column/order",
                self.0.name
            );
        }

        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
struct ColumnWrapper {
    info: ColumnInfo,
    table: TableDef,
}

impl Column for ColumnWrapper {
    fn r#type(&self, r#type: super::ColumnType) -> Box<dyn Column> {
        assert_eq!(
            self.info.r#type,
            r#type.into(),
            "Column {} in table {}: invalid type",
            self.info.name,
            self.table.name
        );
        Box::new(self.clone())
    }

    fn nullable(&self, nullable: bool) -> Box<dyn Column> {
        assert_eq!(
            self.info.not_null, !nullable,
            "Column {} in table {}: invalid nullability",
            self.info.name, self.table.name
        );
        Box::new(self.clone())
    }

    fn default(&self, default: Option<DefaultValue>) -> Box<dyn Column> {
        let default = if let Some(default) = default {
            default.into()
        } else {
            DefaultType::Unspecified
        };
        assert_eq!(
            self.info.default_value, default,
            "Column {} in table {}: invalid default value",
            self.info.name, self.table.name
        );
        Box::new(self.clone())
    }

    fn primary_key(&self) -> Box<dyn Column> {
        assert_eq!(
            self.info.primary_key, true,
            "Column {} in table {} not a primary key",
            self.info.name, self.table.name
        );
        Box::new(self.clone())
    }

    fn foreign_key(&self, _name: &str, into_table: &str, column: &str) -> Box<dyn Column> {
        let foreign_key = self
            .table
            .foreign_keys
            .iter()
            .find(|foreign_key| foreign_key.from.contains(&self.info.name));
        assert!(
            foreign_key.is_some(),
            "No foreign key for column {} in table {}",
            self.info.name,
            self.table.name
        );
        let foreign_key = foreign_key.unwrap();
        assert_eq!(
            foreign_key.table, into_table,
            "Column {} in table {} not a foreign key referencing table {into_table}",
            self.info.name, self.table.name
        );
        assert!(
            foreign_key.to.contains(&column.to_string()),
            "Column {} in table {} not a foreign key referencing column {column} in {into_table}",
            self.info.name,
            self.table.name
        );
        Box::new(self.clone())
    }
}

impl From<super::ColumnType> for ColumnType {
    fn from(value: super::ColumnType) -> Self {
        match value {
            super::ColumnType::String(size) => Self::String(if let Some(size) = size {
                StringLen::N(size)
            } else {
                StringLen::None
            }),
            super::ColumnType::Uuid => Self::Char(Some(36)),
            super::ColumnType::TimestampMilliseconds | super::ColumnType::TimestampSeconds => {
                Self::Custom("datetime".into())
            }
            super::ColumnType::Unsigned => Self::BigInteger,
            super::ColumnType::Boolean => Self::Boolean,
            super::ColumnType::Blob => Self::Blob,
        }
    }
}

impl From<DefaultValue> for DefaultType {
    fn from(value: DefaultValue) -> Self {
        match value {
            DefaultValue::String(text) => Self::String(text),
            DefaultValue::Integer(number) => Self::Integer(number),
        }
    }
}
