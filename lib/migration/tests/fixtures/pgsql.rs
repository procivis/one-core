use std::sync::LazyLock;

use migration::test_utilities::{INIT_DB_SCHEMA, prepare_init_db, with_database};
use regex::Regex;
use sea_orm::sqlx::Postgres;
use sea_orm::{ConnectOptions, ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use sea_schema::postgres::def::{
    ColumnDefault, ColumnInfo, Schema, StringAttr, TableDef, TimeAttr, Type,
};
use sea_schema::postgres::discovery::SchemaDiscovery;
use similar_asserts::assert_eq;

use crate::fixtures::{Column, ColumnType, DefaultValue, Table};

pub(super) async fn get_pgsql_schema(url: &str) -> Box<dyn super::Schema> {
    let url = url.parse().unwrap();
    prepare_init_db(&url).await;
    println!("USING DATABASE {INIT_DB_SCHEMA}");

    let url = with_database(&url, INIT_DB_SCHEMA);
    let conn = sea_orm::Database::connect(url.to_owned()).await.unwrap();
    let non_unique_indexes = extract_non_unique_indexes(&conn).await;

    let pool = ConnectOptions::new(url.to_string())
        .sqlx_pool_options::<Postgres>()
        .connect(url.as_str())
        .await
        .unwrap();

    let schema = SchemaDiscovery::new(pool, "public")
        .discover()
        .await
        .unwrap();
    Box::new(SchemaWrapper(schema, non_unique_indexes))
}

#[derive(Debug, Clone)]
struct NonUniqueIndex {
    table: String,
    name: String,
    columns: Vec<String>,
}

static COLUMNS_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\([\w, ]+\)$").unwrap());

async fn extract_non_unique_indexes(conn: &DatabaseConnection) -> Vec<NonUniqueIndex> {
    let query_result = conn
        .query_all_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT indexname, tablename, indexdef FROM pg_indexes;",
        ))
        .await
        .unwrap();

    let mut result = vec![];
    for row in query_result {
        let name: String = row.try_get_by_index(0).unwrap();
        let table: String = row.try_get_by_index(1).unwrap();
        let def: String = row.try_get_by_index(2).unwrap();

        if def.starts_with(&format!("CREATE INDEX \"{name}\" ON"))
            && let Some(columns) = COLUMNS_REGEX.find(&def)
        {
            let columns = columns.as_str().trim_matches(['(', ')']);
            let columns = columns
                .split(", ")
                .map(|column| {
                    column
                        .trim_end_matches(" ASC")
                        .trim_end_matches(" DESC")
                        .to_string()
                })
                .collect();

            result.push(NonUniqueIndex {
                name,
                table,
                columns,
            });
        }
    }
    result
}

#[derive(Debug)]
struct SchemaWrapper(Schema, Vec<NonUniqueIndex>);

impl super::Schema for SchemaWrapper {
    fn backend(&self) -> DbBackend {
        DbBackend::Postgres
    }

    fn table(&self, name: &str) -> Box<dyn Table> {
        let table = self.0.tables.iter().find(|t| t.info.name == name);
        assert!(table.is_some(), "Table {name} does not exist");

        let non_unique_indexes = self
            .1
            .iter()
            .filter(|index| index.table == name)
            .map(ToOwned::to_owned)
            .collect();
        Box::new(TableWrapper(table.unwrap().to_owned(), non_unique_indexes))
    }
}

#[derive(Clone, Debug)]
struct TableWrapper(TableDef, Vec<NonUniqueIndex>);

impl Table for TableWrapper {
    fn column(&self, name: &str) -> Box<dyn Column> {
        let column = self.0.columns.iter().find(|column| column.name == name);
        assert!(
            column.is_some(),
            "Column {name} does not exist in table {}",
            self.0.info.name
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
                self.0.info.name
            );
        }
        Box::new(self.clone())
    }

    fn index(&self, name: &str, unique: bool, columns: &[&str]) -> Box<dyn Table> {
        // PostgreSQL has a limit of 63 characters for index names, so we need to truncate the name
        let name = if name.len() > 63 { &name[..63] } else { name };

        let index_columns = if unique {
            let index = self
                .0
                .unique_constraints
                .iter()
                .find(|index| index.name == name);
            assert!(
                index.is_some(),
                "No unique index with name {name} exists in table {}",
                self.0.info.name
            );

            &index.unwrap().columns
        } else {
            let index = self.1.iter().find(|index| index.name == name);
            assert!(
                index.is_some(),
                "No non-unique index with name {name} exists in table {}",
                self.0.info.name
            );

            &index.unwrap().columns
        };

        assert_eq!(
            index_columns.len(),
            columns.len(),
            "Index name {name} in table {}: wrong number of columns",
            self.0.info.name
        );

        for (idx, col) in index_columns.iter().enumerate() {
            assert_eq!(
                col, columns[idx],
                "Index name {name} in table {}: wrong column/order",
                self.0.info.name
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
    fn r#type(&self, r#type: ColumnType) -> Box<dyn Column> {
        assert_eq!(
            self.info.col_type,
            r#type.into(),
            "Column {} in table {}: invalid type",
            self.info.name,
            self.table.info.name
        );
        Box::new(self.clone())
    }

    fn nullable(&self, nullable: bool) -> Box<dyn Column> {
        assert_eq!(
            self.info.not_null.is_none(),
            nullable,
            "Column {} in table {}: invalid nullability",
            self.info.name,
            self.table.info.name
        );
        Box::new(self.clone())
    }

    fn default(&self, default: Option<DefaultValue>) -> Box<dyn Column> {
        assert_eq!(
            self.info.default,
            default.map(Into::into),
            "Column {} in table {}: invalid default value",
            self.info.name,
            self.table.info.name
        );
        Box::new(self.clone())
    }

    fn primary_key(&self) -> Box<dyn Column> {
        assert!(
            self.table.primary_key_constraints.len() == 1
                && self.table.primary_key_constraints[0]
                    .columns
                    .contains(&self.info.name),
            "Column {} in table {} not a primary key",
            self.info.name,
            self.table.info.name
        );
        Box::new(self.clone())
    }

    fn foreign_key(&self, name: &str, into_table: &str, column: &str) -> Box<dyn Column> {
        let foreign_key = self
            .table
            .reference_constraints
            .iter()
            .find(|foreign_key| foreign_key.columns.contains(&self.info.name));
        assert!(
            foreign_key.is_some(),
            "No foreign key for column {} in table {}",
            self.info.name,
            self.table.info.name
        );
        let foreign_key = foreign_key.unwrap();
        assert_eq!(
            foreign_key.name, name,
            "Column {} in table {}: invalid foreign key name",
            self.info.name, self.table.info.name
        );
        assert_eq!(
            foreign_key.table, into_table,
            "Column {} in table {} not a foreign key referencing table {into_table}",
            self.info.name, self.table.info.name
        );
        assert!(
            foreign_key.foreign_columns.contains(&column.to_string()),
            "Column {} in table {} not a foreign key referencing column {column} in {into_table}",
            self.info.name,
            self.table.info.name
        );
        Box::new(self.clone())
    }
}

impl From<ColumnType> for Type {
    fn from(value: ColumnType) -> Self {
        match value {
            ColumnType::String(length) => Self::Varchar(StringAttr {
                length: length.map(|len| len as u16),
            }),
            ColumnType::Uuid => Self::Char(StringAttr { length: Some(36) }),
            ColumnType::TimestampMilliseconds => {
                Self::TimestampWithTimeZone(TimeAttr { precision: Some(3) })
            }
            ColumnType::TimestampSeconds => {
                Self::TimestampWithTimeZone(TimeAttr { precision: Some(0) })
            }
            ColumnType::Integer => Self::Integer,
            ColumnType::BigInt => Self::BigInt,
            ColumnType::Boolean => Self::Boolean,
            ColumnType::Blob => Self::Bytea,
            ColumnType::Json => Self::Json,
            ColumnType::JsonBinary => Self::JsonBinary,
            ColumnType::Text => Self::Text,
            ColumnType::VarBinary(_) => Self::Bytea,
        }
    }
}

impl From<DefaultValue> for ColumnDefault {
    fn from(value: DefaultValue) -> Self {
        match value {
            DefaultValue::String(text) => Self::String(text),
            DefaultValue::Integer(number) => Self::Int(number),
            DefaultValue::Boolean(bool) => Self::Bool(bool),
        }
    }
}
