use migration::runner::run_migrations;
use sea_orm::sqlx::MySql;
use sea_orm::{ConnectOptions, ConnectionTrait, DatabaseConnection, DbBackend};
use sea_schema::mysql::def::{
    ColumnDefault, ColumnInfo, ColumnKey, NumericAttr, Schema, StringAttr, TableDef, TimeAttr, Type,
};
use sea_schema::mysql::discovery::SchemaDiscovery;
use similar_asserts::assert_eq;

use super::{Column, ColumnType, DefaultValue, Table};

pub(super) async fn get_mysql_schema(url: &str) -> Box<dyn super::Schema> {
    let mut url: url::Url = url.parse().unwrap();
    // remove path to connect to cluster
    url.set_path("");

    let conn = sea_orm::Database::connect(url.to_owned()).await.unwrap();

    let db_name: String = ulid::Ulid::new().to_string();
    println!("USING DATABASE {db_name}");

    conn.execute_unprepared(&format!("CREATE DATABASE {db_name};"))
        .await
        .unwrap();
    conn.execute_unprepared(&format!("USE {db_name};"))
        .await
        .unwrap();

    url.set_path(&db_name);
    let pool = ConnectOptions::new(url.to_string())
        .sqlx_pool_options::<MySql>()
        .connect(url.as_str())
        .await
        .unwrap();

    run_migrations(&DatabaseConnection::from(pool.to_owned()))
        .await
        .unwrap();

    let schema_discovery = SchemaDiscovery::new(pool, &db_name);
    Box::new(SchemaWrapper(schema_discovery.discover().await.unwrap()))
}

#[derive(Debug)]
struct SchemaWrapper(Schema);

impl super::Schema for SchemaWrapper {
    fn backend(&self) -> DbBackend {
        DbBackend::MySql
    }

    fn table(&self, name: &str) -> Box<dyn Table> {
        let table = self.0.tables.iter().find(|t| t.info.name == name);
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
        let index = self.0.indexes.iter().find(|index| index.name == name);
        assert!(
            index.is_some(),
            "No index with name {name} exists in table {}",
            self.0.info.name
        );
        let index = index.unwrap();

        assert_eq!(
            index.unique, unique,
            "Index name {name} in table {}: wrong uniqueness",
            self.0.info.name
        );

        assert_eq!(
            index.parts.len(),
            columns.len(),
            "Index name {name} in table {}: wrong number of columns",
            self.0.info.name
        );

        for (index, part) in index.parts.iter().enumerate() {
            assert_eq!(
                part.column, columns[index],
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
            self.info.null, nullable,
            "Column {} in table {}: invalid nullability",
            self.info.name, self.table.info.name
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
        assert_eq!(
            self.info.key,
            ColumnKey::Primary,
            "Column {} in table {} not a primary key",
            self.info.name,
            self.table.info.name
        );
        Box::new(self.clone())
    }

    fn foreign_key(&self, name: &str, into_table: &str, column: &str) -> Box<dyn Column> {
        let foreign_key = self
            .table
            .foreign_keys
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
            foreign_key.referenced_table, into_table,
            "Column {} in table {} not a foreign key referencing table {into_table}",
            self.info.name, self.table.info.name
        );
        assert!(
            foreign_key.referenced_columns.contains(&column.to_string()),
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
                length: Some(length.unwrap_or(255)),
                ..Default::default()
            }),
            ColumnType::Uuid => Self::Char(StringAttr {
                length: Some(36),
                ..Default::default()
            }),
            ColumnType::TimestampMilliseconds => Self::DateTime(TimeAttr {
                fractional: Some(3),
            }),
            ColumnType::TimestampSeconds => Self::DateTime(Default::default()),
            ColumnType::Unsigned => Self::Int(NumericAttr {
                maximum: Some(10),
                unsigned: Some(true),
                ..Default::default()
            }),
            ColumnType::BigInt => Self::BigInt(NumericAttr {
                maximum: Some(20),
                ..Default::default()
            }),
            ColumnType::Boolean => Self::TinyInt(NumericAttr {
                maximum: Some(1),
                ..Default::default()
            }),
            ColumnType::Blob => Self::LongBlob,
            ColumnType::Json => Self::LongText(Default::default()),
            ColumnType::Text => Self::Text(Default::default()),
            ColumnType::VarBinary(length) => Self::Varbinary(StringAttr {
                length: Some(length.unwrap_or(255)),
                ..Default::default()
            }),
        }
    }
}

impl From<DefaultValue> for ColumnDefault {
    fn from(value: DefaultValue) -> Self {
        match value {
            DefaultValue::String(text) => Self::String(text),
            DefaultValue::Integer(number) => Self::Int(number),
        }
    }
}
