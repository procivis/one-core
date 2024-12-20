use std::fmt::Write;
use std::path::Path;

use anyhow::Context;
use one_core::repository::error::DataLayerError;
use sea_orm::sea_query::{Func, QueryStatementBuilder, SimpleExpr};
use sea_orm::{ColumnTrait, Database, DatabaseConnection, Iden};

use crate::list_query_generic::Hex;

pub async fn open_sqlite_on_path(path: &Path) -> Result<DatabaseConnection, DataLayerError> {
    Database::connect(format!("sqlite:{}?mode=rw", path.to_string_lossy()))
        .await
        .context("failed to open sql from path")
        .map_err(Into::into)
}

pub struct JsonObject;

impl sea_orm::Iden for JsonObject {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "json_object").unwrap();
    }
}

pub struct JsonArray;

impl sea_orm::Iden for JsonArray {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "json_array").unwrap();
    }
}

pub struct JsonAgg;

impl sea_orm::Iden for JsonAgg {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "json_group_array").unwrap();
    }
}

pub fn json_object_columns<T: Iden + ColumnTrait>(
    columns: impl IntoIterator<Item = T>,
) -> SimpleExpr {
    columns
        .into_iter()
        .fold(Func::cust(JsonObject), |state, column| {
            match column.def().get_column_type() {
                sea_orm::ColumnType::Blob => state
                    .arg(column.to_string())
                    .arg(Func::cust(Hex).arg(column.into_expr())),
                _ => state.arg(column.to_string()).arg(column.into_expr()),
            }
        })
        .into()
}

pub fn coalesce_to_empty_array<T: QueryStatementBuilder>(expr: T) -> SimpleExpr {
    Func::coalesce([
        SimpleExpr::SubQuery(None, Box::new(expr.into_sub_query_statement())),
        Func::cust(JsonArray).into(),
    ])
    .into()
}
