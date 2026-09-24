use std::path::Path;

use anyhow::Context;
use one_core::repository::error::DataLayerError;
use sea_orm::sea_query::{Expr, Func, QueryStatementBuilder, SimpleExpr};
use sea_orm::{ColumnTrait, Database, ExprTrait, Iden, Value};

use crate::list_query_generic::Hex;
use crate::transaction_context::TransactionManagerImpl;

pub async fn open_sqlite_on_path(path: &Path) -> Result<TransactionManagerImpl, DataLayerError> {
    Ok(TransactionManagerImpl::new(
        Database::connect(format!("sqlite:{}?mode=rw", path.to_string_lossy()))
            .await
            .context("failed to open sql from path")?,
    ))
}

pub struct JsonObject;

impl sea_orm::Iden for JsonObject {
    fn unquoted(&self) -> &str {
        "json_object"
    }
}

pub struct JsonArray;

impl sea_orm::Iden for JsonArray {
    fn unquoted(&self) -> &str {
        "json_array"
    }
}

pub struct JsonAgg;

impl sea_orm::Iden for JsonAgg {
    fn unquoted(&self) -> &str {
        "json_group_array"
    }
}

pub fn json_object_columns<T: Iden + ColumnTrait>(
    columns: impl IntoIterator<Item = T>,
) -> SimpleExpr {
    columns
        .into_iter()
        .fold(Func::cust(JsonObject), |state, column| {
            match column.def().get_column_type() {
                sea_orm::ColumnType::Blob => state.arg(column.to_string()).arg(
                    // Case statement required because hex(null) is not null but empty string
                    Expr::case(
                        column.into_expr().is_not_null(),
                        Func::cust(Hex).arg(column.into_expr()),
                    )
                    .finally(Value::String(None)), // null
                ),
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
