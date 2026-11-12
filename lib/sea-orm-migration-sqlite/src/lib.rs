mod introspection;
mod model;
mod statements;
#[cfg(test)]
mod tests;

use sea_orm::sea_query::{
    Alias, Expr, ExprTrait, ForeignKeyCreateStatement, IndexCreateStatement, IntoColumnDef,
    IntoIden, IntoTableRef, Query, SelectStatement, Table, TableName, TableRef,
};
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseTransaction, DbBackend, DbErr, TransactionTrait,
};
use sea_orm_migration::SchemaManager;

use crate::introspection::{
    ForeignKeyInfo, ReferencingForeignKey, TableInfo, UniqueConstraintInfo, autoincrement_sequence,
    foreign_key_violations, load_table, pragma_flag, referencing_foreign_keys,
    restore_autoincrement_sequence, same_name, same_names, table_exists,
};
use crate::model::TableRecreateOperation;
use crate::statements::plan_recreate;

const TEMP_TABLE_PREFIX: &str = "_temp_table_";

pub trait TableExt {
    fn recreate() -> TableRecreateStatement {
        TableRecreateStatement::new()
    }
}

impl TableExt for Table {}

pub trait SchemaManagerExt {
    fn recreate_table(
        &self,
        stmt: TableRecreateStatement,
    ) -> impl Future<Output = Result<(), DbErr>> + Send;
}

impl SchemaManagerExt for SchemaManager<'_> {
    async fn recreate_table(&self, stmt: TableRecreateStatement) -> Result<(), DbErr> {
        if self.get_database_backend() != DatabaseBackend::Sqlite {
            return Err(DbErr::Migration(
                "Only sqlite supports table recreation operation".to_owned(),
            ));
        }
        let table = stmt.table_name()?;

        let tx = self.get_connection().begin().await?;
        let defer_foreign_keys = pragma_flag(&tx, "defer_foreign_keys").await?;
        let result = recreate(&tx, &table, &stmt).await;
        let restored = restore_defer_foreign_keys(&tx, defer_foreign_keys).await;

        match result.and(restored) {
            Ok(()) => {
                tx.commit().await?;
                tracing::debug!("recreated table `{table}`");
                Ok(())
            }
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::warn!(%rollback_error, "failed to roll back recreation of table `{table}`");
                }
                Err(error)
            }
        }
    }
}

async fn recreate(
    tx: &DatabaseTransaction,
    table_name: &str,
    stmt: &TableRecreateStatement,
) -> Result<(), DbErr> {
    let operations = stmt.operations.as_slice();
    let table = load_table(tx, table_name).await?;
    let unsupported_features = table.unsupported_features();
    if !unsupported_features.is_empty() {
        return Err(DbErr::Migration(format!(
            "Table `{table_name}` uses features that can't be preserved when recreating it: {}",
            unsupported_features.join(", ")
        )));
    }

    let table = if rename_columns(tx, &table, operations).await? {
        load_table(tx, &table.name).await?
    } else {
        table
    };

    let temp_table = format!("{TEMP_TABLE_PREFIX}{}", table.name);
    if table_exists(tx, &temp_table).await? {
        return Err(DbErr::Migration(format!(
            "Cannot recreate table `{}`: table `{temp_table}` already exists",
            table.name
        )));
    }
    let foreign_keys = pragma_flag(tx, "foreign_keys").await?;
    let self_reference_table = if foreign_keys {
        temp_table.as_str()
    } else {
        table.name.as_str()
    };
    let plan = plan_recreate(
        &table,
        &temp_table,
        operations,
        stmt.discard_indexes,
        self_reference_table,
    )?;

    let referencing_foreign_keys = referencing_foreign_keys(tx, &table.name).await?;
    let reference_backups = if foreign_keys {
        backup_destructive_references(tx, &table.name, &referencing_foreign_keys).await?
    } else {
        Vec::new()
    };
    let mut checked_tables = vec![table.name.clone()];
    for foreign_key in referencing_foreign_keys {
        if !stmt.skip_referencing_foreign_key_check
            && !checked_tables
                .iter()
                .any(|t| same_name(t, &foreign_key.table))
        {
            checked_tables.push(foreign_key.table);
        }
    }
    let mut violations_before = Vec::with_capacity(checked_tables.len());
    for checked_table in &checked_tables {
        violations_before.push(foreign_key_violations(tx, checked_table).await.ok());
    }
    let sequence = if table.auto_increment {
        autoincrement_sequence(tx, &table.name).await?
    } else {
        None
    };

    tx.execute_unprepared("PRAGMA defer_foreign_keys = ON")
        .await?;
    tracing::trace!("creating table `{temp_table}`: {:?}", plan.create_table);
    tx.execute_raw(DbBackend::Sqlite.build(&plan.create_table))
        .await?;
    tx.execute_raw(DbBackend::Sqlite.build(&plan.copy_data))
        .await?;
    tx.execute_raw(
        DbBackend::Sqlite.build(&Table::drop().table(Alias::new(&table.name)).to_owned()),
    )
    .await?;
    let legacy_alter_table = pragma_flag(tx, "legacy_alter_table").await?;
    tx.execute_unprepared("PRAGMA legacy_alter_table = ON")
        .await?;
    let renamed = tx
        .execute_raw(
            DbBackend::Sqlite.build(
                &Table::rename()
                    .table(Alias::new(&temp_table), Alias::new(&table.name))
                    .to_owned(),
            ),
        )
        .await;
    if !legacy_alter_table {
        tx.execute_unprepared("PRAGMA legacy_alter_table = OFF")
            .await?;
    }
    renamed?;

    restore_references(tx, &reference_backups).await?;
    if let Some(sequence) = sequence {
        restore_autoincrement_sequence(tx, &table.name, sequence).await?;
    }
    let indexes = if stmt.discard_indexes {
        &[][..]
    } else {
        table.indexes.as_slice()
    };
    for sql in indexes
        .iter()
        .map(|index| &index.sql)
        .chain(&table.triggers)
    {
        tracing::trace!("recreating `{sql}`");
        tx.execute_unprepared(sql).await?;
    }

    if stmt.skip_foreign_key_check {
        return Ok(());
    }
    ensure_no_new_foreign_key_violations(tx, &table.name, &checked_tables, &violations_before).await
}

async fn rename_columns(
    tx: &DatabaseTransaction,
    table: &TableInfo,
    operations: &[TableRecreateOperation],
) -> Result<bool, DbErr> {
    let mut columns: Vec<String> = table.columns.iter().map(|c| c.name.clone()).collect();
    let mut renamed = false;
    for operation in operations {
        let TableRecreateOperation::RenameColumn(from, to) = operation else {
            continue;
        };
        let (from, to) = (from.to_string(), to.to_string());
        if !same_name(&from, &to) && columns.iter().any(|c| same_name(c, &to)) {
            return Err(DbErr::Migration(format!(
                "Cannot rename column `{from}` to `{to}`: column `{to}` already exists"
            )));
        }
        let Some(column) = columns.iter_mut().find(|c| same_name(c, &from)) else {
            return Err(DbErr::Migration(format!(
                "Cannot rename column `{from}`: it doesn't exist"
            )));
        };
        *column = to.clone();
        tx.execute_raw(
            DbBackend::Sqlite.build(
                &Table::alter()
                    .table(Alias::new(&table.name))
                    .rename_column(Alias::new(&from), Alias::new(&to))
                    .to_owned(),
            ),
        )
        .await?;
        renamed = true;
    }
    Ok(renamed)
}

struct ReferenceBackup {
    backup_table: String,
    table: String,
    columns: Vec<String>,
}

async fn backup_destructive_references(
    tx: &DatabaseTransaction,
    table: &str,
    referencing_foreign_keys: &[ReferencingForeignKey],
) -> Result<Vec<ReferenceBackup>, DbErr> {
    let mut backups = Vec::new();
    for foreign_key in referencing_foreign_keys {
        let on_delete = foreign_key.on_delete.to_ascii_uppercase();
        if !matches!(on_delete.as_str(), "CASCADE" | "SET NULL" | "SET DEFAULT") {
            continue;
        }
        let mut select = Query::select();
        select
            .expr(Expr::val(1))
            .from(Alias::new(&foreign_key.table))
            .limit(1);
        for column in &foreign_key.columns {
            select.and_where(Expr::col(Alias::new(column)).is_not_null());
        }
        if tx
            .query_one_raw(DbBackend::Sqlite.build(&select))
            .await?
            .is_none()
        {
            continue;
        }
        if on_delete == "CASCADE" {
            return Err(DbErr::Migration(format!(
                "Cannot recreate table `{table}`: rows in `{}` reference it with ON DELETE {on_delete} and would be deleted by SQLite when the table is dropped",
                foreign_key.table
            )));
        }

        let backup_table = format!("{TEMP_TABLE_PREFIX}fk_backup_{}", backups.len());
        let columns = foreign_key
            .columns
            .iter()
            .map(|c| quoted(c))
            .collect::<Vec<_>>();
        tx.execute_unprepared(&format!(
            "DROP TABLE IF EXISTS temp.{}",
            quoted(&backup_table)
        ))
        .await?;
        tx.execute_unprepared(&format!(
            "CREATE TEMP TABLE {} AS SELECT rowid AS \"rid\", {} FROM {} WHERE {}",
            quoted(&backup_table),
            columns.join(", "),
            quoted(&foreign_key.table),
            columns
                .iter()
                .map(|c| format!("{c} IS NOT NULL"))
                .collect::<Vec<_>>()
                .join(" AND ")
        ))
        .await?;
        backups.push(ReferenceBackup {
            backup_table,
            table: foreign_key.table.clone(),
            columns: foreign_key.columns.clone(),
        });
    }
    Ok(backups)
}

async fn restore_references(
    tx: &DatabaseTransaction,
    backups: &[ReferenceBackup],
) -> Result<(), DbErr> {
    for backup in backups {
        let assignments = backup
            .columns
            .iter()
            .map(|c| format!("{} = \"backup\".{}", quoted(c), quoted(c)))
            .collect::<Vec<_>>()
            .join(", ");
        tx.execute_unprepared(&format!(
            "UPDATE {table} SET {assignments} FROM temp.{backup} AS \"backup\" WHERE {table}.rowid = \"backup\".\"rid\"",
            table = quoted(&backup.table),
            backup = quoted(&backup.backup_table),
        ))
        .await?;
        tx.execute_unprepared(&format!("DROP TABLE temp.{}", quoted(&backup.backup_table)))
            .await?;
    }
    Ok(())
}

fn quoted(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

async fn ensure_no_new_foreign_key_violations(
    tx: &DatabaseTransaction,
    table: &str,
    checked_tables: &[String],
    violations_before: &[Option<i64>],
) -> Result<(), DbErr> {
    for (checked_table, before) in checked_tables.iter().zip(violations_before) {
        match (foreign_key_violations(tx, checked_table).await, before) {
            (Ok(after), before) if after > before.unwrap_or(0) => {
                return Err(DbErr::Migration(format!(
                    "Recreating table `{table}` would introduce {} foreign key violation(s) in table `{checked_table}`",
                    after - before.unwrap_or(0)
                )));
            }
            (Ok(_), _) | (Err(_), None) => {}
            (Err(error), Some(_)) => {
                return Err(DbErr::Migration(format!(
                    "Recreating table `{table}` would break foreign keys of table `{checked_table}`: {error}"
                )));
            }
        }
    }
    Ok(())
}

async fn restore_defer_foreign_keys(tx: &DatabaseTransaction, enabled: bool) -> Result<(), DbErr> {
    tx.execute_unprepared("PRAGMA defer_foreign_keys = OFF")
        .await?;
    if enabled {
        tx.execute_unprepared("PRAGMA defer_foreign_keys = ON")
            .await?;
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
pub struct TableRecreateStatement {
    table: Option<TableRef>,
    operations: Vec<TableRecreateOperation>,
    skip_referencing_foreign_key_check: bool,
    skip_foreign_key_check: bool,
    discard_indexes: bool,
}

impl TableRecreateStatement {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn table<T: IntoTableRef>(&mut self, table: T) -> &mut Self {
        self.table = Some(table.into_table_ref());
        self
    }

    pub fn add_column<T: IntoColumnDef>(&mut self, column: T) -> &mut Self {
        self.operations.push(TableRecreateOperation::AddColumn(
            column.into_column_def(),
            None,
        ));
        self
    }

    pub fn add_column_with_value<T: IntoColumnDef, V: Into<Expr>>(
        &mut self,
        column: T,
        value: V,
    ) -> &mut Self {
        self.operations.push(TableRecreateOperation::AddColumn(
            column.into_column_def(),
            Some(value.into()),
        ));
        self
    }

    pub fn modify_column<T: IntoColumnDef>(&mut self, column: T) -> &mut Self {
        self.operations.push(TableRecreateOperation::ModifyColumn(
            column.into_column_def(),
            None,
        ));
        self
    }

    pub fn modify_column_with_value<T: IntoColumnDef, V: Into<Expr>>(
        &mut self,
        column: T,
        value: V,
    ) -> &mut Self {
        self.operations.push(TableRecreateOperation::ModifyColumn(
            column.into_column_def(),
            Some(value.into()),
        ));
        self
    }

    pub fn copy_from<I, C>(&mut self, columns: I, select: SelectStatement) -> &mut Self
    where
        I: IntoIterator<Item = C>,
        C: IntoIden,
    {
        self.operations.push(TableRecreateOperation::CopyFrom(
            columns.into_iter().map(IntoIden::into_iden).collect(),
            select,
        ));
        self
    }

    pub fn column_order<I, C>(&mut self, columns: I) -> &mut Self
    where
        I: IntoIterator<Item = C>,
        C: IntoIden,
    {
        self.operations.push(TableRecreateOperation::ColumnOrder(
            columns.into_iter().map(IntoIden::into_iden).collect(),
        ));
        self
    }

    pub fn drop_column<T: IntoIden>(&mut self, column: T) -> &mut Self {
        self.operations
            .push(TableRecreateOperation::DropColumn(column.into_iden()));
        self
    }

    pub fn rename_column<F: IntoIden, T: IntoIden>(&mut self, from: F, to: T) -> &mut Self {
        self.operations.push(TableRecreateOperation::RenameColumn(
            from.into_iden(),
            to.into_iden(),
        ));
        self
    }

    pub fn add_foreign_key(&mut self, foreign_key: ForeignKeyCreateStatement) -> &mut Self {
        self.operations
            .push(TableRecreateOperation::AddForeignKey(foreign_key));
        self
    }

    pub fn drop_foreign_key(&mut self, foreign_key: ForeignKeyRef) -> &mut Self {
        self.operations
            .push(TableRecreateOperation::DropForeignKey(foreign_key));
        self
    }

    pub fn modify_foreign_key(
        &mut self,
        foreign_key: ForeignKeyRef,
        replacement: ForeignKeyCreateStatement,
    ) -> &mut Self {
        self.operations
            .push(TableRecreateOperation::ModifyForeignKey(
                foreign_key,
                replacement,
            ));
        self
    }

    pub fn add_table_constraint(&mut self, constraint: IndexCreateStatement) -> &mut Self {
        self.operations
            .push(TableRecreateOperation::AddTableConstraint(constraint));
        self
    }

    pub fn drop_table_constraint(&mut self, constraint: TableConstraintRef) -> &mut Self {
        self.operations
            .push(TableRecreateOperation::DropTableConstraint(constraint));
        self
    }

    pub fn modify_table_constraint(
        &mut self,
        constraint: TableConstraintRef,
        replacement: IndexCreateStatement,
    ) -> &mut Self {
        self.operations
            .push(TableRecreateOperation::ModifyTableConstraint(
                constraint,
                replacement,
            ));
        self
    }

    pub fn discard_indexes(&mut self) -> &mut Self {
        self.discard_indexes = true;
        self
    }

    pub fn skip_foreign_key_check(&mut self) -> &mut Self {
        self.skip_foreign_key_check = true;
        self
    }

    pub fn skip_referencing_foreign_key_check(&mut self) -> &mut Self {
        self.skip_referencing_foreign_key_check = true;
        self
    }

    fn table_name(&self) -> Result<String, DbErr> {
        match &self.table {
            Some(TableRef::Table(TableName(None, table), None)) => Ok(table.to_string()),
            Some(_) => Err(DbErr::Migration(
                "Only unqualified table names without alias can be recreated".to_owned(),
            )),
            None => Err(DbErr::Migration(
                "Recreation operation has to have table specified".to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignKeyRef {
    columns: Vec<String>,
    ref_table: String,
    ref_columns: Vec<String>,
}

impl ForeignKeyRef {
    pub fn new(
        columns: impl IntoIterator<Item = impl Into<String>>,
        ref_table: impl Into<String>,
        ref_columns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            columns: columns.into_iter().map(Into::into).collect(),
            ref_table: ref_table.into(),
            ref_columns: ref_columns.into_iter().map(Into::into).collect(),
        }
    }

    fn matches(&self, foreign_key: &ForeignKeyInfo) -> bool {
        same_name(&self.ref_table, &foreign_key.ref_table)
            && same_names(&self.columns, &foreign_key.columns)
            && same_names(&self.ref_columns, &foreign_key.ref_columns)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableConstraintRef {
    columns: Vec<String>,
}

impl TableConstraintRef {
    pub fn new(columns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            columns: columns.into_iter().map(Into::into).collect(),
        }
    }

    fn matches(&self, constraint: &UniqueConstraintInfo) -> bool {
        same_names(&self.columns, &constraint.columns)
    }
}
