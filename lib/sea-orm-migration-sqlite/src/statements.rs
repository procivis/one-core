use std::collections::HashMap;

use sea_orm::DbErr;
use sea_orm::sea_query::{
    Alias, ColumnDef, DynIden, Expr, ForeignKey, ForeignKeyAction, ForeignKeyCreateStatement,
    Index, IndexCreateStatement, InsertStatement, Query, SelectStatement, Table,
    TableCreateStatement, TableName, TableRef,
};

use crate::introspection::{ColumnInfo, ForeignKeyInfo, TableInfo, same_name};
use crate::model::TableRecreateOperation;

#[derive(Debug)]
pub(crate) struct RecreatePlan {
    pub create_table: TableCreateStatement,
    pub copy_data: InsertStatement,
}

pub(crate) fn plan_recreate(
    table: &TableInfo,
    temp_table: &str,
    operations: &[TableRecreateOperation],
    discard_indexes: bool,
    self_reference_table: &str,
) -> Result<RecreatePlan, DbErr> {
    let changes = Changes::collect(table, operations)?;

    let mut create_table = Table::create();
    create_table.table(Alias::new(temp_table));

    let copied_columns = recreate_columns(table, &changes, &mut create_table)?;
    recreate_primary_key(table, &changes, &mut create_table)?;
    recreate_foreign_keys(table, &changes, self_reference_table, &mut create_table)?;
    recreate_unique_constraints(table, &changes, &mut create_table)?;

    for index in table.indexes.iter().filter(|_| !discard_indexes) {
        if let Some(column) = index.columns.iter().find(|c| changes.is_dropped(c)) {
            return Err(migration_error(format!(
                "Cannot drop column `{column}`: it's used by index `{}`, drop the index first",
                index.name
            )));
        }
    }

    let mut copy_data = Query::insert();
    copy_data.into_table(Alias::new(temp_table));
    match changes.copy_from {
        Some((columns, select)) => {
            copy_data.columns(columns.iter().cloned());
            copy_data.select_from(select.clone())
        }
        None => {
            let (columns, values): (Vec<Alias>, Vec<Expr>) = copied_columns
                .into_iter()
                .map(|(column, value)| (Alias::new(column), value))
                .unzip();
            copy_data.columns(columns);
            copy_data.select_from(
                Query::select()
                    .exprs(values)
                    .from(Alias::new(&table.name))
                    .to_owned(),
            )
        }
    }
    .map_err(|e| migration_error(format!("Failed to build copy data statement: {e}")))?;

    Ok(RecreatePlan {
        create_table,
        copy_data,
    })
}

struct Changes<'a> {
    added_columns: Vec<&'a ColumnDef>,
    added_values: Vec<Option<&'a Expr>>,
    modified_columns: Vec<&'a ColumnDef>,
    modified_values: Vec<Option<&'a Expr>>,
    column_order: Option<Vec<String>>,
    copy_from: Option<(&'a Vec<DynIden>, &'a SelectStatement)>,
    dropped_columns: Vec<String>,
    foreign_key_replacements: HashMap<usize, Option<&'a ForeignKeyCreateStatement>>,
    added_foreign_keys: Vec<&'a ForeignKeyCreateStatement>,
    constraint_replacements: HashMap<usize, Option<&'a IndexCreateStatement>>,
    added_constraints: Vec<&'a IndexCreateStatement>,
}

impl<'a> Changes<'a> {
    fn collect(table: &TableInfo, operations: &'a [TableRecreateOperation]) -> Result<Self, DbErr> {
        let mut changes = Self {
            added_columns: vec![],
            added_values: vec![],
            modified_columns: vec![],
            modified_values: vec![],
            column_order: None,
            copy_from: None,
            dropped_columns: vec![],
            foreign_key_replacements: HashMap::new(),
            added_foreign_keys: vec![],
            constraint_replacements: HashMap::new(),
            added_constraints: vec![],
        };

        for operation in operations {
            match operation {
                TableRecreateOperation::AddColumn(column, value) => {
                    changes.added_columns.push(column);
                    changes.added_values.push(value.as_ref());
                }
                TableRecreateOperation::ModifyColumn(column, value) => {
                    changes.modified_columns.push(column);
                    changes.modified_values.push(value.as_ref());
                }
                TableRecreateOperation::ColumnOrder(columns) => {
                    if changes.column_order.is_some() {
                        return Err(migration_error(
                            "Column order is specified more than once".to_owned(),
                        ));
                    }
                    changes.column_order = Some(columns.iter().map(|c| c.to_string()).collect());
                }
                TableRecreateOperation::DropColumn(column) => {
                    changes.dropped_columns.push(column.to_string())
                }
                TableRecreateOperation::RenameColumn(_, _) => {}
                TableRecreateOperation::CopyFrom(columns, select) => {
                    if changes.copy_from.is_some() {
                        return Err(migration_error(
                            "Copy source is specified more than once".to_owned(),
                        ));
                    }
                    changes.copy_from = Some((columns, select));
                }
                TableRecreateOperation::AddForeignKey(fk) => changes.added_foreign_keys.push(fk),
                TableRecreateOperation::DropForeignKey(fk_ref) => {
                    let describe = || format!("Foreign key {fk_ref:?}");
                    let index =
                        find_single(&table.foreign_keys, |fk| fk_ref.matches(fk), describe)?;
                    insert_replacement(
                        &mut changes.foreign_key_replacements,
                        index,
                        None,
                        describe,
                    )?;
                }
                TableRecreateOperation::ModifyForeignKey(fk_ref, fk) => {
                    let describe = || format!("Foreign key {fk_ref:?}");
                    let index = find_single(&table.foreign_keys, |f| fk_ref.matches(f), describe)?;
                    insert_replacement(
                        &mut changes.foreign_key_replacements,
                        index,
                        Some(fk),
                        describe,
                    )?;
                }
                TableRecreateOperation::AddTableConstraint(constraint) => {
                    if !constraint.is_primary_key() && !constraint.is_unique_key() {
                        return Err(migration_error(
                            "Only PRIMARY KEY and UNIQUE table constraints are supported, use SchemaManager::create_index for regular indexes".to_owned(),
                        ));
                    }
                    changes.added_constraints.push(constraint)
                }
                TableRecreateOperation::DropTableConstraint(constraint_ref) => {
                    let describe = || format!("Table constraint {constraint_ref:?}");
                    let index = find_single(
                        &table.unique_constraints,
                        |c| constraint_ref.matches(c),
                        describe,
                    )?;
                    insert_replacement(
                        &mut changes.constraint_replacements,
                        index,
                        None,
                        describe,
                    )?;
                }
                TableRecreateOperation::ModifyTableConstraint(constraint_ref, constraint) => {
                    let describe = || format!("Table constraint {constraint_ref:?}");
                    let index = find_single(
                        &table.unique_constraints,
                        |c| constraint_ref.matches(c),
                        describe,
                    )?;
                    insert_replacement(
                        &mut changes.constraint_replacements,
                        index,
                        Some(constraint),
                        describe,
                    )?;
                }
            }
        }

        changes.validate_columns(table)?;
        Ok(changes)
    }

    fn validate_columns(&self, table: &TableInfo) -> Result<(), DbErr> {
        for (position, column) in self.dropped_columns.iter().enumerate() {
            if !table.has_column(column) {
                return Err(migration_error(format!(
                    "Cannot drop column `{column}`: it doesn't exist"
                )));
            }
            if self
                .dropped_columns
                .iter()
                .skip(position + 1)
                .any(|c| same_name(c, column))
            {
                return Err(migration_error(format!(
                    "Column `{column}` is dropped more than once"
                )));
            }
        }

        for (position, column) in self.modified_columns.iter().enumerate() {
            let name = column.get_column_name();
            if !table.has_column(&name) {
                return Err(migration_error(format!(
                    "Cannot modify column `{name}`: it doesn't exist"
                )));
            }
            if self.is_dropped(&name) {
                return Err(migration_error(format!(
                    "Cannot modify column `{name}`: it's dropped"
                )));
            }
            if self
                .modified_columns
                .iter()
                .skip(position + 1)
                .any(|c| same_name(&c.get_column_name(), &name))
            {
                return Err(migration_error(format!(
                    "Column `{name}` is modified more than once"
                )));
            }
        }

        for (position, column) in self.added_columns.iter().enumerate() {
            let name = column.get_column_name();
            if table.has_column(&name) && !self.is_dropped(&name) {
                return Err(migration_error(format!(
                    "Cannot add column `{name}`: it already exists"
                )));
            }
            if self
                .added_columns
                .iter()
                .skip(position + 1)
                .any(|c| same_name(&c.get_column_name(), &name))
            {
                return Err(migration_error(format!(
                    "Column `{name}` is added more than once"
                )));
            }
        }
        Ok(())
    }

    fn is_dropped(&self, column: &str) -> bool {
        self.dropped_columns.iter().any(|c| same_name(c, column))
    }

    fn modified_column(&self, column: &str) -> Option<(&'a ColumnDef, Option<&'a Expr>)> {
        self.modified_columns
            .iter()
            .zip(&self.modified_values)
            .find(|(c, _)| same_name(&c.get_column_name(), column))
            .map(|(c, v)| (*c, *v))
    }

    fn primary_key_constraint(&self) -> Result<Option<&'a IndexCreateStatement>, DbErr> {
        let mut primary_keys = self.added_constraints.iter().filter(|c| c.is_primary_key());
        let primary_key = primary_keys.next().copied();
        if primary_keys.next().is_some() {
            return Err(migration_error(
                "Only one PRIMARY KEY table constraint can be added".to_owned(),
            ));
        }
        Ok(primary_key)
    }
}

fn recreate_columns(
    table: &TableInfo,
    changes: &Changes,
    create_table: &mut TableCreateStatement,
) -> Result<Vec<(String, Expr)>, DbErr> {
    let inline_auto_increment = table.auto_increment
        && existing_primary_key(table).len() == 1
        && changes.primary_key_constraint()?.is_none();

    let mut columns: Vec<ColumnDef> = Vec::new();
    let mut copied_columns = Vec::new();
    for column in &table.columns {
        if changes.is_dropped(&column.name) {
            continue;
        }
        match changes.modified_column(&column.name) {
            Some((modified, value)) => {
                copied_columns.push((
                    column.name.clone(),
                    value
                        .cloned()
                        .unwrap_or_else(|| Expr::col(Alias::new(&column.name))),
                ));
                columns.push(modified.clone());
            }
            None => {
                copied_columns.push((column.name.clone(), Expr::col(Alias::new(&column.name))));
                columns.push(existing_column_def(
                    column,
                    inline_auto_increment && column.primary_key_position > 0,
                ));
            }
        }
    }
    for (column, value) in changes.added_columns.iter().zip(&changes.added_values) {
        if let Some(value) = value {
            copied_columns.push((column.get_column_name(), (*value).clone()));
        }
        columns.push((*column).clone());
    }

    if let Some(order) = &changes.column_order {
        columns = ordered_columns(table, columns, order)?;
    }
    for column in columns {
        create_table.col(column);
    }
    Ok(copied_columns)
}

fn ordered_columns(
    table: &TableInfo,
    mut columns: Vec<ColumnDef>,
    order: &[String],
) -> Result<Vec<ColumnDef>, DbErr> {
    if order.len() != columns.len() {
        return Err(migration_error(format!(
            "Column order of table `{}` has to list all {} columns",
            table.name,
            columns.len()
        )));
    }
    let mut ordered = Vec::with_capacity(columns.len());
    for name in order {
        let Some(position) = columns
            .iter()
            .position(|c| same_name(&c.get_column_name(), name))
        else {
            return Err(migration_error(format!(
                "Column order of table `{}` contains unknown or repeated column `{name}`",
                table.name
            )));
        };
        ordered.push(columns.swap_remove(position));
    }
    Ok(ordered)
}

fn recreate_primary_key(
    table: &TableInfo,
    changes: &Changes,
    create_table: &mut TableCreateStatement,
) -> Result<(), DbErr> {
    let existing_primary_key = existing_primary_key(table);
    let primary_key_constraint = changes.primary_key_constraint()?;

    if primary_key_constraint.is_none()
        && let Some(column) = existing_primary_key
            .iter()
            .find(|c| changes.is_dropped(&c.name))
    {
        return Err(migration_error(format!(
            "Cannot drop column `{}`: it's part of the primary key",
            column.name
        )));
    }

    let inline_primary_keys: Vec<String> = create_table
        .get_columns()
        .iter()
        .filter(|c| c.get_column_spec().primary_key)
        .map(|c| c.get_column_name())
        .collect();

    match (inline_primary_keys.as_slice(), primary_key_constraint) {
        ([], None) => {
            if !existing_primary_key.is_empty() {
                let mut primary_key = Index::create();
                for column in &existing_primary_key {
                    primary_key.col(Alias::new(&column.name));
                }
                create_table.primary_key(&mut primary_key);
            }
            Ok(())
        }
        ([], Some(_)) => Ok(()),
        ([inline], None)
            if existing_primary_key.is_empty()
                || (existing_primary_key.len() == 1
                    && existing_primary_key
                        .iter()
                        .all(|c| same_name(&c.name, inline))) =>
        {
            Ok(())
        }
        _ => Err(migration_error(format!(
            "Conflicting primary key definitions for table `{}`",
            table.name
        ))),
    }
}

fn recreate_foreign_keys(
    table: &TableInfo,
    changes: &Changes,
    self_reference_table: &str,
    create_table: &mut TableCreateStatement,
) -> Result<(), DbErr> {
    for (index, foreign_key) in table.foreign_keys.iter().enumerate() {
        match changes.foreign_key_replacements.get(&index) {
            Some(Some(replacement)) => {
                create_table.foreign_key(&mut retargeted(
                    replacement,
                    &table.name,
                    self_reference_table,
                ));
            }
            Some(None) => {}
            None => {
                if let Some(column) = foreign_key.columns.iter().find(|c| changes.is_dropped(c)) {
                    return Err(migration_error(format!(
                        "Cannot drop column `{column}`: it's referenced by a foreign key to `{}`",
                        foreign_key.ref_table
                    )));
                }
                create_table.foreign_key(&mut existing_foreign_key(
                    &table.name,
                    foreign_key,
                    self_reference_table,
                )?);
            }
        }
    }
    for foreign_key in &changes.added_foreign_keys {
        create_table.foreign_key(&mut retargeted(
            foreign_key,
            &table.name,
            self_reference_table,
        ));
    }
    Ok(())
}

fn retargeted(
    foreign_key: &ForeignKeyCreateStatement,
    table: &str,
    self_reference_table: &str,
) -> ForeignKeyCreateStatement {
    let mut foreign_key = foreign_key.clone();
    let references_table = matches!(
        foreign_key.get_foreign_key().get_ref_table(),
        Some(TableRef::Table(TableName(_, ref_table), _)) if same_name(&ref_table.to_string(), table)
    );
    if references_table {
        foreign_key.to_tbl(Alias::new(self_reference_table));
    }
    foreign_key
}

fn recreate_unique_constraints(
    table: &TableInfo,
    changes: &Changes,
    create_table: &mut TableCreateStatement,
) -> Result<(), DbErr> {
    for (index, constraint) in table.unique_constraints.iter().enumerate() {
        match changes.constraint_replacements.get(&index) {
            Some(Some(replacement)) => {
                create_table.index(&mut (*replacement).clone());
            }
            Some(None) => {}
            None => {
                if let Some(column) = constraint.columns.iter().find(|c| changes.is_dropped(c)) {
                    return Err(migration_error(format!(
                        "Cannot drop column `{column}`: it's used by a UNIQUE constraint"
                    )));
                }
                let mut unique = Index::create();
                unique.unique();
                for column in &constraint.columns {
                    unique.col(Alias::new(column));
                }
                create_table.index(&mut unique);
            }
        }
    }
    for constraint in &changes.added_constraints {
        create_table.index(&mut (*constraint).clone());
    }
    Ok(())
}

fn existing_primary_key(table: &TableInfo) -> Vec<&ColumnInfo> {
    let mut primary_key: Vec<&ColumnInfo> = table
        .columns
        .iter()
        .filter(|c| c.primary_key_position > 0)
        .collect();
    primary_key.sort_by_key(|c| c.primary_key_position);
    primary_key
}

fn existing_column_def(column: &ColumnInfo, auto_increment_primary_key: bool) -> ColumnDef {
    let mut column_def = ColumnDef::new(Alias::new(&column.name));
    if !column.declared_type.is_empty() {
        column_def.custom(Alias::new(&column.declared_type));
    }
    if column.not_null {
        column_def.not_null();
    }
    if let Some(default_value) = &column.default_value {
        column_def.default(Expr::cust(default_value.clone()));
    }
    if auto_increment_primary_key {
        column_def.primary_key().auto_increment();
    }
    column_def
}

fn existing_foreign_key(
    table: &str,
    foreign_key: &ForeignKeyInfo,
    self_reference_table: &str,
) -> Result<ForeignKeyCreateStatement, DbErr> {
    let ref_table = if same_name(&foreign_key.ref_table, table) {
        self_reference_table
    } else {
        &foreign_key.ref_table
    };
    let mut statement = ForeignKey::create();
    statement
        .from_tbl(Alias::new(table))
        .to_tbl(Alias::new(ref_table))
        .on_delete(foreign_key_action(&foreign_key.on_delete)?)
        .on_update(foreign_key_action(&foreign_key.on_update)?);
    for column in &foreign_key.columns {
        statement.from_col(Alias::new(column));
    }
    for column in &foreign_key.ref_columns {
        statement.to_col(Alias::new(column));
    }
    Ok(statement)
}

fn foreign_key_action(action: &str) -> Result<ForeignKeyAction, DbErr> {
    match action.to_ascii_uppercase().as_str() {
        "NO ACTION" => Ok(ForeignKeyAction::NoAction),
        "RESTRICT" => Ok(ForeignKeyAction::Restrict),
        "CASCADE" => Ok(ForeignKeyAction::Cascade),
        "SET NULL" => Ok(ForeignKeyAction::SetNull),
        "SET DEFAULT" => Ok(ForeignKeyAction::SetDefault),
        other => Err(migration_error(format!(
            "Unsupported foreign key action `{other}`"
        ))),
    }
}

fn find_single<T>(
    items: &[T],
    predicate: impl Fn(&T) -> bool,
    describe: impl Fn() -> String,
) -> Result<usize, DbErr> {
    let mut matches = items
        .iter()
        .enumerate()
        .filter(|(_, item)| predicate(item))
        .map(|(index, _)| index);
    match (matches.next(), matches.next()) {
        (Some(index), None) => Ok(index),
        (None, _) => Err(migration_error(format!("{} not found", describe()))),
        (Some(_), Some(_)) => Err(migration_error(format!("{} is ambiguous", describe()))),
    }
}

fn insert_replacement<T>(
    replacements: &mut HashMap<usize, Option<T>>,
    index: usize,
    replacement: Option<T>,
    describe: impl Fn() -> String,
) -> Result<(), DbErr> {
    if replacements.insert(index, replacement).is_some() {
        return Err(migration_error(format!(
            "{} is changed more than once",
            describe()
        )));
    }
    Ok(())
}

fn migration_error(message: String) -> DbErr {
    DbErr::Migration(message)
}
