use sea_orm::{ConnectionTrait, DbBackend, DbErr, QueryResult, Statement, TryGetable, Value};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ColumnInfo {
    pub name: String,
    pub declared_type: String,
    pub not_null: bool,
    pub default_value: Option<String>,
    pub primary_key_position: i64,
    pub hidden: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ForeignKeyInfo {
    pub columns: Vec<String>,
    pub ref_table: String,
    pub ref_columns: Vec<String>,
    pub on_update: String,
    pub on_delete: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct UniqueConstraintInfo {
    pub columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IndexInfo {
    pub name: String,
    pub columns: Vec<String>,
    pub sql: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TableInfo {
    pub name: String,
    pub sql: String,
    pub auto_increment: bool,
    pub columns: Vec<ColumnInfo>,
    pub foreign_keys: Vec<ForeignKeyInfo>,
    pub unique_constraints: Vec<UniqueConstraintInfo>,
    pub indexes: Vec<IndexInfo>,
    pub triggers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReferencingForeignKey {
    pub table: String,
    pub columns: Vec<String>,
    pub on_delete: String,
}

const UNSUPPORTED_KEYWORDS: [(&str, &str); 8] = [
    ("CHECK", "CHECK constraints"),
    ("COLLATE", "COLLATE clauses"),
    ("CONFLICT", "ON CONFLICT clauses"),
    ("DEFERRABLE", "deferrable foreign keys"),
    ("DESC", "descending PRIMARY KEY or UNIQUE columns"),
    ("GENERATED", "generated columns"),
    ("STRICT", "STRICT tables"),
    ("WITHOUT", "WITHOUT ROWID tables"),
];

impl TableInfo {
    pub(crate) fn unsupported_features(&self) -> Vec<&'static str> {
        let keywords = sql_keywords(&self.sql);
        let mut features: Vec<&'static str> = UNSUPPORTED_KEYWORDS
            .iter()
            .filter(|(keyword, _)| keywords.iter().any(|k| k == keyword))
            .map(|(_, feature)| *feature)
            .collect();
        if keywords.get(1).is_some_and(|k| k == "VIRTUAL") {
            features.push("virtual tables");
        } else if self.columns.iter().any(|c| c.hidden != 0)
            && !features.contains(&"generated columns")
        {
            features.push("generated columns");
        }
        features
    }

    pub(crate) fn has_column(&self, name: &str) -> bool {
        self.columns.iter().any(|c| same_name(&c.name, name))
    }
}

pub(crate) fn same_name(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

pub(crate) fn same_names(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().all(|x| b.iter().any(|y| same_name(x, y)))
}

pub(crate) async fn table_exists<C: ConnectionTrait>(conn: &C, table: &str) -> Result<bool, DbErr> {
    Ok(table_definition(conn, table).await?.is_some())
}

pub(crate) async fn load_table<C: ConnectionTrait>(
    conn: &C,
    table: &str,
) -> Result<TableInfo, DbErr> {
    let (name, sql) = table_definition(conn, table)
        .await?
        .ok_or_else(|| DbErr::Migration(format!("Table `{table}` doesn't exist")))?;
    let auto_increment = sql_keywords(&sql).iter().any(|k| k == "AUTOINCREMENT");

    let columns = query(
        conn,
        r#"SELECT name, type, "notnull", dflt_value, pk, hidden FROM pragma_table_xinfo(?) ORDER BY cid"#,
        [table.into()],
    )
    .await?
    .iter()
    .map(|row| {
        Ok(ColumnInfo {
            name: get(row, "name")?,
            declared_type: get(row, "type")?,
            not_null: get::<i64>(row, "notnull")? != 0,
            default_value: get(row, "dflt_value")?,
            primary_key_position: get(row, "pk")?,
            hidden: get(row, "hidden")?,
        })
    })
    .collect::<Result<Vec<_>, DbErr>>()?;

    let (unique_constraints, indexes) = load_indexes(conn, table).await?;

    let triggers = query(
        conn,
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ? AND sql IS NOT NULL ORDER BY rowid",
        [table.into()],
    )
    .await?
    .iter()
    .map(|row| get(row, "sql"))
    .collect::<Result<Vec<String>, DbErr>>()?;

    Ok(TableInfo {
        name,
        sql,
        auto_increment,
        columns,
        foreign_keys: load_foreign_keys(conn, table).await?,
        unique_constraints,
        indexes,
        triggers,
    })
}

pub(crate) async fn referencing_foreign_keys<C: ConnectionTrait>(
    conn: &C,
    table: &str,
) -> Result<Vec<ReferencingForeignKey>, DbErr> {
    let rows = query(
        conn,
        r#"SELECT m.name AS child_table, f.id AS id, f."from" AS column_name, f.on_delete AS on_delete
           FROM sqlite_master AS m JOIN pragma_foreign_key_list(m.name) AS f
           WHERE m.type = 'table' AND f."table" = ? COLLATE NOCASE AND m.name <> ? COLLATE NOCASE
           ORDER BY m.name, f.id, f.seq"#,
        [table.into(), table.into()],
    )
    .await?;

    let mut foreign_keys: Vec<(String, i64, ReferencingForeignKey)> = Vec::new();
    for row in &rows {
        let child_table: String = get(row, "child_table")?;
        let id: i64 = get(row, "id")?;
        let column: String = get(row, "column_name")?;
        match foreign_keys.last_mut() {
            Some((last_table, last_id, fk)) if *last_table == child_table && *last_id == id => {
                fk.columns.push(column);
            }
            _ => foreign_keys.push((
                child_table.clone(),
                id,
                ReferencingForeignKey {
                    table: child_table,
                    columns: vec![column],
                    on_delete: get(row, "on_delete")?,
                },
            )),
        }
    }
    Ok(foreign_keys.into_iter().map(|(_, _, fk)| fk).collect())
}

pub(crate) async fn pragma_flag<C: ConnectionTrait>(conn: &C, pragma: &str) -> Result<bool, DbErr> {
    let row = conn
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            format!("PRAGMA {pragma}"),
        ))
        .await?
        .ok_or_else(|| DbErr::Migration(format!("PRAGMA {pragma} returned no value")))?;
    Ok(row.try_get_by_index::<i64>(0)? != 0)
}

pub(crate) async fn foreign_key_violations<C: ConnectionTrait>(
    conn: &C,
    table: &str,
) -> Result<i64, DbErr> {
    let rows = query(
        conn,
        "SELECT count(*) AS violations FROM pragma_foreign_key_check(?)",
        [table.into()],
    )
    .await?;
    rows.first()
        .map(|row| get(row, "violations"))
        .transpose()
        .map(Option::unwrap_or_default)
}

pub(crate) async fn autoincrement_sequence<C: ConnectionTrait>(
    conn: &C,
    table: &str,
) -> Result<Option<i64>, DbErr> {
    let rows = query(
        conn,
        "SELECT seq FROM sqlite_sequence WHERE name = ?",
        [table.into()],
    )
    .await?;
    rows.first().map(|row| get(row, "seq")).transpose()
}

pub(crate) async fn restore_autoincrement_sequence<C: ConnectionTrait>(
    conn: &C,
    table: &str,
    sequence: i64,
) -> Result<(), DbErr> {
    let updated = conn
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE sqlite_sequence SET seq = MAX(seq, ?) WHERE name = ?",
            [sequence.into(), table.into()],
        ))
        .await?;
    if updated.rows_affected() == 0 {
        conn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)",
            [table.into(), sequence.into()],
        ))
        .await?;
    }
    Ok(())
}

async fn table_definition<C: ConnectionTrait>(
    conn: &C,
    table: &str,
) -> Result<Option<(String, String)>, DbErr> {
    let rows = query(
        conn,
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name = ? COLLATE NOCASE",
        [table.into()],
    )
    .await?;
    rows.first()
        .map(|row| Ok((get(row, "name")?, get(row, "sql")?)))
        .transpose()
}

async fn load_foreign_keys<C: ConnectionTrait>(
    conn: &C,
    table: &str,
) -> Result<Vec<ForeignKeyInfo>, DbErr> {
    let rows = query(
        conn,
        r#"SELECT id, "table" AS ref_table, "from" AS column_name, "to" AS ref_column, on_update, on_delete
           FROM pragma_foreign_key_list(?) ORDER BY id, seq"#,
        [table.into()],
    )
    .await?;

    let mut foreign_keys: Vec<(i64, ForeignKeyInfo, bool)> = Vec::new();
    for row in &rows {
        let id: i64 = get(row, "id")?;
        let column: String = get(row, "column_name")?;
        let ref_column: Option<String> = get(row, "ref_column")?;
        match foreign_keys.last_mut() {
            Some((last_id, fk, implicit)) if *last_id == id => {
                fk.columns.push(column);
                *implicit |= ref_column.is_none();
                fk.ref_columns.extend(ref_column);
            }
            _ => foreign_keys.push((
                id,
                ForeignKeyInfo {
                    columns: vec![column],
                    ref_table: get(row, "ref_table")?,
                    ref_columns: ref_column.iter().cloned().collect(),
                    on_update: get(row, "on_update")?,
                    on_delete: get(row, "on_delete")?,
                },
                ref_column.is_none(),
            )),
        }
    }

    let mut result = Vec::with_capacity(foreign_keys.len());
    for (_, mut fk, implicit) in foreign_keys {
        if implicit {
            fk.ref_columns = primary_key_columns(conn, &fk.ref_table).await?;
        }
        result.push(fk);
    }
    Ok(result)
}

async fn primary_key_columns<C: ConnectionTrait>(
    conn: &C,
    table: &str,
) -> Result<Vec<String>, DbErr> {
    query(
        conn,
        "SELECT name FROM pragma_table_info(?) WHERE pk > 0 ORDER BY pk",
        [table.into()],
    )
    .await?
    .iter()
    .map(|row| get(row, "name"))
    .collect()
}

async fn load_indexes<C: ConnectionTrait>(
    conn: &C,
    table: &str,
) -> Result<(Vec<UniqueConstraintInfo>, Vec<IndexInfo>), DbErr> {
    let index_list = query(
        conn,
        r#"SELECT il.name AS name, il.origin AS origin, m.sql AS sql
           FROM pragma_index_list(?) AS il LEFT JOIN sqlite_master AS m ON m.type = 'index' AND m.name = il.name
           ORDER BY il.seq DESC"#,
        [table.into()],
    )
    .await?;

    let mut unique_constraints = Vec::new();
    let mut indexes = Vec::new();
    for row in &index_list {
        let name: String = get(row, "name")?;
        let origin: String = get(row, "origin")?;
        let columns = query(
            conn,
            "SELECT name FROM pragma_index_xinfo(?) WHERE key = 1 AND name IS NOT NULL ORDER BY seqno",
            [name.as_str().into()],
        )
        .await?
        .iter()
        .map(|row| get(row, "name"))
        .collect::<Result<Vec<String>, DbErr>>()?;

        match origin.as_str() {
            "u" => unique_constraints.push(UniqueConstraintInfo { columns }),
            "c" => {
                let sql: Option<String> = get(row, "sql")?;
                let sql = sql.ok_or_else(|| {
                    DbErr::Migration(format!("Index `{name}` has no SQL definition"))
                })?;
                indexes.push(IndexInfo { name, columns, sql });
            }
            _ => {}
        }
    }
    Ok((unique_constraints, indexes))
}

async fn query<C: ConnectionTrait, const N: usize>(
    conn: &C,
    sql: &str,
    values: [Value; N],
) -> Result<Vec<QueryResult>, DbErr> {
    conn.query_all_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        sql,
        values,
    ))
    .await
}

fn get<T: TryGetable>(row: &QueryResult, column: &str) -> Result<T, DbErr> {
    row.try_get("", column)
}

fn sql_keywords(sql: &str) -> Vec<String> {
    let mut keywords = Vec::new();
    let mut current = String::new();
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        let quote_end = match c {
            '\'' | '"' | '`' => Some(c),
            '[' => Some(']'),
            _ => None,
        };
        if let Some(end) = quote_end {
            flush_keyword(&mut current, &mut keywords);
            for next in chars.by_ref() {
                if next == end {
                    break;
                }
            }
        } else if c == '-' && chars.peek() == Some(&'-') {
            flush_keyword(&mut current, &mut keywords);
            for next in chars.by_ref() {
                if next == '\n' {
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            flush_keyword(&mut current, &mut keywords);
            chars.next();
            let mut previous = ' ';
            for next in chars.by_ref() {
                if previous == '*' && next == '/' {
                    break;
                }
                previous = next;
            }
        } else if c.is_alphanumeric() || c == '_' {
            current.push(c.to_ascii_uppercase());
        } else {
            flush_keyword(&mut current, &mut keywords);
        }
    }
    flush_keyword(&mut current, &mut keywords);
    keywords
}

fn flush_keyword(current: &mut String, keywords: &mut Vec<String>) {
    if !current.is_empty() {
        keywords.push(std::mem::take(current));
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_sql_keywords_skip_quoted_text_and_comments() {
        let keywords = sql_keywords(
            "CREATE TABLE \"check\" (`collate` text DEFAULT 'it''s CHECK', [desc] int, -- STRICT\n x /* WITHOUT */ int)",
        );
        assert_eq!(
            keywords,
            vec!["CREATE", "TABLE", "TEXT", "DEFAULT", "INT", "X", "INT"]
        );
    }

    #[test]
    fn test_virtual_table_is_unsupported() {
        let table = TableInfo {
            name: "fts".to_owned(),
            sql: "CREATE VIRTUAL TABLE fts USING fts5(content)".to_owned(),
            auto_increment: false,
            columns: vec![],
            foreign_keys: vec![],
            unique_constraints: vec![],
            indexes: vec![],
            triggers: vec![],
        };
        assert_eq!(table.unsupported_features(), vec!["virtual tables"]);
    }

    #[test]
    fn test_unsupported_features_detected() {
        let table = TableInfo {
            name: "t".to_owned(),
            sql: "CREATE TABLE t (a int CHECK (a > 0), b text COLLATE NOCASE) STRICT".to_owned(),
            auto_increment: false,
            columns: vec![ColumnInfo {
                name: "c".to_owned(),
                declared_type: "int".to_owned(),
                not_null: false,
                default_value: None,
                primary_key_position: 0,
                hidden: 2,
            }],
            foreign_keys: vec![],
            unique_constraints: vec![],
            indexes: vec![],
            triggers: vec![],
        };
        assert_eq!(
            table.unsupported_features(),
            vec![
                "CHECK constraints",
                "COLLATE clauses",
                "STRICT tables",
                "generated columns"
            ]
        );
    }
}
