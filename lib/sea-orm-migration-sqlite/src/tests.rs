use sea_orm::sea_query::{
    Alias, ColumnDef, Expr, ExprTrait, ForeignKey, ForeignKeyAction, Index, IntoColumnRef, Query,
    Table,
};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, DbBackend,
    DeriveIden, Iden, MockDatabase, Statement, TransactionTrait,
};
use sea_orm_migration::SchemaManager;
use sea_orm_migration::schema::{
    custom, custom_null, string, string_len, string_len_null, string_null,
};
use similar_asserts::assert_eq;

use crate::introspection::{ColumnInfo, TableInfo, load_table};
use crate::{ForeignKeyRef, SchemaManagerExt, TableConstraintRef, TableExt};

#[tokio::test]
async fn test_recreate_with_add_and_modify_column_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .add_column(ColumnDef::new(BookNew::AuthorName).string().to_owned())
            .modify_column(ColumnDef::new(Book::Isbn).string().not_null().to_owned())
            .to_owned(),
    )
    .await
    .unwrap();

    let book = table(&db, "book").await;
    assert!(book.has_column("author_name"));
    let isbn = column(&book, "isbn");
    assert!(isbn.not_null);
    assert_eq!(isbn.declared_type, "varchar");
    assert_eq!(count(&db, "SELECT count(*) FROM library").await, 1);
    assert_eq!(
        count(&db, "SELECT count(*) FROM book WHERE isbn = '654321'").await,
        1
    );
}

#[tokio::test]
async fn test_recreate_with_rename_column_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .rename_column(Book::LibraryNumber, BookNew::NewAwesomeLibraryNumber)
            .to_owned(),
    )
    .await
    .unwrap();

    let result = db
        .query_all_raw(
            DatabaseBackend::Sqlite.build(Query::select().from(Book::Table).columns([
                Book::Id.into_column_ref(),
                Book::Name.into_column_ref(),
                BookNew::NewAwesomeLibraryNumber.into_column_ref(),
            ])),
        )
        .await
        .unwrap();
    assert_eq!(1, result.len());

    let book = table(&db, "book").await;
    assert!(book.has_column("new_awesome_library_number"));
    assert!(!book.has_column("library_number"));
    assert_eq!(
        book.unique_constraints.first().unwrap().columns,
        vec!["id", "name", "new_awesome_library_number"]
    );
    assert_eq!(
        book.foreign_keys.first().unwrap().columns,
        vec!["new_awesome_library_number"]
    );
}

#[tokio::test]
async fn test_recreate_with_drop_column_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .drop_column(Book::Isbn)
            .to_owned(),
    )
    .await
    .unwrap();

    let book = table(&db, "book").await;
    assert_eq!(book.columns.len(), 6);
    assert!(!book.has_column("isbn"));
    assert_eq!(count(&db, "SELECT count(*) FROM book").await, 1);
}

#[tokio::test]
async fn test_recreate_with_add_foreign_key_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .add_column(string_len_null(BookNew::BorrowerId, 3))
            .add_foreign_key(
                ForeignKey::create()
                    .name("fk-book-borrower")
                    .from(Book::Table, BookNew::BorrowerId)
                    .to(Borrower::Table, Borrower::Id)
                    .to_owned(),
            )
            .to_owned(),
    )
    .await
    .unwrap();

    let book = table(&db, "book").await;
    assert_eq!(book.columns.len(), 8);
    assert!(book.has_column("borrower_id"));

    let update_result = sm
        .exec_stmt(
            Query::update()
                .table(Book::Table)
                .value(BookNew::BorrowerId, "123")
                .to_owned(),
        )
        .await;
    assert_fk_error(update_result);

    sm.exec_stmt(
        Query::update()
            .table(Book::Table)
            .value(BookNew::BorrowerId, "321")
            .to_owned(),
    )
    .await
    .unwrap();
    assert_eq!(
        count(&db, "SELECT count(*) FROM book WHERE borrower_id = '321'").await,
        1
    );
}

#[tokio::test]
async fn test_recreate_with_drop_foreign_key_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .drop_foreign_key(ForeignKeyRef::new(
                [Book::LibraryNumber.to_string()],
                "library",
                [Library::Number.to_string()],
            ))
            .to_owned(),
    )
    .await
    .unwrap();

    assert_eq!(table(&db, "book").await.foreign_keys.len(), 0);
    insert_book(&sm, "222", "999", "London").await.unwrap();
}

#[tokio::test]
async fn test_recreate_with_add_constraint_and_modify_foreign_key_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    let change_library_primary_key = Table::recreate()
        .table(Library::Table)
        .modify_column(string_len(Library::Number, 3))
        .add_table_constraint(
            Index::create()
                .col(Library::Number)
                .col(Library::City)
                .primary()
                .to_owned(),
        )
        .to_owned();
    let error = sm
        .recreate_table(change_library_primary_key.clone())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("would break foreign keys of table `book`"),
        "{error}"
    );
    assert_eq!(
        column(&table(&db, "library").await, "city").primary_key_position,
        0
    );

    sm.recreate_table(
        change_library_primary_key
            .clone()
            .skip_referencing_foreign_key_check()
            .to_owned(),
    )
    .await
    .unwrap();
    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .modify_foreign_key(
                ForeignKeyRef::new(["library_number"], "library", ["number"]),
                ForeignKey::create()
                    .from(Book::Table, (Book::LibraryNumber, Book::LibraryCity))
                    .to(Library::Table, (Library::Number, Library::City))
                    .to_owned(),
            )
            .to_owned(),
    )
    .await
    .unwrap();

    let library = table(&db, "library").await;
    assert_eq!(column(&library, "number").primary_key_position, 1);
    assert_eq!(column(&library, "city").primary_key_position, 2);
    assert_eq!(library.unique_constraints.len(), 0);
    assert_eq!(library.indexes.len(), 1);

    let book = table(&db, "book").await;
    assert_eq!(book.foreign_keys.len(), 1);
    let book_fk = book.foreign_keys.first().unwrap();
    assert_eq!(book_fk.ref_table, "library");
    assert_eq!(book_fk.columns, vec!["library_number", "library_city"]);
    assert_eq!(book_fk.ref_columns, vec!["number", "city"]);
    assert_eq!(count(&db, "SELECT count(*) FROM book").await, 1);

    assert_fk_error(insert_book(&sm, "222", "123", "London").await);
    insert_book(&sm, "222", "123", "Krakow").await.unwrap();
}

#[tokio::test]
async fn test_recreate_with_modify_constraint_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .modify_table_constraint(
                TableConstraintRef::new(["id", "name", "library_number"]),
                Index::create()
                    .col(Book::Id)
                    .col(Book::Name)
                    .unique()
                    .to_owned(),
            )
            .to_owned(),
    )
    .await
    .unwrap();

    let book = table(&db, "book").await;
    assert_eq!(book.indexes.len(), 0);
    assert_eq!(book.unique_constraints.len(), 1);
    assert_eq!(
        book.unique_constraints.first().unwrap().columns,
        vec!["id", "name"]
    );
}

#[tokio::test]
async fn test_recreate_with_drop_constraint_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .drop_table_constraint(TableConstraintRef::new(["name", "id", "library_number"]))
            .to_owned(),
    )
    .await
    .unwrap();

    let book = table(&db, "book").await;
    assert_eq!(book.indexes.len(), 0);
    assert_eq!(book.unique_constraints.len(), 0);
}

#[tokio::test]
async fn test_recreate_without_operations_preserves_schema() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;
    exec(&db, "CREATE TABLE edge (id INTEGER PRIMARY KEY, a TEXT NOT NULL DEFAULT 'it''s', b DEFAULT (lower('X')), c REAL DEFAULT -1.5, d, e TIMESTAMP DEFAULT CURRENT_TIMESTAMP, parent_id INTEGER REFERENCES edge ON DELETE SET NULL ON UPDATE CASCADE, borrower_id varchar(3) REFERENCES borrower(id) ON DELETE RESTRICT ON UPDATE SET DEFAULT, UNIQUE (a, b))").await;
    exec(
        &db,
        "CREATE TABLE composite (b TEXT, a TEXT, v BLOB, PRIMARY KEY (a, b))",
    )
    .await;
    exec(&db, "CREATE TABLE child (id INTEGER PRIMARY KEY, a TEXT, b TEXT, FOREIGN KEY (a, b) REFERENCES composite (a, b))").await;
    exec(
        &db,
        "INSERT INTO edge (id, a, parent_id) VALUES (1, 'a', NULL), (2, 'b', 1)",
    )
    .await;
    exec(&db, "INSERT INTO composite VALUES ('b', 'a', x'00')").await;
    exec(&db, "INSERT INTO child VALUES (1, 'a', 'b')").await;

    for name in ["library", "book", "borrower", "edge", "composite", "child"] {
        let before = table(&db, name).await;
        sm.recreate_table(Table::recreate().table(Alias::new(name)).to_owned())
            .await
            .unwrap();
        assert_eq!(normalized(table(&db, name).await), normalized(before));
    }

    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM edge WHERE id = 2 AND parent_id = 1"
        )
        .await,
        1
    );
    assert_eq!(
        count(&db, "SELECT count(*) FROM pragma_foreign_key_check").await,
        0
    );
    exec(&db, "INSERT INTO edge (a) VALUES ('x')").await;
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM edge WHERE id = 3 AND b = 'x' AND c = -1.5"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn test_recreate_preserves_autoincrement_sequence() {
    let db = get_test_connection().await;
    exec(
        &db,
        "CREATE TABLE seq (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)",
    )
    .await;
    exec(&db, "INSERT INTO seq (v) VALUES ('a'), ('b'), ('c')").await;
    exec(&db, "DELETE FROM seq WHERE id = 3").await;
    let sm = SchemaManager::new(&db);

    sm.recreate_table(
        Table::recreate()
            .table(Alias::new("seq"))
            .add_column(string_null(Alias::new("w")))
            .to_owned(),
    )
    .await
    .unwrap();

    let seq = table(&db, "seq").await;
    assert!(seq.auto_increment);
    assert_eq!(column(&seq, "id").declared_type, "INTEGER");
    exec(&db, "INSERT INTO seq (v) VALUES ('d')").await;
    assert_eq!(count(&db, "SELECT max(id) FROM seq").await, 4);
}

#[tokio::test]
async fn test_recreate_preserves_expression_and_partial_index_across_rename() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;
    exec(&db, "CREATE UNIQUE INDEX `book-name-disposal-unique` ON book(`name`, COALESCE(date_of_disposal, 'not_deleted')) WHERE isbn IS NOT NULL").await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .rename_column(Book::Name, Alias::new("title"))
            .add_column(string_null(BookNew::AuthorName))
            .to_owned(),
    )
    .await
    .unwrap();

    let book = table(&db, "book").await;
    let index = book
        .indexes
        .iter()
        .find(|i| i.name == "book-name-disposal-unique")
        .unwrap();
    assert!(index.sql.contains("\"title\""));
    assert!(index.sql.contains("COALESCE"));
    assert!(index.sql.contains("WHERE isbn IS NOT NULL"));
    assert_eq!(
        count(
            &db,
            "SELECT partial FROM pragma_index_list('book') WHERE name = 'book-name-disposal-unique'"
        )
        .await,
        1
    );
    let duplicate = db
        .execute_unprepared("INSERT INTO book (id, title, date_of_purchase, library_number, library_city, isbn) VALUES ('112', 'Lord of the Rings', '2020-01-01', '123', 'Krakow', '1')")
        .await
        .unwrap_err();
    assert!(
        duplicate
            .to_string()
            .contains("UNIQUE constraint failed: index 'book-name-disposal-unique'"),
        "{duplicate}"
    );
    exec(&db, "INSERT INTO book (id, title, date_of_purchase, library_number, library_city, isbn) VALUES ('113', 'Lord of the Rings', '2020-01-01', '123', 'Krakow', NULL)").await;
}

#[tokio::test]
async fn test_recreate_preserves_triggers() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;
    exec(&db, "CREATE TRIGGER book_inserted AFTER INSERT ON book BEGIN INSERT INTO borrower (id, name) VALUES (NEW.id, NEW.name); END").await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .add_column(string_null(BookNew::AuthorName))
            .to_owned(),
    )
    .await
    .unwrap();

    assert_eq!(table(&db, "book").await.triggers.len(), 1);
    insert_book(&sm, "222", "123", "Krakow").await.unwrap();
    assert_eq!(
        count(&db, "SELECT count(*) FROM borrower WHERE id = '222'").await,
        1
    );
}

#[tokio::test]
async fn test_recreate_parent_table_keeps_referencing_rows() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Library::Table)
            .add_column(string_null(Alias::new("address")))
            .to_owned(),
    )
    .await
    .unwrap();

    assert_eq!(count(&db, "SELECT count(*) FROM book").await, 1);
    assert_eq!(
        count(&db, "SELECT count(*) FROM pragma_foreign_key_check").await,
        0
    );
    assert_eq!(count(&db, "PRAGMA defer_foreign_keys").await, 0);
}

#[tokio::test]
async fn test_recreate_parent_table_with_cascading_references_failure() {
    let db = get_test_connection().await;
    exec(&db, "CREATE TABLE parent (id INTEGER PRIMARY KEY)").await;
    exec(&db, "CREATE TABLE cascading (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON DELETE CASCADE)").await;
    exec(&db, "INSERT INTO parent VALUES (1)").await;
    let sm = SchemaManager::new(&db);
    let statement = Table::recreate()
        .table(Alias::new("parent"))
        .add_column(string_null(Alias::new("name")))
        .to_owned();

    exec(&db, "INSERT INTO cascading VALUES (1, NULL)").await;
    sm.recreate_table(statement.clone()).await.unwrap();

    exec(&db, "INSERT INTO cascading VALUES (2, 1)").await;
    let result = sm
        .recreate_table(
            Table::recreate()
                .table(Alias::new("parent"))
                .drop_column(Alias::new("name"))
                .to_owned(),
        )
        .await;

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("ON DELETE CASCADE")
    );
    assert_eq!(count(&db, "SELECT count(*) FROM cascading").await, 2);
    assert!(table(&db, "parent").await.has_column("name"));
}

#[tokio::test]
async fn test_recreate_with_foreign_key_violated_by_existing_data_failure() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    let result = sm
        .recreate_table(
            Table::recreate()
                .table(Book::Table)
                .add_column(string_len_null(BookNew::BorrowerId, 3).default("999"))
                .add_foreign_key(
                    ForeignKey::create()
                        .from(Book::Table, BookNew::BorrowerId)
                        .to(Borrower::Table, Borrower::Id)
                        .to_owned(),
                )
                .to_owned(),
        )
        .await;

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("foreign key violation")
    );
    let book = table(&db, "book").await;
    assert!(!book.has_column("borrower_id"));
    assert_eq!(count(&db, "PRAGMA defer_foreign_keys").await, 0);
}

#[tokio::test]
async fn test_recreate_with_skipped_foreign_key_check_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .add_column(string_len_null(BookNew::BorrowerId, 3).default("999"))
            .add_foreign_key(
                ForeignKey::create()
                    .from(Book::Table, BookNew::BorrowerId)
                    .to(Borrower::Table, Borrower::Id)
                    .to_owned(),
            )
            .skip_foreign_key_check()
            .to_owned(),
    )
    .await
    .unwrap();

    assert_eq!(
        count(&db, "SELECT count(*) FROM pragma_foreign_key_check('book')").await,
        1
    );
}

#[tokio::test]
async fn test_recreate_with_not_null_column_without_default_on_filled_table_failure() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    let result = sm
        .recreate_table(
            Table::recreate()
                .table(Book::Table)
                .add_column(string(BookNew::AuthorName))
                .to_owned(),
        )
        .await;

    let error = result.unwrap_err().to_string();
    assert!(error.contains("NOT NULL constraint failed"), "{error}");
    assert!(!table(&db, "book").await.has_column("author_name"));
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM sqlite_master WHERE name LIKE '_temp_table_%'"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn test_recreate_inside_outer_transaction() {
    let db = get_test_connection().await;
    create_test_tables(&SchemaManager::new(&db)).await;

    let tx = db.begin().await.unwrap();
    SchemaManager::new(&tx)
        .recreate_table(
            Table::recreate()
                .table(Book::Table)
                .drop_column(Book::Isbn)
                .to_owned(),
        )
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert!(table(&db, "book").await.has_column("isbn"));

    let tx = db.begin().await.unwrap();
    tx.execute_unprepared("PRAGMA defer_foreign_keys = ON")
        .await
        .unwrap();
    SchemaManager::new(&tx)
        .recreate_table(
            Table::recreate()
                .table(Book::Table)
                .drop_column(Book::Isbn)
                .to_owned(),
        )
        .await
        .unwrap();
    assert_eq!(count(&tx, "PRAGMA defer_foreign_keys").await, 1);
    tx.commit().await.unwrap();
    assert!(!table(&db, "book").await.has_column("isbn"));
}

#[tokio::test]
async fn test_recreate_with_drop_column_in_unique_constraint_failure() {
    assert_recreate_fails(
        Table::recreate()
            .table(Book::Table)
            .drop_column(Book::Name)
            .to_owned(),
        "it's used by a UNIQUE constraint",
    )
    .await;
}

#[tokio::test]
async fn test_recreate_with_drop_column_in_foreign_key_failure() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;
    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .drop_table_constraint(TableConstraintRef::new(["id", "name", "library_number"]))
            .to_owned(),
    )
    .await
    .unwrap();

    let error = sm
        .recreate_table(
            Table::recreate()
                .table(Book::Table)
                .drop_column(Book::LibraryNumber)
                .to_owned(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("referenced by a foreign key"));
}

#[tokio::test]
async fn test_recreate_with_drop_column_in_index_failure() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    let error = sm
        .recreate_table(
            Table::recreate()
                .table(Library::Table)
                .drop_column(Library::Name)
                .to_owned(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("library-name-unique"));
}

#[tokio::test]
async fn test_recreate_with_drop_column_in_expression_index_failure() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;
    exec(&db, "CREATE INDEX `book-isbn-lower` ON book(lower(isbn))").await;

    let result = sm
        .recreate_table(
            Table::recreate()
                .table(Book::Table)
                .drop_column(Book::Isbn)
                .to_owned(),
        )
        .await;

    let error = result.unwrap_err().to_string();
    assert!(error.contains("no such column: isbn"), "{error}");
    assert!(table(&db, "book").await.has_column("isbn"));
}

#[tokio::test]
async fn test_recreate_with_drop_primary_key_column_failure() {
    assert_recreate_fails(
        Table::recreate()
            .table(Borrower::Table)
            .drop_column(Borrower::Id)
            .to_owned(),
        "part of the primary key",
    )
    .await;
}

#[tokio::test]
async fn test_recreate_with_invalid_column_operations_failure() {
    let cases = [
        (
            Table::recreate()
                .table(Book::Table)
                .drop_column(Alias::new("missing"))
                .to_owned(),
            "Cannot drop column `missing`: it doesn't exist",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .drop_column(Book::Isbn)
                .drop_column(Book::Isbn)
                .to_owned(),
            "dropped more than once",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .modify_column(string_null(Alias::new("missing")))
                .to_owned(),
            "Cannot modify column `missing`: it doesn't exist",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .drop_column(Book::Isbn)
                .modify_column(string_null(Book::Isbn))
                .to_owned(),
            "it's dropped",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .modify_column(string_null(Book::Isbn))
                .modify_column(string(Book::Isbn))
                .to_owned(),
            "modified more than once",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .add_column(string_null(Book::Isbn))
                .to_owned(),
            "Cannot add column `isbn`: it already exists",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .add_column(string_null(BookNew::AuthorName))
                .add_column(string_null(BookNew::AuthorName))
                .to_owned(),
            "added more than once",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .rename_column(Alias::new("missing"), Alias::new("other"))
                .to_owned(),
            "Cannot rename column `missing`: it doesn't exist",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .rename_column(Book::Isbn, Book::Name)
                .to_owned(),
            "column `name` already exists",
        ),
    ];
    for (statement, message) in cases {
        assert_recreate_fails(statement, message).await;
    }
}

#[tokio::test]
async fn test_recreate_with_drop_and_add_same_column_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .drop_column(Book::Isbn)
            .add_column(ColumnDef::new(Book::Isbn).integer().null().to_owned())
            .to_owned(),
    )
    .await
    .unwrap();

    let book = table(&db, "book").await;
    assert_eq!(column(&book, "isbn").declared_type, "INTEGER");
    assert_eq!(
        count(&db, "SELECT count(*) FROM book WHERE isbn IS NULL").await,
        1
    );
}

#[tokio::test]
async fn test_recreate_with_invalid_constraint_operations_failure() {
    let fk_ref = || ForeignKeyRef::new(["library_number"], "library", ["number"]);
    let constraint_ref = || TableConstraintRef::new(["id", "name", "library_number"]);
    let cases = [
        (
            Table::recreate()
                .table(Book::Table)
                .drop_foreign_key(ForeignKeyRef::new(["name"], "library", ["number"]))
                .to_owned(),
            "not found",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .drop_foreign_key(fk_ref())
                .modify_foreign_key(
                    fk_ref(),
                    ForeignKey::create()
                        .from(Book::Table, Book::LibraryNumber)
                        .to(Library::Table, Library::Number)
                        .to_owned(),
                )
                .to_owned(),
            "changed more than once",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .drop_table_constraint(TableConstraintRef::new(["id"]))
                .to_owned(),
            "not found",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .drop_table_constraint(constraint_ref())
                .modify_table_constraint(
                    constraint_ref(),
                    Index::create().col(Book::Id).unique().to_owned(),
                )
                .to_owned(),
            "changed more than once",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .add_table_constraint(Index::create().col(Book::Name).to_owned())
                .to_owned(),
            "Only PRIMARY KEY and UNIQUE table constraints are supported",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .add_table_constraint(Index::create().col(Book::Id).primary().to_owned())
                .add_table_constraint(Index::create().col(Book::Name).primary().to_owned())
                .to_owned(),
            "Only one PRIMARY KEY table constraint can be added",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .modify_column(string_len(Book::Name, 3).primary_key())
                .to_owned(),
            "Conflicting primary key definitions",
        ),
    ];
    for (statement, message) in cases {
        assert_recreate_fails(statement, message).await;
    }
}

#[tokio::test]
async fn test_recreate_with_ambiguous_foreign_key_failure() {
    let db = get_test_connection().await;
    exec(&db, "CREATE TABLE parent (id INTEGER PRIMARY KEY)").await;
    exec(&db, "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id), FOREIGN KEY (parent_id) REFERENCES parent(id) ON DELETE CASCADE)").await;

    let error = SchemaManager::new(&db)
        .recreate_table(
            Table::recreate()
                .table(Alias::new("child"))
                .drop_foreign_key(ForeignKeyRef::new(["parent_id"], "parent", ["id"]))
                .to_owned(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("is ambiguous"));
}

#[tokio::test]
async fn test_recreate_with_modified_inline_primary_key_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Borrower::Table)
            .modify_column(string_len(Borrower::Id, 10).primary_key())
            .to_owned(),
    )
    .await
    .unwrap();

    let borrower = table(&db, "borrower").await;
    assert_eq!(column(&borrower, "id").declared_type, "varchar(10)");
    assert_eq!(column(&borrower, "id").primary_key_position, 1);
}

#[tokio::test]
async fn test_recreate_unsupported_table_failure() {
    let db = get_test_connection().await;
    exec(&db, "CREATE TABLE checked (id INTEGER PRIMARY KEY, v INTEGER CHECK (v > 0), g INTEGER GENERATED ALWAYS AS (v * 2) VIRTUAL)").await;

    let error = SchemaManager::new(&db)
        .recreate_table(Table::recreate().table(Alias::new("checked")).to_owned())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("CHECK constraints, generated columns")
    );
}

#[tokio::test]
async fn test_recreate_with_existing_temp_table_failure() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;
    exec(&db, "CREATE TABLE _temp_table_book (id TEXT)").await;

    assert!(
        sm.recreate_table(Table::recreate().table(Book::Table).to_owned())
            .await
            .unwrap_err()
            .to_string()
            .contains("table `_temp_table_book` already exists")
    );
}

#[tokio::test]
async fn test_recreate_invalid_statement_failure() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);

    let cases = [
        (Table::recreate(), "has to have table specified"),
        (
            Table::recreate()
                .table((Alias::new("main"), Alias::new("book")))
                .to_owned(),
            "Only unqualified table names",
        ),
        (
            Table::recreate().table(Alias::new("missing")).to_owned(),
            "Table `missing` doesn't exist",
        ),
    ];
    for (statement, message) in cases {
        let error = sm.recreate_table(statement).await.unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
    }
}

#[tokio::test]
async fn test_recreate_on_other_backend_failure() {
    let db = MockDatabase::new(DbBackend::Postgres).into_connection();
    let error = SchemaManager::new(&db)
        .recreate_table(Table::recreate().table(Book::Table).to_owned())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Only sqlite supports"));
}

#[tokio::test]
async fn test_recreate_with_foreign_key_actions_and_modified_foreign_key() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .modify_foreign_key(
                ForeignKeyRef::new(["library_number"], "library", ["number"]),
                ForeignKey::create()
                    .from(Book::Table, Book::LibraryNumber)
                    .to(Library::Table, Library::Number)
                    .on_delete(ForeignKeyAction::Cascade)
                    .on_update(ForeignKeyAction::SetDefault)
                    .to_owned(),
            )
            .to_owned(),
    )
    .await
    .unwrap();

    let book = table(&db, "book").await;
    let fk = book.foreign_keys.first().unwrap();
    assert_eq!(fk.on_delete, "CASCADE");
    assert_eq!(fk.on_update, "SET DEFAULT");

    let error = sm
        .recreate_table(Table::recreate().table(Library::Table).to_owned())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("rows in `book`"));
}

#[tokio::test]
async fn test_recreate_restores_autoincrement_sequence_of_emptied_table() {
    let db = get_test_connection().await;
    exec(
        &db,
        "CREATE TABLE seq (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)",
    )
    .await;
    exec(&db, "INSERT INTO seq (v) VALUES ('a'), ('b')").await;
    exec(&db, "DELETE FROM seq").await;

    SchemaManager::new(&db)
        .recreate_table(Table::recreate().table(Alias::new("seq")).to_owned())
        .await
        .unwrap();

    exec(&db, "INSERT INTO seq (v) VALUES ('c')").await;
    assert_eq!(count(&db, "SELECT max(id) FROM seq").await, 3);
}

#[tokio::test]
async fn test_recreate_with_foreign_key_to_non_unique_column_failure() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    let result = sm
        .recreate_table(
            Table::recreate()
                .table(Book::Table)
                .modify_foreign_key(
                    ForeignKeyRef::new(["library_number"], "library", ["number"]),
                    ForeignKey::create()
                        .from(Book::Table, Book::LibraryCity)
                        .to(Library::Table, Library::City)
                        .to_owned(),
                )
                .to_owned(),
        )
        .await;

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("foreign key mismatch")
    );
    assert_eq!(
        table(&db, "book")
            .await
            .foreign_keys
            .first()
            .unwrap()
            .ref_columns,
        vec!["number"]
    );
}

#[tokio::test]
async fn test_recreate_with_preexisting_foreign_key_mismatch_failure() {
    let db = get_test_connection().await;
    exec(
        &db,
        "CREATE TABLE parent (id INTEGER PRIMARY KEY, code TEXT)",
    )
    .await;
    exec(
        &db,
        "CREATE TABLE child (id INTEGER PRIMARY KEY, code TEXT REFERENCES parent(code))",
    )
    .await;

    let result = SchemaManager::new(&db)
        .recreate_table(
            Table::recreate()
                .table(Alias::new("child"))
                .add_column(string_null(Alias::new("v")))
                .to_owned(),
        )
        .await;

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("foreign key mismatch")
    );
    assert!(!table(&db, "child").await.has_column("v"));
}

#[tokio::test]
async fn test_recreate_parent_table_breaking_referencing_foreign_key_failure() {
    let db = get_test_connection().await;
    exec(
        &db,
        "CREATE TABLE parent (id INTEGER PRIMARY KEY, code TEXT UNIQUE)",
    )
    .await;
    exec(
        &db,
        "CREATE TABLE child (id INTEGER PRIMARY KEY, code TEXT REFERENCES parent(code))",
    )
    .await;
    exec(&db, "INSERT INTO parent VALUES (1, 'a')").await;
    exec(&db, "INSERT INTO child VALUES (1, 'a')").await;
    let sm = SchemaManager::new(&db);
    let drop_unique = Table::recreate()
        .table(Alias::new("parent"))
        .drop_table_constraint(TableConstraintRef::new(["code"]))
        .to_owned();

    let error = sm.recreate_table(drop_unique.clone()).await.unwrap_err();

    assert!(
        error
            .to_string()
            .contains("would break foreign keys of table `child`"),
        "{error}"
    );
    assert_eq!(table(&db, "parent").await.unique_constraints.len(), 1);
    exec(&db, "INSERT INTO child VALUES (2, 'a')").await;

    sm.recreate_table(
        drop_unique
            .clone()
            .skip_referencing_foreign_key_check()
            .to_owned(),
    )
    .await
    .unwrap();
    assert_eq!(table(&db, "parent").await.unique_constraints.len(), 0);
}

#[tokio::test]
async fn test_recreate_keeps_canonical_table_name() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Alias::new("BOOK"))
            .add_column(string_null(BookNew::AuthorName))
            .to_owned(),
    )
    .await
    .unwrap();

    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'book'"
        )
        .await,
        1
    );
    assert!(table(&db, "book").await.has_column("author_name"));
}

#[tokio::test]
async fn test_recreate_keeps_views_working() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;
    exec(&db, "CREATE VIEW book_names AS SELECT name FROM book").await;
    exec(&db, "CREATE TRIGGER borrower_inserted AFTER INSERT ON borrower BEGIN UPDATE book SET isbn = NEW.id; END").await;

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .add_column(string_null(BookNew::AuthorName))
            .to_owned(),
    )
    .await
    .unwrap();

    assert_eq!(count(&db, "SELECT count(*) FROM book_names").await, 1);
    exec(&db, "INSERT INTO borrower (id, name) VALUES ('777', 'Eve')").await;
    assert_eq!(
        count(&db, "SELECT count(*) FROM book WHERE isbn = '777'").await,
        1
    );
    assert_eq!(count(&db, "PRAGMA legacy_alter_table").await, 0);
}

#[tokio::test]
async fn test_recreate_restores_defer_foreign_keys_after_failure() {
    let db = get_test_connection().await;
    create_test_tables(&SchemaManager::new(&db)).await;
    let tx = db.begin().await.unwrap();
    tx.execute_unprepared("PRAGMA defer_foreign_keys = ON")
        .await
        .unwrap();

    SchemaManager::new(&tx)
        .recreate_table(
            Table::recreate()
                .table(Book::Table)
                .add_column(string(BookNew::AuthorName))
                .to_owned(),
        )
        .await
        .unwrap_err();

    assert_eq!(count(&tx, "PRAGMA defer_foreign_keys").await, 1);
    assert!(!table(&tx, "book").await.has_column("author_name"));
    tx.commit().await.unwrap();
}

fn assert_fk_error<T: std::fmt::Debug>(result: Result<T, sea_orm::DbErr>) {
    let error = result.unwrap_err().to_string();
    assert!(error.contains("FOREIGN KEY constraint failed"), "{error}");
}

#[tokio::test]
async fn test_recreate_with_column_values_and_order_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;

    sm.recreate_table(
        Table::recreate()
            .table(Library::Table)
            .add_column_with_value(
                ColumnDef::new(Alias::new("active"))
                    .boolean()
                    .not_null()
                    .to_owned(),
                Expr::value(true),
            )
            .modify_column_with_value(string(Library::Name), Expr::cust("upper(\"name\")"))
            .column_order([
                Alias::new("number"),
                Alias::new("active"),
                Alias::new("city"),
                Alias::new("name"),
            ])
            .to_owned(),
    )
    .await
    .unwrap();

    let library = table(&db, "library").await;
    assert_eq!(
        library
            .columns
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        vec!["number", "active", "city", "name"]
    );
    assert_eq!(column(&library, "active").default_value, None);
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM library WHERE active = 1 AND name = 'LIBRARY123' AND city = 'Krakow'"
        )
        .await,
        1
    );
    assert_eq!(count(&db, "SELECT count(*) FROM book").await, 1);
}

#[tokio::test]
async fn test_recreate_with_invalid_column_order_failure() {
    let cases = [
        (
            Table::recreate()
                .table(Book::Table)
                .column_order([Book::Id])
                .to_owned(),
            "has to list all 7 columns",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .column_order([
                    Book::Id,
                    Book::Id,
                    Book::Name,
                    Book::DateOfPurchase,
                    Book::DateOfDisposal,
                    Book::LibraryNumber,
                    Book::LibraryCity,
                ])
                .to_owned(),
            "unknown or repeated column `id`",
        ),
        (
            Table::recreate()
                .table(Book::Table)
                .column_order([Book::Id])
                .column_order([Book::Id])
                .to_owned(),
            "Column order is specified more than once",
        ),
    ];
    for (statement, message) in cases {
        assert_recreate_fails(statement, message).await;
    }
}

#[tokio::test]
async fn test_recreate_with_discarded_indexes_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;
    exec(
        &db,
        "CREATE TRIGGER library_inserted AFTER INSERT ON library BEGIN SELECT 1; END",
    )
    .await;

    sm.recreate_table(
        Table::recreate()
            .table(Library::Table)
            .drop_column(Library::Name)
            .add_column(string_null(Library::Name))
            .discard_indexes()
            .to_owned(),
    )
    .await
    .unwrap();

    let library = table(&db, "library").await;
    assert_eq!(library.indexes.len(), 0);
    assert_eq!(library.triggers.len(), 1);
    assert_eq!(
        count(&db, "SELECT count(*) FROM library WHERE name IS NULL").await,
        1
    );
}

#[tokio::test]
async fn test_recreate_keeps_self_references_with_destructive_actions() {
    for foreign_keys in ["ON", "OFF"] {
        let db = get_test_connection().await;
        exec(&db, &format!("PRAGMA foreign_keys = {foreign_keys}")).await;
        exec(&db, "CREATE TABLE node (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES node(id) ON DELETE CASCADE, other_id INTEGER)").await;
        exec(
            &db,
            "INSERT INTO node VALUES (1, NULL, NULL), (2, 1, 1), (3, 2, 2)",
        )
        .await;

        SchemaManager::new(&db)
            .recreate_table(
                Table::recreate()
                    .table(Alias::new("node"))
                    .add_column(string_null(Alias::new("name")))
                    .add_foreign_key(
                        ForeignKey::create()
                            .from(Alias::new("node"), Alias::new("other_id"))
                            .to(Alias::new("node"), Alias::new("id"))
                            .on_delete(ForeignKeyAction::SetNull)
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await
            .unwrap();

        assert_eq!(
            count(&db, "SELECT count(*) FROM node WHERE (id, parent_id, other_id) IN (VALUES (2, 1, 1), (3, 2, 2))").await,
            2,
            "foreign_keys = {foreign_keys}"
        );
        let node = table(&db, "node").await;
        assert!(
            node.foreign_keys.iter().all(|fk| fk.ref_table == "node"),
            "{node:?}"
        );
        exec(&db, "PRAGMA foreign_keys = ON").await;
        assert_eq!(
            count(&db, "SELECT count(*) FROM pragma_foreign_key_check").await,
            0
        );
        exec(&db, "DELETE FROM node WHERE id = 1").await;
        assert_eq!(count(&db, "SELECT count(*) FROM node").await, 0);
    }
}

#[tokio::test]
async fn test_recreate_with_custom_copy_source_success() {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;
    insert_book(&sm, "222", "123", "Krakow").await.unwrap();

    sm.recreate_table(
        Table::recreate()
            .table(Book::Table)
            .copy_from(
                [
                    Book::Id,
                    Book::Name,
                    Book::DateOfPurchase,
                    Book::LibraryNumber,
                    Book::LibraryCity,
                ],
                Query::select()
                    .columns([
                        Book::Id,
                        Book::Name,
                        Book::DateOfPurchase,
                        Book::LibraryNumber,
                        Book::LibraryCity,
                    ])
                    .from(Book::Table)
                    .and_where(Expr::col(Book::Id).eq("222"))
                    .to_owned(),
            )
            .to_owned(),
    )
    .await
    .unwrap();

    assert_eq!(count(&db, "SELECT count(*) FROM book").await, 1);
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM book WHERE id = '222' AND isbn IS NULL"
        )
        .await,
        1
    );

    let error = sm
        .recreate_table(
            Table::recreate()
                .table(Book::Table)
                .copy_from(
                    [Book::Id],
                    Query::select()
                        .column(Book::Id)
                        .from(Book::Table)
                        .to_owned(),
                )
                .copy_from(
                    [Book::Id],
                    Query::select()
                        .column(Book::Id)
                        .from(Book::Table)
                        .to_owned(),
                )
                .to_owned(),
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Copy source is specified more than once")
    );
}

#[tokio::test]
async fn test_recreate_parent_table_restores_set_null_references() {
    let db = get_test_connection().await;
    exec(&db, "CREATE TABLE parent (id INTEGER PRIMARY KEY)").await;
    exec(&db, "CREATE TABLE child (id INTEGER PRIMARY KEY, a INTEGER REFERENCES parent(id) ON DELETE SET NULL, b INTEGER REFERENCES parent(id) ON DELETE SET DEFAULT)").await;
    exec(&db, "INSERT INTO parent VALUES (1), (2)").await;
    exec(
        &db,
        "INSERT INTO child VALUES (1, 1, 2), (2, NULL, 1), (3, 2, NULL)",
    )
    .await;

    SchemaManager::new(&db)
        .recreate_table(
            Table::recreate()
                .table(Alias::new("parent"))
                .add_column(string_null(Alias::new("name")))
                .to_owned(),
        )
        .await
        .unwrap();

    assert_eq!(
        count(&db, "SELECT count(*) FROM child WHERE (id, a, b) IS (1, 1, 2) OR (id, a, b) IS (2, NULL, 1) OR (id, a, b) IS (3, 2, NULL)").await,
        3
    );
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM sqlite_temp_master WHERE name LIKE '_temp_table_%'"
        )
        .await,
        0
    );
    assert_eq!(
        count(&db, "SELECT count(*) FROM pragma_foreign_key_check").await,
        0
    );
}

async fn assert_recreate_fails(statement: crate::TableRecreateStatement, message: &str) {
    let db = get_test_connection().await;
    let sm = SchemaManager::new(&db);
    create_test_tables(&sm).await;
    let before = table(&db, "book").await;

    let error = sm.recreate_table(statement).await.unwrap_err();

    assert!(error.to_string().contains(message), "{error}");
    assert_eq!(table(&db, "book").await, before);
    assert_eq!(count(&db, "SELECT count(*) FROM book").await, 1);
}

async fn get_test_connection() -> DatabaseConnection {
    let connect_options = ConnectOptions::new("sqlite::memory:")
        .max_connections(1)
        .to_owned();
    Database::connect(connect_options).await.unwrap()
}

async fn table<C: ConnectionTrait>(db: &C, name: &str) -> TableInfo {
    load_table(db, name).await.unwrap()
}

fn column<'a>(table: &'a TableInfo, name: &str) -> &'a ColumnInfo {
    table.columns.iter().find(|c| c.name == name).unwrap()
}

fn normalized(mut table: TableInfo) -> TableInfo {
    table.sql = String::new();
    table
        .foreign_keys
        .sort_by(|a, b| (&a.ref_table, &a.columns).cmp(&(&b.ref_table, &b.columns)));
    table
        .unique_constraints
        .sort_by(|a, b| a.columns.cmp(&b.columns));
    table
}

async fn exec(db: &DatabaseConnection, sql: &str) {
    db.execute_unprepared(sql).await.unwrap();
}

async fn count<C: ConnectionTrait>(db: &C, sql: &str) -> i64 {
    db.query_one_raw(Statement::from_string(DbBackend::Sqlite, sql))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap()
}

async fn insert_book(
    sm: &SchemaManager<'_>,
    id: &str,
    library_number: &str,
    library_city: &str,
) -> Result<(), sea_orm::DbErr> {
    sm.exec_stmt(
        Query::insert()
            .into_table(Book::Table)
            .columns([
                Book::Id,
                Book::Name,
                Book::DateOfPurchase,
                Book::LibraryNumber,
                Book::LibraryCity,
                Book::Isbn,
            ])
            .values([
                id.into(),
                "Harry Potter".into(),
                "2020-01-01".into(),
                library_number.into(),
                library_city.into(),
                "456456".into(),
            ])
            .unwrap()
            .to_owned(),
    )
    .await
}

#[derive(DeriveIden)]
enum Library {
    Table,
    Number,
    Name,
    City,
}

#[derive(DeriveIden)]
enum Book {
    Table,
    Id,
    Name,
    LibraryNumber,
    LibraryCity,
    DateOfPurchase,
    DateOfDisposal,
    Isbn,
}

#[derive(DeriveIden)]
enum BookNew {
    NewAwesomeLibraryNumber,
    AuthorName,
    BorrowerId,
}

#[derive(DeriveIden)]
enum Borrower {
    Table,
    Id,
    Name,
}

async fn create_test_tables(sm: &SchemaManager<'_>) {
    sm.create_table(
        Table::create()
            .table(Library::Table)
            .col(string_len(Library::Number, 3).primary_key())
            .col(string(Library::Name))
            .col(string(Library::City))
            .to_owned(),
    )
    .await
    .unwrap();

    sm.create_table(
        Table::create()
            .table(Book::Table)
            .col(string_len(Book::Id, 3).primary_key())
            .col(string(Book::Name))
            .col(custom(Book::DateOfPurchase, Alias::new("datetime")))
            .col(custom_null(Book::DateOfDisposal, Alias::new("datetime")))
            .col(string_len(Book::LibraryNumber, 3))
            .col(string(Book::LibraryCity))
            .col(string_null(Book::Isbn))
            .foreign_key(
                ForeignKey::create()
                    .name("fk-book-library")
                    .from(Book::Table, Book::LibraryNumber)
                    .to(Library::Table, Library::Number),
            )
            .index(
                Index::create()
                    .col(Book::Id)
                    .col(Book::Name)
                    .col(Book::LibraryNumber)
                    .unique(),
            )
            .to_owned(),
    )
    .await
    .unwrap();

    sm.create_table(
        Table::create()
            .table(Borrower::Table)
            .col(string_len(Borrower::Id, 3).primary_key())
            .col(string(Borrower::Name))
            .to_owned(),
    )
    .await
    .unwrap();

    sm.create_index(
        Index::create()
            .name("library-name-unique")
            .table(Library::Table)
            .col(Library::Name)
            .to_owned(),
    )
    .await
    .unwrap();

    sm.exec_stmt(
        Query::insert()
            .into_table(Library::Table)
            .columns([Library::Number, Library::Name, Library::City])
            .values(["123".into(), "Library123".into(), "Krakow".into()])
            .unwrap()
            .to_owned(),
    )
    .await
    .unwrap();

    sm.exec_stmt(
        Query::insert()
            .into_table(Book::Table)
            .columns([
                Book::Id,
                Book::Name,
                Book::DateOfPurchase,
                Book::LibraryNumber,
                Book::LibraryCity,
                Book::Isbn,
            ])
            .values([
                "111".into(),
                "Lord of the Rings".into(),
                "2020-01-01".into(),
                "123".into(),
                "Krakow".into(),
                "654321".into(),
            ])
            .unwrap()
            .to_owned(),
    )
    .await
    .unwrap();

    sm.exec_stmt(
        Query::insert()
            .into_table(Borrower::Table)
            .columns([Borrower::Id, Borrower::Name])
            .values(["321".into(), "Adam".into()])
            .unwrap()
            .to_owned(),
    )
    .await
    .unwrap();
}
