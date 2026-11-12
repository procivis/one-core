use sea_orm::sea_query::{
    ColumnDef, DynIden, Expr, ForeignKeyCreateStatement, IndexCreateStatement, SelectStatement,
};

use crate::{ForeignKeyRef, TableConstraintRef};

#[derive(Debug, Clone)]
pub(crate) enum TableRecreateOperation {
    AddColumn(ColumnDef, Option<Expr>),
    ModifyColumn(ColumnDef, Option<Expr>),
    ColumnOrder(Vec<DynIden>),
    CopyFrom(Vec<DynIden>, SelectStatement),
    DropColumn(DynIden),
    RenameColumn(DynIden, DynIden),
    AddForeignKey(ForeignKeyCreateStatement),
    DropForeignKey(ForeignKeyRef),
    ModifyForeignKey(ForeignKeyRef, ForeignKeyCreateStatement),
    AddTableConstraint(IndexCreateStatement),
    DropTableConstraint(TableConstraintRef),
    ModifyTableConstraint(TableConstraintRef, IndexCreateStatement),
}
