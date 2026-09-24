use sea_orm_migration::prelude::*;

use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

pub trait ColumnDefExt {
    fn large_blob<T: WithSupportedDbType>(&mut self, manager: &T) -> &mut ColumnDef;
    fn datetime_millisecond_precision<T: WithSupportedDbType>(
        &mut self,
        manager: &T,
    ) -> &mut ColumnDef;
    fn datetime_second_precision<T: WithSupportedDbType>(&mut self, manager: &T) -> &mut ColumnDef;
}

impl ColumnDefExt for ColumnDef {
    fn large_blob<T: WithSupportedDbType>(&mut self, _manager: &T) -> &mut ColumnDef {
        self.blob();

        #[cfg(feature = "mysql")]
        if matches!(_manager.supported_db_type(), SupportedDbType::MySql) {
            self.custom(extension::mysql::MySqlType::LongBlob);
        }

        self
    }

    fn datetime_millisecond_precision<T: WithSupportedDbType>(
        &mut self,
        manager: &T,
    ) -> &mut ColumnDef {
        let dt = match manager.supported_db_type() {
            SupportedDbType::MySql => "datetime(3)",
            SupportedDbType::Postgres => "timestamp(3) with time zone",
            SupportedDbType::Sqlite => "datetime",
        };

        self.custom(Alias::new(dt));

        self
    }

    fn datetime_second_precision<T: WithSupportedDbType>(&mut self, manager: &T) -> &mut ColumnDef {
        let dt = match manager.supported_db_type() {
            SupportedDbType::MySql => "datetime(0)",
            SupportedDbType::Postgres => "timestamp(0) with time zone",
            SupportedDbType::Sqlite => "datetime",
        };

        self.custom(Alias::new(dt));

        self
    }
}

pub(crate) fn uuid_char<T: IntoIden>(ident: T) -> ColumnDef {
    ColumnDef::new(ident).char_len(36).not_null().take()
}

pub(crate) fn uuid_char_null<T: IntoIden>(ident: T) -> ColumnDef {
    ColumnDef::new(ident).char_len(36).null().take()
}

pub(crate) fn timestamp<T: IntoIden, DB: WithSupportedDbType>(ident: T, manager: &DB) -> ColumnDef {
    ColumnDef::new(ident)
        .datetime_millisecond_precision(manager)
        .not_null()
        .take()
}
pub(crate) fn timestamp_seconds<T: IntoIden, DB: WithSupportedDbType>(
    ident: T,
    manager: &DB,
) -> ColumnDef {
    ColumnDef::new(ident)
        .datetime_second_precision(manager)
        .not_null()
        .take()
}

pub(crate) fn timestamp_null<T: IntoIden, DB: WithSupportedDbType>(
    ident: T,
    manager: &DB,
) -> ColumnDef {
    ColumnDef::new(ident)
        .datetime_millisecond_precision(manager)
        .null()
        .take()
}
pub(crate) fn timestamp_seconds_null<T: IntoIden, DB: WithSupportedDbType>(
    ident: T,
    manager: &DB,
) -> ColumnDef {
    ColumnDef::new(ident)
        .datetime_second_precision(manager)
        .null()
        .take()
}

pub(crate) fn large_blob<T: IntoIden, DB: WithSupportedDbType>(
    ident: T,
    manager: &DB,
) -> ColumnDef {
    ColumnDef::new(ident).large_blob(manager).not_null().take()
}

pub(crate) fn large_blob_null<T: IntoIden, DB: WithSupportedDbType>(
    ident: T,
    manager: &DB,
) -> ColumnDef {
    ColumnDef::new(ident).large_blob(manager).null().take()
}
