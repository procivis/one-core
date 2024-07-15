/// Implements necessary traits for using *newtypes* in sea-orm
///
/// # Examples
/// ```
///   struct MyNewtype(String);
///   // assumes that the newtype wraps a String and will be stored in the database as a String.
///   impl_for_seaorm_newtype!(MyNewtype);
///
///   struct MyNewtype(OtherType);
///   // assumes that OtherType will be stored in the database as a String, so it must be convertible to a String and also implement FromStr.
///   impl FromStr for MyNewtype { ... }
///   impl_for_seaorm_newtype!(MyNewtype);
/// ```
macro_rules! impls_for_seaorm_newtype {
    ($newtype: ty) => {
        impl std::convert::From<$newtype> for sea_orm::Value {
            fn from(source: $newtype) -> Self {
                source.0.to_string().into()
            }
        }
        // needed for sea-orm `eq` to work
        impl std::convert::From<&$newtype> for sea_orm::Value {
            fn from(source: &$newtype) -> Self {
                source.0.to_string().into()
            }
        }

        impl sea_orm::TryGetable for $newtype {
            fn try_get_by<I: sea_orm::ColIdx>(
                res: &sea_orm::QueryResult,
                idx: I,
            ) -> Result<Self, sea_orm::TryGetError> {
                let s: String = <String as sea_orm::TryGetable>::try_get_by(res, idx)?;

                let newtype_str = stringify!($newtype);
                let s: $newtype = s.parse().map_err(|error| {
                    sea_orm::TryGetError::DbErr(sea_orm::error::DbErr::Type(format!(
                        "Failed to parse {newtype_str}: {error}"
                    )))
                })?;

                Ok(s)
            }
        }

        impl sea_orm::sea_query::ValueType for $newtype {
            fn try_from(v: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
                let s = <String as sea_orm::sea_query::ValueType>::try_from(v)?;

                let s: $newtype = s.parse().map_err(|_| sea_orm::sea_query::ValueTypeErr)?;

                Ok(s)
            }

            fn type_name() -> String {
                stringify!($newtype).to_owned()
            }

            fn array_type() -> sea_orm::sea_query::ArrayType {
                sea_orm::sea_query::ArrayType::String
            }

            fn column_type() -> sea_orm::sea_query::ColumnType {
                sea_orm::sea_query::ColumnType::String(None)
            }
        }

        // needed for sea-orm `find_by_id` to work
        impl std::convert::From<&$newtype> for $newtype {
            fn from(source: &$newtype) -> Self {
                Self(source.0.to_owned())
            }
        }

        // needed if we want to put the type inside and Option
        impl sea_orm::sea_query::value::Nullable for $newtype {
            fn null() -> sea_orm::Value {
                sea_orm::Value::String(None)
            }
        }

        // needed if we want to use the type as a primary key
        impl sea_orm::TryFromU64 for $newtype {
            fn try_from_u64(_n: u64) -> Result<Self, sea_orm::DbErr> {
                Err(sea_orm::DbErr::ConvertFromU64(stringify!($newtype)))
            }
        }
    };
}
pub(crate) use impls_for_seaorm_newtype;

/// Implements [`std::str::FromStr`], [`std::fmt::Display`], [`std::convert::From`] and [`std::convert::Into`] for a newtype that wraps an Uuid
macro_rules! impls_for_uuid_newtype {
    ($newtype: ty) => {
        impl std::str::FromStr for $newtype {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let s = s.parse()?;

                Ok(Self(s))
            }
        }

        impl std::cmp::PartialEq<uuid::Uuid> for $newtype {
            fn eq(&self, other: &uuid::Uuid) -> bool {
                self.0.eq(other)
            }
        }

        $crate::macros::impl_display!($newtype);
        $crate::macros::impl_from!($newtype; uuid::Uuid);
        $crate::macros::impl_into!($newtype; uuid::Uuid);
    };
}
pub(crate) use impls_for_uuid_newtype;

/// Implements [`std::fmt::Display`] for a newtype, assuming that the inner type implements Display.
macro_rules! impl_display {
    ($newtype: ty) => {
        impl std::fmt::Display for $newtype {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}
pub(crate) use impl_display;

/// Implements [`std::convert::From`]
macro_rules! impl_from {
    ($newtype: ty; $inner: ty) => {
        impl std::convert::From<$inner> for $newtype {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }
    };
}
pub(crate) use impl_from;

/// Implements [`std::convert::From`]
macro_rules! impl_from_unnamed {
    ($newtype: ty; $inner: ty) => {
        impl std::convert::From<$inner> for $newtype {
            fn from(value: $inner) -> Self {
                Self(value.into())
            }
        }
    };
}
pub(crate) use impl_from_unnamed;

/// Implements [`std::convert::Into`]
macro_rules! impl_into {
    ($newtype: ty; $inner: ty) => {
        impl std::convert::From<$newtype> for $inner {
            fn from(value: $newtype) -> Self {
                value.0.into()
            }
        }
    };
}
pub(crate) use impl_into;

/// Implements [`std::convert::Into`]
macro_rules! impl_into_unnamed {
    ($newtype: ty; $inner: ty) => {
        #[allow(clippy::from_over_into)]
        impl std::convert::Into<$inner> for $newtype {
            fn into(self) -> $inner {
                <$inner>::from(self.0)
            }
        }
    };
}
pub(crate) use impl_into_unnamed;
