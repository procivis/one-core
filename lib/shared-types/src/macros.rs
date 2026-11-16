/// Declares one or more newtypes wrapping a [`uuid::Uuid`].
///
/// Each generated type is `Copy` and `Ord`, (de)serializes transparently as the inner UUID and
/// gets: a random `new()` constructor, [`std::str::FromStr`], [`std::fmt::Display`],
/// `From<Uuid>`, `From<Self> for Uuid`, `PartialEq<Uuid>`, a `utoipa::ToSchema` derive (feature
/// `utoipa`) and the sea-orm conversions from [`impls_for_seaorm_newtype`] (feature `sea-orm`).
///
/// # Examples
/// ```ignore
/// uuid_ids! {
///     /// Identifier of a credential
///     CredentialId,
///     ProofId,
/// }
/// ```
macro_rules! uuid_ids {
    ($( $(#[$meta:meta])* $name:ident ),* $(,)?) => {
        $(
            $(#[$meta])*
            #[derive(
                Debug,
                Clone,
                Copy,
                Eq,
                PartialEq,
                Hash,
                Ord,
                PartialOrd,
                serde::Serialize,
                serde::Deserialize,
            )]
            #[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
            #[serde(transparent)]
            #[repr(transparent)]
            pub struct $name(uuid::Uuid);

            impl $name {
                /// Generates a new random identifier.
                #[expect(
                    clippy::new_without_default,
                    reason = "a default value should not be a random identifier"
                )]
                pub fn new() -> Self {
                    Self(uuid::Uuid::new_v4())
                }
            }

            $crate::macros::impls_for_uuid_newtype!($name);

            #[cfg(feature = "sea-orm")]
            $crate::macros::impls_for_seaorm_newtype!($name);
        )*
    };
}
pub(crate) use uuid_ids;

/// Declares one or more newtypes wrapping a [`String`].
///
/// Each generated type (de)serializes transparently as the inner string and gets: `as_str()`,
/// infallible [`std::str::FromStr`], `From<&str>`, `From<String>`, `From<Self> for String`,
/// `AsRef<str>`, `Borrow<str>` (allows looking up `&str` keys in maps keyed by the newtype),
/// [`std::fmt::Display`], a `utoipa::ToSchema` derive (feature `utoipa`) and the sea-orm
/// conversions from [`impls_for_seaorm_newtype`] (feature `sea-orm`).
///
/// # Examples
/// ```ignore
/// string_ids! {
///     /// Identifier of a signer based in CoreConfig.signer
///     SignerId,
///     TaskId,
/// }
/// ```
macro_rules! string_ids {
    ($( $(#[$meta:meta])* $name:ident ),* $(,)?) => {
        $(
            $(#[$meta])*
            #[derive(
                Debug,
                Clone,
                Eq,
                PartialEq,
                Hash,
                Ord,
                PartialOrd,
                serde::Serialize,
                serde::Deserialize,
            )]
            #[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
            #[serde(transparent)]
            #[repr(transparent)]
            pub struct $name(String);

            impl $name {
                /// Returns the underlying string.
                pub fn as_str(&self) -> &str {
                    &self.0
                }
            }

            impl std::str::FromStr for $name {
                type Err = std::convert::Infallible;

                fn from_str(s: &str) -> Result<Self, Self::Err> {
                    Ok(Self(s.to_owned()))
                }
            }

            impl std::convert::From<&str> for $name {
                fn from(value: &str) -> Self {
                    Self(value.to_owned())
                }
            }

            impl std::convert::AsRef<str> for $name {
                fn as_ref(&self) -> &str {
                    &self.0
                }
            }

            // consistent with `Eq`, `Ord` and `Hash`, which are derived from the inner `String`
            impl std::borrow::Borrow<str> for $name {
                fn borrow(&self) -> &str {
                    &self.0
                }
            }

            $crate::macros::impl_display!($name);
            $crate::macros::impl_from!($name; String);
            $crate::macros::impl_into!($name; String);

            #[cfg(feature = "sea-orm")]
            $crate::macros::impls_for_seaorm_newtype!($name);
        )*
    };
}
pub(crate) use string_ids;

/// Implements the traits necessary for using a newtype in sea-orm, including the
/// `From<&T> for T` conversion needed by `find_by_id`.
///
/// The type is stored in the database as a string: it must implement [`std::fmt::Display`],
/// [`std::str::FromStr`] and [`Clone`].
#[cfg(feature = "sea-orm")]
macro_rules! impls_for_seaorm_newtype {
    ($newtype: ty) => {
        // needed for sea-orm `find_by_id` to work
        impl std::convert::From<&$newtype> for $newtype {
            fn from(source: &$newtype) -> Self {
                source.clone()
            }
        }

        $crate::macros::impls_for_seaorm_value!($newtype);
    };
}
#[cfg(feature = "sea-orm")]
pub(crate) use impls_for_seaorm_newtype;

/// Same as [`impls_for_seaorm_newtype`], but without the `From<&T> for T` conversion, for
/// types that already provide it regardless of the `sea-orm` feature.
#[cfg(feature = "sea-orm")]
macro_rules! impls_for_seaorm_value {
    ($newtype: ty) => {
        impl std::convert::From<$newtype> for sea_orm::Value {
            fn from(source: $newtype) -> Self {
                source.to_string().into()
            }
        }

        // needed for sea-orm `eq` to work
        impl std::convert::From<&$newtype> for sea_orm::Value {
            fn from(source: &$newtype) -> Self {
                source.to_string().into()
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
                sea_orm::sea_query::ColumnType::string(None)
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
#[cfg(feature = "sea-orm")]
pub(crate) use impls_for_seaorm_value;

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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use crate::{CredentialId, SignerId};

    const UUID: &str = "3fa85f64-5717-4562-b3fc-2c963f66afa6";

    #[test]
    fn test_uuid_id_str_roundtrip() {
        let id = CredentialId::from_str(UUID).unwrap();
        assert_eq!(id.to_string(), UUID);
        assert_eq!(Uuid::from(id), Uuid::from_str(UUID).unwrap());
        assert!(id == Uuid::from_str(UUID).unwrap());
        assert!(CredentialId::from_str("not-a-uuid").is_err());
        assert_ne!(CredentialId::new(), CredentialId::new());
    }

    #[test]
    fn test_uuid_id_ord_matches_uuid() {
        let lower = CredentialId::from(Uuid::from_u128(1));
        let higher = CredentialId::from(Uuid::from_u128(2));
        assert!(lower < higher);
    }

    #[test]
    fn test_uuid_id_serde_transparent() {
        let id = CredentialId::from_str(UUID).unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{UUID}\""));
        assert_eq!(serde_json::from_str::<CredentialId>(&json).unwrap(), id);
    }

    #[test]
    fn test_string_id_conversions() {
        let id = SignerId::from("X509");
        assert_eq!(id, SignerId::from_str("X509").unwrap());
        assert_eq!(id, SignerId::from("X509".to_string()));
        assert_eq!(id.as_ref(), "X509");
        assert_eq!(id.as_str(), "X509");
        assert_eq!(id.to_string(), "X509");
        assert_eq!(String::from(id), "X509");
    }

    #[test]
    fn test_string_id_borrow_lookup() {
        let map = std::collections::HashMap::from([(SignerId::from("X509"), 1)]);
        assert_eq!(map.get("X509"), Some(&1));
        assert_eq!(map.get("other"), None);
    }

    #[test]
    fn test_string_id_serde_transparent() {
        let id = SignerId::from("X509");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"X509\"");
        assert_eq!(serde_json::from_str::<SignerId>(&json).unwrap(), id);
    }

    #[cfg(feature = "sea-orm")]
    #[test]
    fn test_seaorm_value_roundtrip() {
        use sea_orm::sea_query::ValueType;

        use crate::DidValue;

        let id = CredentialId::from_str(UUID).unwrap();
        let value = sea_orm::Value::from(&id);
        assert_eq!(value, sea_orm::Value::from(UUID.to_string()));
        assert_eq!(<CredentialId as ValueType>::try_from(value).unwrap(), id);

        let id = SignerId::from("X509");
        let value = sea_orm::Value::from(id.clone());
        assert_eq!(<SignerId as ValueType>::try_from(value).unwrap(), id);

        let did = DidValue::from_str("did:example:12345").unwrap();
        let value = sea_orm::Value::from(&did);
        assert_eq!(value, sea_orm::Value::from("did:example:12345".to_string()));
        assert_eq!(<DidValue as ValueType>::try_from(value).unwrap(), did);
    }
}
