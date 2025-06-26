use std::fmt::Debug;

use serde::de::DeserializeOwned;
use serde_json::Value;
use similar_asserts::assert_eq;

pub trait FieldHelpers {
    fn parse<T>(&self) -> T
    where
        T: DeserializeOwned;

    fn assert_eq<T>(&self, other: &T)
    where
        T: DeserializeOwned + PartialEq + Debug;
}

impl FieldHelpers for Value {
    #[track_caller]
    fn parse<T>(&self) -> T
    where
        T: DeserializeOwned,
    {
        T::deserialize(self).unwrap()
    }

    #[track_caller]
    fn assert_eq<T>(&self, other: &T)
    where
        T: DeserializeOwned + PartialEq + Debug,
    {
        assert_eq!(&self.parse::<T>(), other);
    }
}
