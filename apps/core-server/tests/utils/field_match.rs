use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

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

    fn assert_eq_unordered<T>(&self, other: &[T])
    where
        T: DeserializeOwned + Eq + Hash + Debug;
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

    #[track_caller]
    fn assert_eq_unordered<T>(&self, other: &[T])
    where
        T: DeserializeOwned + Eq + Hash + Debug,
    {
        let vec = self.parse::<Vec<T>>();
        let set: HashSet<&_> = HashSet::from_iter(&vec);
        assert_eq!(set, HashSet::from_iter(other));
    }
}
