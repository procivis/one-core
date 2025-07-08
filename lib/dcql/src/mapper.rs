use crate::{ClaimPath, ClaimQueryId, CredentialQueryId, PathSegment};

impl<T: ToString> From<T> for CredentialQueryId {
    fn from(value: T) -> Self {
        Self(value.to_string())
    }
}

impl<T: ToString> From<T> for ClaimQueryId {
    fn from(value: T) -> Self {
        Self(value.to_string())
    }
}

impl<T: Into<PathSegment>> From<Vec<T>> for ClaimPath {
    fn from(value: Vec<T>) -> Self {
        Self {
            segments: value.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<String> for PathSegment {
    fn from(value: String) -> Self {
        Self::PropertyName(value)
    }
}

impl From<&str> for PathSegment {
    fn from(value: &str) -> Self {
        Self::PropertyName(value.to_owned())
    }
}

impl From<usize> for PathSegment {
    fn from(value: usize) -> Self {
        Self::ArrayIndex(value)
    }
}
