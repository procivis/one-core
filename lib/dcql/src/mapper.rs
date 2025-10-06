use crate::matching::ClaimFilter;
use crate::{ClaimPath, ClaimQuery, ClaimQueryId, ClaimValue, CredentialQueryId, PathSegment};

impl From<String> for CredentialQueryId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<CredentialQueryId> for String {
    fn from(value: CredentialQueryId) -> Self {
        value.to_string()
    }
}

impl From<&str> for CredentialQueryId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for ClaimQueryId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ClaimQueryId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
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

impl From<ClaimQuery> for ClaimFilter {
    fn from(value: ClaimQuery) -> Self {
        Self {
            path: value.path,
            values: value.values.unwrap_or_default(),
            required: value.required.unwrap_or(true),
        }
    }
}

impl From<String> for ClaimValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for ClaimValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<isize> for ClaimValue {
    fn from(value: isize) -> Self {
        Self::Integer(value)
    }
}

impl From<bool> for ClaimValue {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}
