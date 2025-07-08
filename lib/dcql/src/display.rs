use std::fmt::Display;

use crate::{ClaimPath, ClaimQueryId, CredentialQueryId, PathSegment};

impl Display for CredentialQueryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for ClaimQueryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for ClaimPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let elements = self
            .segments
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "[{elements}]")
    }
}

impl Display for PathSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathSegment::PropertyName(name) => write!(f, "\"{name}\""),
            PathSegment::ArrayIndex(idx) => write!(f, "{idx}"),
            PathSegment::ArrayAll => write!(f, "null"),
        }
    }
}
