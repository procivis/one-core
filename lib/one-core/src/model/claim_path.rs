use std::fmt::{Display, Formatter};

/// Segment of a claim path in the formatted credential
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimPathSegment {
    Key(String),
    Index(usize),
}

impl From<&str> for ClaimPathSegment {
    fn from(key: &str) -> Self {
        Self::Key(key.to_string())
    }
}

impl Display for ClaimPathSegment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key(key) => f.write_str(key),
            Self::Index(index) => write!(f, "{index}"),
        }
    }
}
