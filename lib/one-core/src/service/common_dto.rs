use serde::{Deserialize, Serialize};

pub const KB: usize = 1 << 10;
pub const MB: usize = KB << 10;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoundedB64Image<const MAX: usize>(pub(crate) String);
