//! Common code for status list types

use serde::{Deserialize, Serialize};

#[derive(Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct StatusListSizeParams<const MINIMUM_CAPACITY: usize> {
    /// number of entries on the generated status list
    pub capacity: usize,
    /// assignment block size, when allocating indexes on the status-list,
    /// a random block is selected (to optimize for parallel execution).
    /// When a block is filled, a new status list is started.
    ///
    /// `capacity` must be a multiple of `block_size`
    ///
    /// This approach leads to statistically filling each status list
    /// to a certain amount, before starting another:
    ///
    /// | capacity | block_size | avg. fill |
    /// |---------:|-----------:|----------:|
    /// |   131072 |         16 |      32 % |
    /// |   131072 |         32 |      49 % |
    /// |   131072 |         64 |      63 % |
    /// |   131072 |        128 |      74 % |
    /// |   131072 |        256 |      82 % |
    /// |   131072 |        512 |      88 % |
    /// |  1048576 |         16 |      27 % |
    /// |  1048576 |         32 |      43 % |
    /// |  1048576 |         64 |      58 % |
    /// |  1048576 |        128 |      70 % |
    /// |  1048576 |        256 |      79 % |
    /// |  1048576 |        512 |      86 % |
    ///
    /// so, when growing `capacity`, it makes sense to grow `block_size` as well
    pub block_size: usize,
}

impl<'de, const MINIMUM_CAPACITY: usize> Deserialize<'de>
    for StatusListSizeParams<MINIMUM_CAPACITY>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Params {
            capacity: Option<usize>,
            block_size: Option<usize>,
        }
        let deserialized = Params::deserialize(deserializer)?;
        let capacity = deserialized.capacity.unwrap_or(131072);
        let block_size = deserialized.block_size.unwrap_or(128);

        if capacity < MINIMUM_CAPACITY {
            return Err(serde::de::Error::custom(format!(
                "Invalid capacity: {capacity}"
            )));
        }

        if !capacity.is_multiple_of(block_size) {
            return Err(serde::de::Error::custom(format!(
                "Invalid blockSize: {block_size} (for capacity: {capacity})"
            )));
        }

        Ok(Self {
            capacity,
            block_size,
        })
    }
}
