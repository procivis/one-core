use serde::Deserialize;

use crate::service::error::ValidationError;

#[derive(Clone, Copy, Debug)]
pub struct TransactionCodeLength(u32);

impl TransactionCodeLength {
    const MIN: u32 = 4;
    const MAX: u32 = 10;
}

impl From<TransactionCodeLength> for u32 {
    fn from(value: TransactionCodeLength) -> Self {
        value.0
    }
}

impl TryFrom<u32> for TransactionCodeLength {
    type Error = ValidationError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if !(Self::MIN..=Self::MAX).contains(&value) {
            return Err(ValidationError::InvalidTransactionCodeLength);
        }

        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for TransactionCodeLength {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let size = u32::deserialize(deserializer)?;

        if size < Self::MIN {
            return Err(serde::de::Error::custom(format!(
                "expected minimum of {}, got {size}",
                Self::MIN
            )));
        }

        if size > Self::MAX {
            return Err(serde::de::Error::custom(format!(
                "expected maximum of {}, got {size}",
                Self::MAX
            )));
        }

        Ok(Self(size))
    }
}
