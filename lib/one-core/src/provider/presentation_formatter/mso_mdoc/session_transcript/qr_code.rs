use serde::{Deserialize, Serialize, Serializer, de};

/// QR-code Handover ISO 18013-5 9.1.5.1
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct QRHandover;

// serialized as null value
impl Serialize for QRHandover {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ciborium::Value::Null.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for QRHandover {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'a>,
    {
        let value: ciborium::Value = ciborium::Value::deserialize(deserializer)?;
        if value != ciborium::Value::Null {
            return Err(de::Error::custom("Invalid QR-code handover"));
        }

        Ok(Self)
    }
}
