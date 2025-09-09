use ciborium::cbor;
use serde::{Deserialize, Serialize, Serializer, de, ser};

use crate::util::mdoc::Bstr;

/// NFCHandover ISO 18013-5 9.1.5.1
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NFCHandover {
    pub select_message: Bstr,
    pub request_message: Option<Bstr>,
}

impl Serialize for NFCHandover {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!([self.select_message, self.request_message])
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for NFCHandover {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'a>,
    {
        let (select_message, request_message): (Bstr, Option<Bstr>) =
            ciborium::Value::deserialize(deserializer)?
                .deserialized()
                .map_err(de::Error::custom)?;

        Ok(Self {
            select_message,
            request_message,
        })
    }
}
