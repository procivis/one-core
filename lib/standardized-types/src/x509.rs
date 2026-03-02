use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use serde::{Deserialize, Serialize, de, ser};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertificateSerial(Vec<u8>);

impl TryFrom<Vec<u8>> for CertificateSerial {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > 20 {
            return Err(anyhow::anyhow!("Certificate serial too long"));
        }
        Ok(Self(value))
    }
}

impl From<CertificateSerial> for Vec<u8> {
    fn from(value: CertificateSerial) -> Self {
        value.0
    }
}

impl CertificateSerial {
    /// Generate a random serial
    pub fn new_random() -> Self {
        let mut random_bytes = Uuid::new_v4().as_bytes().to_vec();
        random_bytes.insert(0, 0x01); // to make sure it is a positive value
        Self(random_bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AuthorityKeyIdentifier(Vec<u8>);

impl From<Vec<u8>> for AuthorityKeyIdentifier {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl AuthorityKeyIdentifier {
    pub fn from_base64url(value: &str) -> Result<Self, ct_codecs::Error> {
        Ok(Self(Base64UrlSafeNoPadding::decode_to_vec(value, None)?))
    }
}

// serialization from/into base64url string
impl Serialize for AuthorityKeyIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Base64UrlSafeNoPadding::encode_to_string(&self.0)
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AuthorityKeyIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_base64url(&value).map_err(de::Error::custom)
    }
}
