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
}
