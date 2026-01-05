use anyhow::Context;

pub(crate) type MessageSize = u16;

#[derive(Debug)]
pub(crate) struct Chunk {
    pub index: MessageSize,
    pub payload: Vec<u8>,
    pub checksum: u16,
}

impl Chunk {
    pub fn new(index: MessageSize, payload: Vec<u8>) -> Self {
        let idx_bytes = index.to_be_bytes();

        let crc = crc::Crc::<u16>::new(&crc::CRC_16_IBM_3740);

        let checksum = crc.checksum(
            [idx_bytes.as_slice(), payload.as_slice()]
                .concat()
                .as_slice(),
        );
        Self {
            index,
            payload,
            checksum,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [
            self.index.to_be_bytes().as_slice(),
            &self.payload,
            self.checksum.to_be_bytes().as_slice(),
        ]
        .concat()
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let (index, rest) = bytes.split_at(2);
        let (payload, checksum) = rest.split_at(rest.len() - 2);

        let chunk_index = index.try_into().context("Failed to read chunk index")?;
        let received_checksum =
            u16::from_be_bytes(checksum.try_into().context("Failed to read checksum")?);

        let crc = crc::Crc::<u16>::new(&crc::CRC_16_IBM_3740);

        let calculated_checksum = crc.checksum([index, payload].concat().as_slice());

        if received_checksum != calculated_checksum {
            return Err(anyhow::anyhow!(
                "Invalid checksum. Computed: {calculated_checksum}, received: {:?}",
                received_checksum
            ));
        }

        Ok(Self {
            index: MessageSize::from_be_bytes(chunk_index),
            payload: payload.to_owned(),
            checksum: received_checksum,
        })
    }
}

pub(crate) type Chunks = Vec<Chunk>;

pub(crate) trait ChunkExt {
    fn from_bytes(bytes: &[u8], chunk_size: MessageSize) -> Chunks;
}

impl ChunkExt for Chunks {
    fn from_bytes(bytes: &[u8], chunk_size: MessageSize) -> Self {
        bytes
            .chunks((chunk_size - 4) as usize)
            .enumerate()
            .map(|(index, chunk)| Chunk::new((index + 1) as MessageSize, chunk.to_vec()))
            .collect()
    }
}

// https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#section-5.3
#[derive(Clone, Debug)]
pub(super) struct IdentityRequest {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    pub version: ProtocolVersion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProtocolVersion {
    /// legacy version using Presentation Exchange and Draft20 structures
    V1,
    /// using final-1 structures and DCQL query
    V2,
}

pub(super) trait WithProtocolVersion {
    fn protocol_version(&self) -> ProtocolVersion;
}

impl From<ProtocolVersion> for u8 {
    fn from(value: ProtocolVersion) -> Self {
        match value {
            ProtocolVersion::V1 => 1,
            ProtocolVersion::V2 => 2,
        }
    }
}

impl IdentityRequest {
    pub(super) fn encode(self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(&self.key);
        result.extend(&self.nonce);
        if self.version != ProtocolVersion::V1 {
            result.push(self.version.into());
        }
        result
    }

    pub(crate) fn parse(data: Vec<u8>) -> anyhow::Result<Self> {
        let version = match data.len() {
            44 => ProtocolVersion::V1,
            45 => ProtocolVersion::V2,
            len => return Err(anyhow::anyhow!("Invalid identity request size: {len}")),
        };

        let arr = data
            .get(..44)
            .ok_or(anyhow::anyhow!("Invalid identity request data"))?;
        let (key, nonce) = arr.split_at(32);

        Ok(Self {
            key: key
                .try_into()
                .context("Failed to parse key from identity request")?,
            nonce: nonce
                .try_into()
                .context("Failed to parse nonce from identity request")?,
            version,
        })
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_identity_request_v1_parsing() {
        let original = IdentityRequest {
            key: [1; 32],
            nonce: [2; 12],
            version: ProtocolVersion::V1,
        };

        let serialized = original.to_owned().encode();
        assert_eq!(serialized.len(), 44);

        let decoded = IdentityRequest::parse(serialized).unwrap();
        assert_eq!(decoded.key, original.key);
        assert_eq!(decoded.nonce, original.nonce);
        assert_eq!(decoded.version, ProtocolVersion::V1);
    }

    #[test]
    fn test_identity_request_v2_parsing() {
        let original = IdentityRequest {
            key: [1; 32],
            nonce: [2; 12],
            version: ProtocolVersion::V2,
        };

        let serialized = original.to_owned().encode();
        assert_eq!(serialized.len(), 45);

        let decoded = IdentityRequest::parse(serialized).unwrap();
        assert_eq!(decoded.key, original.key);
        assert_eq!(decoded.nonce, original.nonce);
        assert_eq!(decoded.version, ProtocolVersion::V2);
    }
}
