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
