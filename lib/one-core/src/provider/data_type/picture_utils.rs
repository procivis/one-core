use hex_literal::hex;

pub(crate) const JPEG_HEADER: [u8; 2] = hex!("FF D8");
pub(crate) const PNG_HEADER: [u8; 8] = hex!("89 50 4E 47 0D 0A 1A 0A");
pub(crate) const JPEG_SUFFIX: [u8; 2] = hex!("FF D9");
pub(crate) const JPEG2000_HEADER: [u8; 12] = hex!("00 00 00 0C 6A 50 20 20 0D 0A 87 0A");
