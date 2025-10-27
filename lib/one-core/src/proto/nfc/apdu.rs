// Implementation of APDU message encoding/decoding according to ISO 7816-4

use anyhow::bail;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Command {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub payload: Vec<u8>,
    pub le: usize,
}

impl TryFrom<Vec<u8>> for Command {
    type Error = anyhow::Error;

    fn try_from(encoded: Vec<u8>) -> Result<Self, Self::Error> {
        if encoded.len() < 4 {
            bail!("Invalid APDU command");
        }

        let to_u16 = |index: usize| -> anyhow::Result<u16> {
            if encoded.len() < (index + 2) {
                bail!("Invalid APDU command - index out of bounds");
            }

            let encoded: [u8; 2] = encoded[index..(index + 2)].try_into()?;
            Ok(u16::from_be_bytes(encoded))
        };

        let cla = encoded[0];
        let ins = encoded[1];
        let p1 = encoded[2];
        let p2 = encoded[3];
        let mut payload = vec![];
        let mut le = 0;

        if encoded.len() == 5 {
            let enc_le = encoded[4] as usize;
            le = if enc_le == 0 { 0x100 } else { enc_le };
        } else if encoded.len() > 5 {
            let mut lc = encoded[4] as usize;
            let mut lc_ends_at: usize = 5;
            if lc == 0 {
                lc = to_u16(5)? as _;
                lc_ends_at = 7;
            }
            if lc > 0 && lc_ends_at + lc <= encoded.len() {
                payload = encoded[lc_ends_at..(lc_ends_at + lc)].to_vec();
            } else {
                lc = 0;
                lc_ends_at = 4;
            }

            let le_len = encoded.len() - lc_ends_at - lc;
            le = match le_len {
                0 => 0,
                1 => {
                    let enc_le = encoded[encoded.len() - 1] as usize;
                    if enc_le == 0 { 0x100 } else { enc_le }
                }
                2 | 3 => {
                    let enc_le = to_u16(encoded.len() - 2)? as usize;
                    if enc_le == 0 { 0x10000 } else { enc_le }
                }
                length => {
                    bail!("Invalid LE length {length}");
                }
            };
        }

        Ok(Command {
            cla,
            ins,
            p1,
            p2,
            payload,
            le,
        })
    }
}

impl TryFrom<Command> for Vec<u8> {
    type Error = anyhow::Error;

    fn try_from(
        Command {
            cla,
            ins,
            p1,
            p2,
            le,
            payload,
        }: Command,
    ) -> Result<Self, Self::Error> {
        let mut result = vec![cla, ins, p1, p2];
        let extended_length = payload.len() > 0xFF || le > 0x100;
        let has_payload = !payload.is_empty();

        if has_payload {
            let lc: u16 = payload.len().try_into()?;
            if extended_length {
                result.push(0x00);
                result.push((lc >> 8) as u8);
                result.push(lc as u8);
            } else {
                result.push(lc as u8);
            }
            result.extend(payload);
        }

        if le > 0 {
            if le > 0x10000 {
                bail!("Too large expected length: {le}");
            }

            if extended_length {
                if !has_payload {
                    result.push(0x00);
                }
                result.push((le >> 8) as u8);
                result.push(le as u8);
            } else {
                result.push(le as u8);
            }
        }

        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Response {
    pub payload: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl Response {
    pub(crate) fn is_success(&self) -> bool {
        matches!((self.sw1, self.sw2), (0x90, 0x00) | (0x61, _))
    }
}

impl From<Response> for Vec<u8> {
    fn from(value: Response) -> Self {
        let mut data = value.payload;
        data.extend([value.sw1, value.sw2]);
        data
    }
}

impl TryFrom<Vec<u8>> for Response {
    type Error = anyhow::Error;

    fn try_from(mut encoded: Vec<u8>) -> Result<Self, Self::Error> {
        let length = encoded.len();
        if length < 2 {
            bail!("Invalid response: {encoded:?}");
        }
        let tail = encoded.split_off(length - 2);
        Ok(Self {
            payload: encoded,
            sw1: tail[0],
            sw2: tail[1],
        })
    }
}

impl From<[u8; 2]> for Response {
    fn from([sw1, sw2]: [u8; 2]) -> Self {
        Self {
            payload: Default::default(),
            sw1,
            sw2,
        }
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_parse_apdu_command() {
        let res: Command = vec![0x01, 0x02, 0x03, 0x04, 0x03, 0x05, 0x06, 0x07, 0x08]
            .try_into()
            .unwrap();
        assert_eq!(res.cla, 0x01);
        assert_eq!(res.ins, 0x02);
        assert_eq!(res.p1, 0x03);
        assert_eq!(res.p2, 0x04);
        assert_eq!(res.payload, &[0x05, 0x06, 0x07]);
        assert_eq!(res.le, 0x08);
    }

    #[test]
    fn test_write_apdu_command() {
        let encoded: Vec<u8> = Command {
            cla: 0x01,
            ins: 0x02,
            p1: 0x03,
            p2: 0x04,
            payload: vec![0x05, 0x06, 0x07],
            le: 0x08,
        }
        .try_into()
        .unwrap();
        assert_eq!(
            encoded,
            &[0x01, 0x02, 0x03, 0x04, 0x03, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn test_write_response() {
        let encoded: Vec<u8> = Response {
            payload: vec![0x03, 0x04, 0x05],
            sw1: 0x01,
            sw2: 0x02,
        }
        .into();
        assert_eq!(encoded, &[0x03, 0x04, 0x05, 0x01, 0x02]);

        let encoded: Vec<u8> = Response {
            payload: vec![],
            sw1: 0x01,
            sw2: 0x02,
        }
        .into();
        assert_eq!(encoded, &[0x01, 0x02]);
    }

    #[test]
    fn test_parse_response() {
        let parsed: Response = vec![0x03, 0x04, 0x05, 0x01, 0x02].try_into().unwrap();
        assert_eq!(parsed.payload, &[0x03, 0x04, 0x05]);
        assert_eq!(parsed.sw1, 0x01);
        assert_eq!(parsed.sw2, 0x02);

        let parsed: Response = vec![0x01, 0x02].try_into().unwrap();
        assert!(parsed.payload.is_empty());
        assert_eq!(parsed.sw1, 0x01);
        assert_eq!(parsed.sw2, 0x02);
    }

    #[test]
    fn test_response_is_success() {
        let parsed: Response = vec![0x03, 0x04, 0x05, 0x90, 0x00].try_into().unwrap();
        assert!(parsed.is_success());

        let parsed: Response = [0x6a, 0x82].into();
        assert!(!parsed.is_success());
    }
}
