// Encoding/decoding of selected commands according to ISO 7816-4

use anyhow::bail;

use super::apdu::Command;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum KnownCommand {
    SelectApplication { application_id: Vec<u8> },
    SelectFile { file_id: [u8; 2] },
    ReadBinary { offset: u16, length: usize },
    Other(Command),
}

const CLA_DEFAULT: u8 = 0x00;
const INS_SELECT: u8 = 0xa4;
const INS_READ_BINARY: u8 = 0xb0;

const PARAMS_SELECT_APPLICATION: [u8; 2] = [0x04, 0x00];
const PARAMS_SELECT_FILE: [u8; 2] = [0x00, 0x0c];

impl TryFrom<KnownCommand> for Command {
    type Error = anyhow::Error;
    fn try_from(value: KnownCommand) -> Result<Self, Self::Error> {
        Ok(match value {
            KnownCommand::SelectApplication { application_id } => Self {
                cla: CLA_DEFAULT,
                ins: INS_SELECT,
                p1: PARAMS_SELECT_APPLICATION[0],
                p2: PARAMS_SELECT_APPLICATION[1],
                payload: application_id,
                le: 0,
            },
            KnownCommand::SelectFile { file_id } => Self {
                cla: CLA_DEFAULT,
                ins: INS_SELECT,
                p1: PARAMS_SELECT_FILE[0],
                p2: PARAMS_SELECT_FILE[1],
                payload: file_id.to_vec(),
                le: 0,
            },
            KnownCommand::ReadBinary { offset, length } => {
                if offset > 0x7FFF {
                    bail!("Offset out of bounds: {offset}");
                }
                let [p1, p2] = offset.to_be_bytes();
                Self {
                    cla: CLA_DEFAULT,
                    ins: INS_READ_BINARY,
                    p1,
                    p2,
                    payload: Default::default(),
                    le: length,
                }
            }
            KnownCommand::Other(other_command) => other_command,
        })
    }
}

impl TryFrom<Command> for KnownCommand {
    type Error = anyhow::Error;

    fn try_from(command: Command) -> Result<Self, Self::Error> {
        Ok(match (command.cla, command.ins, [command.p1, command.p2]) {
            (CLA_DEFAULT, INS_SELECT, PARAMS_SELECT_APPLICATION) => {
                if command.payload.is_empty() {
                    bail!("Missing application ID");
                }
                Self::SelectApplication {
                    application_id: command.payload,
                }
            }
            (CLA_DEFAULT, INS_SELECT, PARAMS_SELECT_FILE) => Self::SelectFile {
                file_id: command.payload.as_slice().try_into()?,
            },
            (CLA_DEFAULT, INS_READ_BINARY, params) => {
                let offset = u16::from_be_bytes(params);
                if offset > 0x7FFF {
                    bail!("Unsupported EF identifier: {}", params[0]);
                }
                if command.le == 0 {
                    bail!("Missing length");
                }
                Self::ReadBinary {
                    offset,
                    length: command.le,
                }
            }
            _ => Self::Other(command),
        })
    }
}

impl TryFrom<KnownCommand> for Vec<u8> {
    type Error = anyhow::Error;

    fn try_from(value: KnownCommand) -> Result<Self, Self::Error> {
        let command: Command = value.try_into()?;
        command.try_into()
    }
}

impl TryFrom<Vec<u8>> for KnownCommand {
    type Error = anyhow::Error;

    fn try_from(encoded: Vec<u8>) -> Result<Self, Self::Error> {
        let command: Command = encoded.try_into()?;
        command.try_into()
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_construct_and_parse_success() {
        fn check(command: KnownCommand, expected_encoded: Vec<u8>) {
            let encoded: Vec<u8> = command.to_owned().try_into().unwrap();
            assert_eq!(encoded, expected_encoded);

            let parsed = KnownCommand::try_from(encoded).unwrap();
            assert_eq!(parsed, command);
        }

        // SelectApplication
        check(
            KnownCommand::SelectApplication {
                application_id: vec![0xaa, 0xbb, 0xcc],
            },
            vec![0x00, 0xa4, 0x04, 0x00, 0x03, 0xaa, 0xbb, 0xcc],
        );

        // SelectFile
        check(
            KnownCommand::SelectFile {
                file_id: [0xaa, 0xbb],
            },
            vec![0x00, 0xa4, 0x00, 0x0c, 0x02, 0xaa, 0xbb],
        );

        // ReadBinary
        check(
            KnownCommand::ReadBinary {
                offset: 2,
                length: 200,
            },
            vec![0x00, 0xb0, 0x00, 0x02, 0xc8],
        );
        check(
            KnownCommand::ReadBinary {
                offset: 500,
                length: 600,
            },
            vec![0x00, 0xb0, 0x01, 0xf4, 0x00, 0x02, 0x58],
        );
        check(
            KnownCommand::ReadBinary {
                offset: 0x7fff,
                length: 0x10000,
            },
            vec![0x00, 0xb0, 0x7f, 0xff, 0x00, 0x00, 0x00],
        );
    }
}
